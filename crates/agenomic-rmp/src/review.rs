//! The Review engine: evaluate an agent before release, after changes, or
//! after incidents.
//!
//! Deterministic and offline: replay is delegated to
//! [`agenomic_replay_local`], contract checks to [`agenomic_contract`],
//! policy checks to [`agenomic_policy`], and regression detection compares
//! against the recorded [`EvaluationHistoryEntry`] series. No LLM is called.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::{CliResult, Severity};
use agenomic_replay_local::{run_local_replay, ReplayOptions, ReplayReport};

use crate::cards::{AgentIdCard, UseCaseCard};
use crate::enrich::ScenarioEnrichmentProposal;
use crate::risk::{AgentTypeAssessment, RiskMatrix};
use crate::scenario::{validate_scenario, TestScenario};
use crate::types::{
    EvaluationHistoryEntry, EvaluationResult, Finding, FindingKind, ReviewSession,
    RmpSessionStatus, RMP_SPEC_VERSION,
};

/// Tuning knobs for a review pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewConfig {
    /// Findings at or above this severity fail the review.
    pub fail_on: Severity,
    /// Score drop (0.0 ..= 1.0) vs. the best recent history entry that
    /// counts as a regression.
    pub regression_threshold: f64,
    /// Release-risk score above which human review is recommended.
    pub human_review_threshold: f64,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            fail_on: Severity::Critical,
            regression_threshold: 0.1,
            human_review_threshold: 0.6,
        }
    }
}

/// Everything a review pass can consume. All inputs are optional except the
/// bundle path and agent id — Review degrades gracefully and reports what
/// it could not evaluate instead of failing.
#[derive(Debug, Clone, Default)]
pub struct ReviewInputs {
    /// Bundle directory holding `genome.yaml`, contract, policies, traces.
    pub bundle: Option<PathBuf>,
    pub agent_id: String,
    pub genome_hash: Option<String>,
    pub release_id: Option<String>,
    pub id_card: Option<AgentIdCard>,
    pub use_case: Option<UseCaseCard>,
    pub risk_matrix: Option<RiskMatrix>,
    pub scenarios: Vec<TestScenario>,
    pub evaluation_history: Vec<EvaluationHistoryEntry>,
    /// Trace fixtures for replay (JSONL path, data-engine output or
    /// recorded production traces).
    pub traces: Option<PathBuf>,
    /// Findings carried over from Monitor/Protect (previous loop turns).
    pub carried_findings: Vec<Finding>,
    /// Previously approved enrichment proposals to fold into the corpus.
    pub approved_proposals: Vec<ScenarioEnrichmentProposal>,
}

/// The release recommendation Review lands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseRecommendation {
    Approve,
    ApproveWithConditions,
    HumanReviewRequired,
    Block,
}

impl ReleaseRecommendation {
    /// Stable snake_case label (matches the serde encoding).
    pub fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithConditions => "approve_with_conditions",
            Self::HumanReviewRequired => "human_review_required",
            Self::Block => "block",
        }
    }
}

/// Scenario coverage summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageReport {
    pub total_scenarios: usize,
    pub scenarios_by_source: BTreeMap<String, usize>,
    pub open_risks: usize,
    pub covered_risks: usize,
    /// 0.0 ..= 1.0.
    pub coverage_ratio: f64,
    pub uncovered_risk_ids: Vec<String>,
}

/// The outcome of one review pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewOutcome {
    pub spec_version: String,
    pub session: ReviewSession,
    pub result: EvaluationResult,
    /// 0.0 (worst) ..= 1.0 (best) overall review score.
    pub score: f64,
    /// 0.0 ..= 1.0 aggregate release risk from the risk matrix.
    pub release_risk_score: f64,
    pub recommendation: ReleaseRecommendation,
    pub findings: Vec<Finding>,
    pub coverage: CoverageReport,
    /// Updated risk matrix (coverage marks + assessment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_matrix: Option<RiskMatrix>,
    /// Replay report when a replay ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_report: Option<ReplayReport>,
    pub metrics: BTreeMap<String, f64>,
    /// Changes required before release (derived from blocking findings).
    pub required_changes: Vec<String>,
    /// The history entry recorded for this pass.
    pub history_entry: EvaluationHistoryEntry,
    pub generated_at: DateTime<Utc>,
}

/// The Review engine. Stateless: all state flows through
/// [`ReviewInputs`] / [`ReviewOutcome`].
#[derive(Debug, Clone, Default)]
pub struct ReviewEngine {
    pub config: ReviewConfig,
}

impl ReviewEngine {
    /// Create an engine with the given config.
    pub fn new(config: ReviewConfig) -> Self {
        Self { config }
    }

    /// Run a full review pass.
    ///
    /// Steps: agent-type classification → risk identification → scenario
    /// selection/validation → replay (when a bundle + traces exist) →
    /// contract/policy validation (inside replay) → metric computation →
    /// regression detection → risk-matrix update → release recommendation.
    pub fn run(&self, mut inputs: ReviewInputs) -> CliResult<ReviewOutcome> {
        let mut session = ReviewSession::new(inputs.agent_id.clone());
        session.genome_hash = inputs.genome_hash.clone();
        session.release_id = inputs.release_id.clone();
        let mut findings: Vec<Finding> = Vec::new();
        let mut metrics: BTreeMap<String, f64> = BTreeMap::new();

        // 1. Fold approved enrichment proposals into the scenario corpus.
        for proposal in &inputs.approved_proposals {
            if proposal.status == crate::enrich::EnrichmentStatus::Approved
                || proposal.status == crate::enrich::EnrichmentStatus::Applied
            {
                inputs.scenarios.push(proposal.proposed_scenario.clone());
            }
        }

        // 2. Agent-type classification + risk matrix assessment.
        let mut matrix = inputs
            .risk_matrix
            .clone()
            .unwrap_or_else(|| RiskMatrix::new(inputs.agent_id.clone()));
        if matrix.assessment.is_none() {
            if let Some(card) = &inputs.id_card {
                matrix.assessment = Some(AgentTypeAssessment::from_id_card(card));
            }
        }
        matrix.genome_hash = matrix.genome_hash.or_else(|| inputs.genome_hash.clone());

        // 3. Scenario validation + selection; mark coverage on the matrix.
        let mut valid_scenarios: Vec<&TestScenario> = Vec::new();
        for scenario in &inputs.scenarios {
            match validate_scenario(scenario) {
                Ok(()) => valid_scenarios.push(scenario),
                Err(e) => {
                    findings.push(
                        Finding::new(
                            "review",
                            &session.session_id,
                            &inputs.agent_id,
                            FindingKind::ScenarioFailure,
                            Severity::Medium,
                            format!("Invalid scenario {}", scenario.scenario_id),
                            e.to_string(),
                        )
                        .with_evidence([scenario.scenario_id.clone()]),
                    );
                }
            }
        }
        session.scenario_ids = valid_scenarios
            .iter()
            .map(|s| s.scenario_id.clone())
            .collect();
        {
            let coverage_pairs: Vec<(String, String)> = valid_scenarios
                .iter()
                .flat_map(|s| {
                    s.risk_ids
                        .iter()
                        .map(|r| (r.clone(), s.scenario_id.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            for (risk_id, scenario_id) in coverage_pairs {
                matrix.mark_covered(&risk_id, &scenario_id);
            }
        }

        // 4. Use-case-driven risk identification: uncovered failure modes
        //    become risk-gap findings.
        if let Some(use_case) = &inputs.use_case {
            for mode in &use_case.failure_modes {
                let already = matrix
                    .items
                    .iter()
                    .any(|i| i.title.eq_ignore_ascii_case(mode));
                if !already {
                    findings.push(Finding::new(
                        "review",
                        &session.session_id,
                        &inputs.agent_id,
                        FindingKind::RiskGap,
                        Severity::Medium,
                        format!("Failure mode not in risk matrix: {mode}"),
                        "declared in the use case card but absent from the risk matrix"
                            .to_string(),
                    ));
                }
            }
        }

        // 5. Coverage report + coverage-gap findings.
        let coverage = self.coverage(&matrix, &valid_scenarios);
        if coverage.coverage_ratio < 1.0 && !coverage.uncovered_risk_ids.is_empty() {
            findings.push(
                Finding::new(
                    "review",
                    &session.session_id,
                    &inputs.agent_id,
                    FindingKind::CoverageGap,
                    Severity::Medium,
                    format!(
                        "{} open risk(s) have no covering scenario",
                        coverage.uncovered_risk_ids.len()
                    ),
                    "add scenarios (or approve enrichment proposals) covering these risks"
                        .to_string(),
                )
                .with_risks(coverage.uncovered_risk_ids.clone()),
            );
        }

        // 6. Replay + behavior-contract + policy validation.
        let replay_report = self.run_replay(&inputs, &session, &mut findings)?;

        // 7. Carried Monitor/Protect findings feed risk observations.
        for carried in &inputs.carried_findings {
            for risk_id in &carried.risk_ids {
                matrix.record_observation(risk_id, &carried.finding_id);
            }
        }

        // 8. Metrics.
        let release_risk_score = matrix.release_risk_score();
        metrics.insert("release_risk_score".into(), release_risk_score);
        metrics.insert("scenario_count".into(), valid_scenarios.len() as f64);
        metrics.insert("risk_coverage_ratio".into(), coverage.coverage_ratio);
        if let Some(replay) = &replay_report {
            metrics.insert("replay_total_traces".into(), replay.total_traces as f64);
            metrics.insert(
                "replay_violations".into(),
                replay.violations.len() as f64,
            );
            metrics.insert(
                "replay_contract_passed".into(),
                if replay.contract_passed { 1.0 } else { 0.0 },
            );
        }
        let blocking = findings
            .iter()
            .filter(|f| f.severity >= self.config.fail_on)
            .count();
        metrics.insert("blocking_findings".into(), blocking as f64);

        // 9. Score: start from 1.0, subtract weighted findings and risk.
        let score = self.score(&findings, release_risk_score, replay_report.as_ref());
        metrics.insert("review_score".into(), score);

        // 10. Regression detection against evaluation history.
        if let Some(best_recent) = inputs
            .evaluation_history
            .iter()
            .filter(|h| h.source == "review")
            .map(|h| h.score)
            .fold(None::<f64>, |acc, s| Some(acc.map_or(s, |a| a.max(s))))
        {
            if best_recent - score > self.config.regression_threshold {
                findings.push(Finding::new(
                    "review",
                    &session.session_id,
                    &inputs.agent_id,
                    FindingKind::Regression,
                    Severity::High,
                    format!(
                        "Review score regressed: {score:.2} vs best recent {best_recent:.2}"
                    ),
                    "investigate the diff between this candidate and the last approved release"
                        .to_string(),
                ));
            }
        }

        // 11. Result + recommendation.
        let result = if findings
            .iter()
            .any(|f| f.severity >= self.config.fail_on)
        {
            EvaluationResult::Fail
        } else if findings.is_empty() {
            EvaluationResult::Pass
        } else {
            EvaluationResult::Warn
        };
        let recommendation = self.recommend(result, release_risk_score, &findings);

        let required_changes: Vec<String> = findings
            .iter()
            .filter(|f| f.blocks_release)
            .map(|f| format!("[{}] {}", f.kind.label(), f.title))
            .collect();

        let mut history_entry = EvaluationHistoryEntry::new(
            &inputs.agent_id,
            "review",
            &session.session_id,
            result,
            score,
        );
        history_entry.genome_hash = inputs.genome_hash.clone();
        history_entry.release_id = inputs.release_id.clone();
        history_entry.metrics = serde_json::to_value(&metrics).unwrap_or(serde_json::Value::Null);
        if let Some(replay) = &replay_report {
            history_entry
                .evidence_refs
                .push(format!("replay:{}", replay.bundle_hash));
        }

        session.status = RmpSessionStatus::Completed;
        session.ended_at = Some(Utc::now());

        Ok(ReviewOutcome {
            spec_version: RMP_SPEC_VERSION.into(),
            session,
            result,
            score,
            release_risk_score,
            recommendation,
            findings,
            coverage,
            risk_matrix: Some(matrix),
            replay_report,
            metrics,
            required_changes,
            history_entry,
            generated_at: Utc::now(),
        })
    }

    fn coverage(&self, matrix: &RiskMatrix, scenarios: &[&TestScenario]) -> CoverageReport {
        let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
        for s in scenarios {
            *by_source.entry(s.source.label().to_string()).or_default() += 1;
        }
        let open: Vec<_> = matrix.items.iter().filter(|i| i.status == "open").collect();
        let covered = open.iter().filter(|i| i.is_covered()).count();
        CoverageReport {
            total_scenarios: scenarios.len(),
            scenarios_by_source: by_source,
            open_risks: open.len(),
            covered_risks: covered,
            coverage_ratio: matrix.coverage_ratio(),
            uncovered_risk_ids: open
                .iter()
                .filter(|i| !i.is_covered())
                .map(|i| i.risk_id.clone())
                .collect(),
        }
    }

    fn run_replay(
        &self,
        inputs: &ReviewInputs,
        session: &ReviewSession,
        findings: &mut Vec<Finding>,
    ) -> CliResult<Option<ReplayReport>> {
        let Some(bundle) = &inputs.bundle else {
            return Ok(None);
        };
        if inputs.traces.is_none() {
            return Ok(None);
        }
        let report = run_local_replay(ReplayOptions {
            bundle: bundle.clone(),
            traces: inputs.traces.clone(),
            atep_store: None,
            contract: None,
            runs_per_trace: 1,
            fail_on: self.config.fail_on,
        })?;
        for violation in &report.violations {
            findings.push(
                Finding::new(
                    "review",
                    &session.session_id,
                    &inputs.agent_id,
                    FindingKind::ContractViolation,
                    violation.severity,
                    format!("Contract check failed: {}", violation.check_id),
                    violation.message.clone(),
                )
                .with_evidence([format!("trace:{}", violation.trace_id)]),
            );
        }
        if !report.contract_passed {
            findings.push(Finding::new(
                "review",
                &session.session_id,
                &inputs.agent_id,
                FindingKind::ReplayDivergence,
                Severity::High,
                "Replay contract evaluation failed",
                format!(
                    "{} violation(s) across {} trace(s)",
                    report.violations.len(),
                    report.total_traces
                ),
            ));
        }
        Ok(Some(report))
    }

    fn score(
        &self,
        findings: &[Finding],
        release_risk_score: f64,
        replay: Option<&ReplayReport>,
    ) -> f64 {
        let mut score: f64 = 1.0;
        for f in findings {
            score -= match f.severity {
                Severity::Critical => 0.3,
                Severity::High => 0.15,
                Severity::Medium => 0.05,
                Severity::Low => 0.02,
                Severity::Info => 0.0,
            };
        }
        score -= release_risk_score * 0.2;
        if let Some(r) = replay {
            if !r.contract_passed {
                score -= 0.2;
            }
        }
        score.clamp(0.0, 1.0)
    }

    fn recommend(
        &self,
        result: EvaluationResult,
        release_risk_score: f64,
        findings: &[Finding],
    ) -> ReleaseRecommendation {
        if matches!(result, EvaluationResult::Fail)
            || findings.iter().any(|f| f.blocks_release)
        {
            return ReleaseRecommendation::Block;
        }
        if release_risk_score >= self.config.human_review_threshold
            || findings.iter().any(|f| f.requires_human_review)
        {
            return ReleaseRecommendation::HumanReviewRequired;
        }
        if matches!(result, EvaluationResult::Warn) {
            return ReleaseRecommendation::ApproveWithConditions;
        }
        ReleaseRecommendation::Approve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskItem;
    use crate::scenario::ScenarioSource;

    fn base_inputs() -> ReviewInputs {
        ReviewInputs {
            agent_id: "agent://acme/claims".into(),
            ..ReviewInputs::default()
        }
    }

    #[test]
    fn empty_review_passes() {
        let outcome = ReviewEngine::default().run(base_inputs()).unwrap();
        assert_eq!(outcome.result, EvaluationResult::Pass);
        assert_eq!(outcome.recommendation, ReleaseRecommendation::Approve);
        assert!(outcome.score > 0.9);
    }

    #[test]
    fn uncovered_risk_produces_coverage_gap() {
        let mut inputs = base_inputs();
        let mut matrix = RiskMatrix::new("agent://acme/claims");
        matrix.items.push(RiskItem::new("wrong payout", 0.4, 0.5));
        inputs.risk_matrix = Some(matrix);
        let outcome = ReviewEngine::default().run(inputs).unwrap();
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::CoverageGap));
        assert_eq!(outcome.result, EvaluationResult::Warn);
        assert_eq!(
            outcome.recommendation,
            ReleaseRecommendation::ApproveWithConditions
        );
    }

    #[test]
    fn scenario_covers_risk() {
        let mut inputs = base_inputs();
        let mut matrix = RiskMatrix::new("agent://acme/claims");
        let risk = RiskItem::new("wrong payout", 0.4, 0.5);
        let risk_id = risk.risk_id.clone();
        matrix.items.push(risk);
        inputs.risk_matrix = Some(matrix);
        let mut scenario = TestScenario::new(
            "agent://acme/claims",
            "payout bounds",
            ScenarioSource::Manual,
            Severity::High,
        );
        scenario.risk_ids.push(risk_id);
        inputs.scenarios.push(scenario);
        let outcome = ReviewEngine::default().run(inputs).unwrap();
        assert!((outcome.coverage.coverage_ratio - 1.0).abs() < 1e-9);
        assert!(!outcome
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::CoverageGap));
    }

    #[test]
    fn regression_detected_against_history() {
        let mut inputs = base_inputs();
        // A prior perfect review...
        let prior = EvaluationHistoryEntry::new(
            "agent://acme/claims",
            "review",
            "rev_prior",
            EvaluationResult::Pass,
            1.0,
        );
        inputs.evaluation_history.push(prior);
        // ...and a current pass dragged down by a high-risk matrix.
        let mut matrix = RiskMatrix::new("agent://acme/claims");
        for i in 0..4 {
            matrix.items.push(RiskItem::new(format!("r{i}"), 0.9, 0.9));
        }
        inputs.risk_matrix = Some(matrix);
        let outcome = ReviewEngine::default().run(inputs).unwrap();
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::Regression));
    }

    #[test]
    fn approved_proposals_join_corpus() {
        let mut inputs = base_inputs();
        let finding = Finding::new(
            "monitor",
            "m1",
            "agent://acme/claims",
            FindingKind::Loop,
            Severity::Low,
            "loop",
            "msg",
        );
        let mut proposal = crate::enrich::proposals_from_findings(&[finding]).remove(0);
        proposal.submit().unwrap();
        proposal.approve("reviewer").unwrap();
        inputs.approved_proposals.push(proposal);
        let outcome = ReviewEngine::default().run(inputs).unwrap();
        assert_eq!(outcome.coverage.total_scenarios, 1);
        assert_eq!(
            outcome.coverage.scenarios_by_source.get("monitor_derived"),
            Some(&1)
        );
    }
}
