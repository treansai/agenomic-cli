//! The continuous feedback loop: Monitor/Protect findings become Review
//! artifacts through [`ScenarioEnrichmentProposal`]s.
//!
//! A proposal is never applied automatically. It moves through an explicit
//! approval workflow (`draft → pending_review → approved → applied`, or
//! `rejected`), and high-severity proposals always require human approval.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::{CliError, CliResult, Severity};

use crate::scenario::{ScenarioSource, TestScenario, TestScenarioInput};
use crate::types::{Finding, FindingKind};

/// Version stamped on enrichment proposals.
pub const ENRICHMENT_VERSION: &str = "agenomic.rmp.enrichment/v0.1";

/// Approval workflow state of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentStatus {
    Draft,
    PendingReview,
    Approved,
    Rejected,
    Applied,
}

impl EnrichmentStatus {
    /// Stable snake_case label (matches the serde encoding).
    pub fn label(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingReview => "pending_review",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Applied => "applied",
        }
    }
}

/// A proposed Review enrichment derived from a production finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEnrichmentProposal {
    pub spec_version: String,
    pub proposal_id: String,
    pub source_finding_id: String,
    /// Producer event ids / ledger entry ids backing the source finding.
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    pub proposed_scenario: TestScenario,
    #[serde(default)]
    pub risk_ids: Vec<String>,
    pub reason: String,
    /// Expected coverage improvement in 0.0 ..= 1.0 (fraction of currently
    /// uncovered risk this scenario would cover).
    pub expected_coverage_improvement: f64,
    pub severity: Severity,
    pub human_approval_required: bool,
    pub status: EnrichmentStatus,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,
}

impl ScenarioEnrichmentProposal {
    /// Create a proposal for a scenario derived from a finding.
    pub fn new(finding: &Finding, proposed_scenario: TestScenario, reason: impl Into<String>) -> Self {
        Self {
            spec_version: ENRICHMENT_VERSION.into(),
            proposal_id: format!("sep_{}", ulid::Ulid::new()),
            source_finding_id: finding.finding_id.clone(),
            source_event_ids: finding.evidence_refs.clone(),
            risk_ids: proposed_scenario.risk_ids.clone(),
            proposed_scenario,
            reason: reason.into(),
            expected_coverage_improvement: 0.0,
            severity: finding.severity,
            human_approval_required: matches!(
                finding.severity,
                Severity::High | Severity::Critical
            ),
            status: EnrichmentStatus::Draft,
            created_at: Utc::now(),
            reviewed_by: None,
            reviewed_at: None,
        }
    }

    /// Submit the draft for review.
    pub fn submit(&mut self) -> CliResult<()> {
        self.transition(EnrichmentStatus::Draft, EnrichmentStatus::PendingReview)
    }

    /// Approve the proposal. `reviewer` is recorded for the audit trail and
    /// is mandatory when human approval is required.
    pub fn approve(&mut self, reviewer: &str) -> CliResult<()> {
        if self.human_approval_required && reviewer.trim().is_empty() {
            return Err(CliError::Schema(
                "this proposal requires human approval: a reviewer identity is mandatory".into(),
            ));
        }
        self.transition(EnrichmentStatus::PendingReview, EnrichmentStatus::Approved)?;
        self.reviewed_by = Some(reviewer.to_string());
        self.reviewed_at = Some(Utc::now());
        Ok(())
    }

    /// Reject the proposal.
    pub fn reject(&mut self, reviewer: &str) -> CliResult<()> {
        self.transition(EnrichmentStatus::PendingReview, EnrichmentStatus::Rejected)?;
        self.reviewed_by = Some(reviewer.to_string());
        self.reviewed_at = Some(Utc::now());
        Ok(())
    }

    /// Mark an approved proposal as applied (the scenario was added to the
    /// Review corpus).
    pub fn mark_applied(&mut self) -> CliResult<()> {
        self.transition(EnrichmentStatus::Approved, EnrichmentStatus::Applied)
    }

    fn transition(&mut self, from: EnrichmentStatus, to: EnrichmentStatus) -> CliResult<()> {
        if self.status != from {
            return Err(CliError::Schema(format!(
                "invalid proposal transition: {} -> {} (current status is {})",
                from.label(),
                to.label(),
                self.status.label()
            )));
        }
        self.status = to;
        Ok(())
    }
}

/// Derive scenario enrichment proposals from findings. Deterministic: the
/// mapping from finding kind to scenario template is fixed.
///
/// | Finding | Derived scenario |
/// |---|---|
/// | Loop | loop regression scenario (bounds repeated tool calls) |
/// | Drift | prompt/config regression check |
/// | PolicyViolation / HarnessViolation | policy test |
/// | IntentShift / ForbiddenIntent | intent boundary scenario |
/// | Failure / RepeatedFailure | tool-failure replay fixture |
/// | ReplayDivergence / LowReplayFidelity | release validation gate scenario |
/// | MissingHumanApproval / DangerousAutonomy | human-approval gate scenario |
/// | ToolMisuse / MemoryMisuse / SuspiciousOutput / Anomaly | forbidden-behavior scenario |
pub fn proposals_from_findings(findings: &[Finding]) -> Vec<ScenarioEnrichmentProposal> {
    findings
        .iter()
        .filter_map(proposal_from_finding)
        .collect()
}

fn scenario_source_for(finding: &Finding) -> ScenarioSource {
    match finding.loop_stage.as_str() {
        "protect" => ScenarioSource::ProtectDerived,
        "monitor" => ScenarioSource::MonitorDerived,
        _ => ScenarioSource::IncidentDerived,
    }
}

fn proposal_from_finding(finding: &Finding) -> Option<ScenarioEnrichmentProposal> {
    let (title_prefix, description, forbidden, reason): (&str, String, Vec<String>, String) =
        match finding.kind {
            FindingKind::Loop => (
                "Loop regression",
                format!(
                    "Replay the event sequence that produced the loop and assert the loop \
                     bound is respected. Source: {}",
                    finding.title
                ),
                vec!["unbounded_repeated_tool_calls".into()],
                "a loop detected in production becomes a loop regression scenario".into(),
            ),
            FindingKind::Drift => (
                "Drift regression",
                format!(
                    "Assert the drifted surface (prompt/model/tool/policy) matches the \
                     release baseline. Source: {}",
                    finding.title
                ),
                Vec::new(),
                "a drift finding becomes a baseline regression check".into(),
            ),
            FindingKind::PolicyViolation | FindingKind::HarnessViolation => (
                "Policy test",
                format!(
                    "Re-evaluate the violating input against the policy bundle and assert \
                     the deny holds. Source: {}",
                    finding.title
                ),
                Vec::new(),
                "a policy violation becomes a policy test".into(),
            ),
            FindingKind::IntentShift | FindingKind::ForbiddenIntent => (
                "Intent boundary",
                format!(
                    "Assert the agent does not enter the forbidden/shifted intent for this \
                     input class. Source: {}",
                    finding.title
                ),
                vec!["forbidden_intent".into()],
                "an intent shift becomes an intent boundary scenario".into(),
            ),
            FindingKind::Failure | FindingKind::RepeatedFailure => (
                "Failure replay",
                format!(
                    "Replay the failing tool interaction as a fixture and assert graceful \
                     handling. Source: {}",
                    finding.title
                ),
                Vec::new(),
                "a tool failure becomes a failure replay fixture".into(),
            ),
            FindingKind::ReplayDivergence | FindingKind::LowReplayFidelity => (
                "Release validation gate",
                format!(
                    "Add a release validation gate on replay fidelity for this surface. \
                     Source: {}",
                    finding.title
                ),
                Vec::new(),
                "a replay divergence becomes a release validation gate".into(),
            ),
            FindingKind::MissingHumanApproval | FindingKind::DangerousAutonomy => (
                "Human approval gate",
                format!(
                    "Assert the sensitive action requires a recorded human approval. \
                     Source: {}",
                    finding.title
                ),
                vec!["final_decision_without_approval".into()],
                "a missing approval becomes a human-approval gate scenario".into(),
            ),
            FindingKind::ToolMisuse
            | FindingKind::MemoryMisuse
            | FindingKind::SuspiciousOutput
            | FindingKind::Anomaly
            | FindingKind::UnexpectedWorkflowTransition => (
                "Forbidden behavior",
                format!(
                    "Assert the anomalous behavior pattern does not recur for this input \
                     class. Source: {}",
                    finding.title
                ),
                vec![finding.kind.label().to_string()],
                "an anomaly becomes a forbidden-behavior scenario".into(),
            ),
            // Review-side kinds do not loop back into Review.
            FindingKind::RiskGap
            | FindingKind::ContractViolation
            | FindingKind::Regression
            | FindingKind::ScenarioFailure
            | FindingKind::CoverageGap
            | FindingKind::Other => return None,
        };

    let mut scenario = TestScenario::new(
        finding.agent_id.clone(),
        format!("{title_prefix}: {}", finding.title),
        scenario_source_for(finding),
        finding.severity,
    );
    scenario.description = description;
    scenario.genome_hash = finding.genome_hash.clone();
    scenario.risk_ids = finding.risk_ids.clone();
    scenario.forbidden_behaviors = forbidden;
    scenario.evidence_source_refs = finding.evidence_refs.clone();
    scenario.created_by = format!("rmp:{}", finding.loop_stage);
    scenario.tags = vec!["enrichment".into(), finding.kind.label().into()];
    if let Some(observed) = &finding.observed {
        scenario.inputs.push(TestScenarioInput {
            name: Some("observed".into()),
            input: observed.clone(),
            input_hash: None,
        });
    }
    scenario
        .metrics_to_compute
        .push("regression_recurrence_rate".into());

    let mut proposal = ScenarioEnrichmentProposal::new(finding, scenario, reason);
    proposal.expected_coverage_improvement = match finding.severity {
        Severity::Critical => 0.4,
        Severity::High => 0.3,
        Severity::Medium => 0.2,
        Severity::Low | Severity::Info => 0.1,
    };
    Some(proposal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: FindingKind, severity: Severity) -> Finding {
        Finding::new(
            "monitor",
            "sess",
            "agent://acme/claims",
            kind,
            severity,
            "test finding",
            "message",
        )
    }

    #[test]
    fn loop_finding_becomes_scenario() {
        let f = finding(FindingKind::Loop, Severity::High);
        let proposals = proposals_from_findings(&[f]);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert!(p.human_approval_required);
        assert_eq!(p.proposed_scenario.source, ScenarioSource::MonitorDerived);
        assert!(p.proposed_scenario.title.starts_with("Loop regression"));
    }

    #[test]
    fn review_findings_do_not_loop_back() {
        let f = finding(FindingKind::CoverageGap, Severity::Medium);
        assert!(proposals_from_findings(&[f]).is_empty());
    }

    #[test]
    fn approval_workflow() {
        let f = finding(FindingKind::PolicyViolation, Severity::Critical);
        let mut p = proposals_from_findings(&[f]).remove(0);
        assert_eq!(p.status, EnrichmentStatus::Draft);
        p.submit().unwrap();
        // Empty reviewer refused for high-severity proposals.
        assert!(p.approve("").is_err());
        p.approve("alice@example.com").unwrap();
        p.mark_applied().unwrap();
        assert_eq!(p.status, EnrichmentStatus::Applied);
    }

    #[test]
    fn invalid_transition_rejected() {
        let f = finding(FindingKind::Loop, Severity::Low);
        let mut p = proposals_from_findings(&[f]).remove(0);
        assert!(p.mark_applied().is_err());
    }
}
