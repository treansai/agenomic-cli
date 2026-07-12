//! The Protect engine: anomaly detection, alert generation/deduplication/
//! routing/throttling, recommendations, and action plans.
//!
//! Protect consumes findings (from Monitor, Review, and governance agents)
//! plus raw evaluation signals, and produces operator-facing artifacts. It
//! is fully deterministic: the same findings produce the same alerts,
//! recommendations, and plans. It never mutates a bundle, policy, or
//! contract — every high-impact recommendation requires human approval.

use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use agenomic_core::{CliResult, Severity};

use crate::enrich::{proposals_from_findings, ScenarioEnrichmentProposal};
use crate::risk::RiskMatrix;
use crate::types::{
    ActionPlan, ActionPlanStep, Alert, AlertRoute, AlertStatus, Finding, FindingKind,
    ProtectSession, Recommendation, RecommendationKind, RmpSessionStatus, RMP_SPEC_VERSION,
};

/// Default maximum number of notifications per dedup group per pass;
/// occurrences beyond it are recorded but marked throttled.
pub const DEFAULT_THROTTLE_LIMIT: u64 = 3;

/// One routing rule: findings matching `kind_label` / minimum severity go
/// to `route`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    /// Finding-kind label to match (`drift`, `policy_violation`, …) or
    /// `"*"` for any.
    pub kind: String,
    /// Minimum severity for this rule to apply.
    pub min_severity: Severity,
    /// Team / channel target.
    pub target: String,
    /// Transport channel (`slack` | `email` | `webhook` | `pagerduty` |
    /// `stdout`).
    pub channel: String,
}

/// Deterministic alert router. Rules are evaluated in order; every matching
/// rule adds a route. With no matching rule, the default route applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRouter {
    pub rules: Vec<RouteRule>,
    pub default_target: String,
    pub default_channel: String,
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self {
            rules: vec![
                RouteRule {
                    kind: "policy_violation".into(),
                    min_severity: Severity::Medium,
                    target: "security-oncall".into(),
                    channel: "pagerduty".into(),
                },
                RouteRule {
                    kind: "anomaly".into(),
                    min_severity: Severity::High,
                    target: "security-oncall".into(),
                    channel: "pagerduty".into(),
                },
                RouteRule {
                    kind: "drift".into(),
                    min_severity: Severity::Medium,
                    target: "ml-platform".into(),
                    channel: "slack".into(),
                },
                RouteRule {
                    kind: "loop".into(),
                    min_severity: Severity::Medium,
                    target: "agent-owners".into(),
                    channel: "slack".into(),
                },
            ],
            default_target: "agent-owners".into(),
            default_channel: "slack".into(),
        }
    }
}

impl AlertRouter {
    /// Resolve routes for a finding kind + severity.
    pub fn routes_for(&self, kind_label: &str, severity: Severity) -> Vec<AlertRoute> {
        let mut routes: Vec<AlertRoute> = self
            .rules
            .iter()
            .filter(|r| (r.kind == "*" || r.kind == kind_label) && severity >= r.min_severity)
            .map(|r| AlertRoute {
                target: r.target.clone(),
                channel: r.channel.clone(),
                routed_at: Some(Utc::now()),
            })
            .collect();
        if routes.is_empty() {
            routes.push(AlertRoute {
                target: self.default_target.clone(),
                channel: self.default_channel.clone(),
                routed_at: Some(Utc::now()),
            });
        }
        routes.dedup_by(|a, b| a.target == b.target && a.channel == b.channel);
        routes
    }
}

/// Protect configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectConfig {
    pub router: AlertRouter,
    /// Max notifications per dedup group per pass.
    pub throttle_limit: u64,
    /// Findings at or above this severity escalate their alert.
    pub escalate_at: Severity,
    /// Consecutive failure findings that count as a repeated failure.
    pub repeated_failure_threshold: usize,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        Self {
            router: AlertRouter::default(),
            throttle_limit: DEFAULT_THROTTLE_LIMIT,
            escalate_at: Severity::Critical,
            repeated_failure_threshold: 3,
        }
    }
}

/// Output of one Protect pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectOutcome {
    pub spec_version: String,
    pub session: ProtectSession,
    /// Anomaly findings raised by Protect itself (on top of the inputs).
    pub anomaly_findings: Vec<Finding>,
    pub alerts: Vec<Alert>,
    pub recommendations: Vec<Recommendation>,
    pub action_plans: Vec<ActionPlan>,
    pub scenario_proposals: Vec<ScenarioEnrichmentProposal>,
}

/// The Protect engine. Stateless between passes; feed it the accumulated
/// findings of a session.
#[derive(Debug, Clone, Default)]
pub struct ProtectEngine {
    pub config: ProtectConfig,
}

impl ProtectEngine {
    /// Create an engine with the given config.
    pub fn new(config: ProtectConfig) -> Self {
        Self { config }
    }

    /// Run a Protect pass over findings (typically Monitor's plus carried
    /// Review findings). `risk_matrix` sharpens anomaly detection when
    /// available.
    pub fn run(
        &self,
        agent_id: &str,
        findings: &[Finding],
        risk_matrix: Option<&RiskMatrix>,
    ) -> CliResult<ProtectOutcome> {
        let mut session = ProtectSession::new(agent_id);

        // 1. Anomaly detection: derive Protect-level findings from patterns
        //    the per-event detectors cannot see.
        let anomaly_findings = self.detect_anomalies(&session, agent_id, findings, risk_matrix);

        // 2. All findings (input + derived) become alert candidates.
        let mut all: Vec<&Finding> = findings.iter().chain(anomaly_findings.iter()).collect();
        // Deterministic ordering: severity desc, then kind, then id.
        all.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.kind.label().cmp(b.kind.label()))
                .then_with(|| a.finding_id.cmp(&b.finding_id))
        });

        // 3. Alert generation with dedup, grouping, throttling, routing.
        let alerts = self.generate_alerts(&session, agent_id, &all);

        // 4. Recommendations.
        let recommendations = self.recommend(&session, agent_id, &all);

        // 5. Action plans for the highest-severity alerts.
        let scenario_proposals = proposals_from_findings(
            &all.iter().map(|f| (*f).clone()).collect::<Vec<_>>(),
        );
        let action_plans: Vec<ActionPlan> = alerts
            .iter()
            .filter(|a| a.severity >= Severity::High)
            .map(|a| self.action_plan(a, &recommendations, &scenario_proposals))
            .collect();

        session.status = RmpSessionStatus::Completed;
        session.ended_at = Some(Utc::now());

        Ok(ProtectOutcome {
            spec_version: RMP_SPEC_VERSION.into(),
            session,
            anomaly_findings,
            alerts,
            recommendations,
            action_plans,
            scenario_proposals,
        })
    }

    /// Generate an action plan for a single alert (used by
    /// `agenomic protect action-plan --alert <id>`).
    pub fn action_plan(
        &self,
        alert: &Alert,
        recommendations: &[Recommendation],
        proposals: &[ScenarioEnrichmentProposal],
    ) -> ActionPlan {
        let related_recs: Vec<&Recommendation> = recommendations
            .iter()
            .filter(|r| {
                r.source_finding_ids
                    .iter()
                    .any(|id| alert.finding_ids.contains(id))
            })
            .collect();
        let related_proposals: Vec<&ScenarioEnrichmentProposal> = proposals
            .iter()
            .filter(|p| alert.finding_ids.contains(&p.source_finding_id))
            .collect();

        let mut steps: Vec<ActionPlanStep> = Vec::new();
        let mut order: u32 = 1;
        let push = |title: String, description: String, phase: &str, approval: bool,
                        rec_ids: Vec<String>,
                        steps: &mut Vec<ActionPlanStep>,
                        order: &mut u32| {
            steps.push(ActionPlanStep {
                step_id: format!("aps_{}", ulid::Ulid::new()),
                order: *order,
                title,
                description,
                phase: phase.into(),
                requires_human_approval: approval,
                recommendation_ids: rec_ids,
                status: "pending".into(),
            });
            *order += 1;
        };

        push(
            format!("Triage: {}", alert.title),
            format!(
                "Review the alert evidence ({} reference(s)) and confirm the incident scope.",
                alert.evidence_refs.len()
            ),
            "investigate",
            false,
            Vec::new(),
            &mut steps,
            &mut order,
        );
        if alert.severity >= Severity::Critical {
            push(
                "Contain: pause or constrain the agent".into(),
                "For critical incidents, gate the affected tools or pause the release while \
                 the incident is investigated."
                    .into(),
                "mitigate",
                true,
                Vec::new(),
                &mut steps,
                &mut order,
            );
        }
        for rec in &related_recs {
            push(
                format!("Apply recommendation: {}", rec.title),
                rec.rationale.clone(),
                "remediate",
                rec.requires_human_approval,
                vec![rec.recommendation_id.clone()],
                &mut steps,
                &mut order,
            );
        }
        push(
            "Verify via replay".into(),
            "Re-run Review with the enriched scenario corpus and confirm the finding no \
             longer reproduces."
                .into(),
            "verify",
            false,
            Vec::new(),
            &mut steps,
            &mut order,
        );
        push(
            "Document and export evidence".into(),
            "Export the RMP evidence bundle (including the ledger proof when enabled) for \
             the audit trail."
                .into(),
            "document",
            false,
            Vec::new(),
            &mut steps,
            &mut order,
        );

        ActionPlan {
            spec_version: RMP_SPEC_VERSION.into(),
            plan_id: format!("plan_{}", ulid::Ulid::new()),
            alert_id: alert.alert_id.clone(),
            session_id: alert.session_id.clone(),
            agent_id: alert.agent_id.clone(),
            severity: alert.severity,
            title: format!("Action plan: {}", alert.title),
            created_at: Utc::now(),
            steps,
            scenario_proposal_ids: related_proposals
                .iter()
                .map(|p| p.proposal_id.clone())
                .collect(),
            evidence_refs: alert.evidence_refs.clone(),
        }
    }

    // ---- anomaly detection --------------------------------------------

    fn detect_anomalies(
        &self,
        session: &ProtectSession,
        agent_id: &str,
        findings: &[Finding],
        risk_matrix: Option<&RiskMatrix>,
    ) -> Vec<Finding> {
        let mut out = Vec::new();

        // Repeated failures: N same-kind failure findings become one
        // repeated-failure anomaly.
        let failure_count = findings
            .iter()
            .filter(|f| matches!(f.kind, FindingKind::Failure | FindingKind::HarnessViolation))
            .count();
        if failure_count >= self.config.repeated_failure_threshold {
            out.push(
                Finding::new(
                    "protect",
                    &session.session_id,
                    agent_id,
                    FindingKind::RepeatedFailure,
                    Severity::High,
                    format!("{failure_count} failures in one session"),
                    "repeated failures exceed the configured threshold; the agent is \
                     likely stuck in a degraded state",
                )
                .with_evidence(findings.iter().filter(|f| {
                    matches!(f.kind, FindingKind::Failure | FindingKind::HarnessViolation)
                }).map(|f| f.finding_id.clone())),
            );
        }

        // Missing human approval on a critical finding that requires it.
        let unapproved: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.requires_human_review && f.severity >= Severity::Critical)
            .collect();
        if !unapproved.is_empty() {
            out.push(
                Finding::new(
                    "protect",
                    &session.session_id,
                    agent_id,
                    FindingKind::MissingHumanApproval,
                    Severity::Critical,
                    "Critical finding awaiting human review",
                    format!(
                        "{} critical finding(s) require human review before release",
                        unapproved.len()
                    ),
                )
                .with_evidence(unapproved.iter().map(|f| f.finding_id.clone())),
            );
        }

        // Dangerous autonomy: intent or policy findings on an agent whose
        // risk assessment says it acts without a human in the loop.
        if let Some(matrix) = risk_matrix {
            if let Some(assessment) = &matrix.assessment {
                let risky_behavior = findings.iter().any(|f| {
                    matches!(
                        f.kind,
                        FindingKind::IntentShift
                            | FindingKind::ForbiddenIntent
                            | FindingKind::PolicyViolation
                    )
                });
                if risky_behavior
                    && !assessment.human_in_the_loop
                    && assessment.autonomy_level > 0.5
                {
                    out.push(Finding::new(
                        "protect",
                        &session.session_id,
                        agent_id,
                        FindingKind::DangerousAutonomy,
                        Severity::Critical,
                        "Autonomous agent violated intent/policy boundaries",
                        "an agent with high autonomy and no human in the loop produced \
                         intent or policy findings; add a human approval gate",
                    ));
                }
            }
        }

        out
    }

    // ---- alert generation ---------------------------------------------

    fn generate_alerts(
        &self,
        session: &ProtectSession,
        agent_id: &str,
        findings: &[&Finding],
    ) -> Vec<Alert> {
        // Group by dedup key: kind + coarse signature (title).
        let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            let key = format!("{}:{}:{}", f.kind.label(), f.agent_id, f.title);
            groups.entry(key).or_default().push(f);
        }
        let mut alerts: Vec<Alert> = groups
            .into_iter()
            .map(|(dedup_key, group)| {
                // Safe: groups are built from non-empty pushes.
                let first = group[0];
                let severity = group.iter().map(|f| f.severity).max().unwrap_or(first.severity);
                let occurrence_count = group.len() as u64;
                let mut evidence: Vec<String> = group
                    .iter()
                    .flat_map(|f| f.evidence_refs.iter().cloned())
                    .collect();
                evidence.sort();
                evidence.dedup();
                Alert {
                    spec_version: RMP_SPEC_VERSION.into(),
                    alert_id: format!("alr_{}", ulid::Ulid::new()),
                    session_id: session.session_id.clone(),
                    agent_id: agent_id.to_string(),
                    severity,
                    status: AlertStatus::Open,
                    title: first.title.clone(),
                    message: first.message.clone(),
                    created_at: Utc::now(),
                    finding_ids: group.iter().map(|f| f.finding_id.clone()).collect(),
                    dedup_key,
                    occurrence_count,
                    routes: self.config.router.routes_for(first.kind.label(), severity),
                    evidence_refs: evidence,
                    throttled: occurrence_count > self.config.throttle_limit,
                    escalated: severity >= self.config.escalate_at,
                }
            })
            .collect();
        // Highest severity first.
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.dedup_key.cmp(&b.dedup_key)));
        alerts
    }

    // ---- recommendations ------------------------------------------------

    fn recommend(
        &self,
        session: &ProtectSession,
        agent_id: &str,
        findings: &[&Finding],
    ) -> Vec<Recommendation> {
        let mut recs: Vec<Recommendation> = Vec::new();
        let mut seen: std::collections::HashSet<(RecommendationKind, String)> =
            std::collections::HashSet::new();
        for f in findings {
            for (kind, title, rationale) in recommendation_templates(f) {
                if !seen.insert((kind, title.clone())) {
                    continue;
                }
                let mut rec = Recommendation::new(
                    &session.session_id,
                    agent_id,
                    kind,
                    f.severity,
                    title,
                    rationale,
                );
                rec.source_finding_ids.push(f.finding_id.clone());
                rec.evidence_refs = f.evidence_refs.clone();
                recs.push(rec);
            }
        }
        recs
    }
}

/// Deterministic finding→recommendation templates.
fn recommendation_templates(
    f: &Finding,
) -> Vec<(RecommendationKind, String, String)> {
    let src = &f.title;
    match f.kind {
        FindingKind::Drift => vec![
            (
                RecommendationKind::MonitoringThresholdUpdate,
                format!("Tighten drift baseline after: {src}"),
                "confirm whether the drifted surface is intentional; if not, roll back, \
                 if yes, refresh the release baseline"
                    .into(),
            ),
            (
                RecommendationKind::ReplayScenario,
                format!("Add drift regression scenario for: {src}"),
                "pin the expected surface in a replay scenario so the drift cannot recur \
                 silently"
                    .into(),
            ),
        ],
        FindingKind::Loop => vec![
            (
                RecommendationKind::WorkflowGuardrail,
                format!("Add loop guardrail for: {src}"),
                "bound repeated tool calls / iterations in the workflow configuration".into(),
            ),
            (
                RecommendationKind::ReplayScenario,
                format!("Add loop regression scenario for: {src}"),
                "replay the looping sequence as a regression scenario".into(),
            ),
        ],
        FindingKind::IntentShift | FindingKind::ForbiddenIntent => vec![
            (
                RecommendationKind::PromptImprovement,
                format!("Clarify intent boundaries in the prompt: {src}"),
                "the system prompt should state the allowed intents explicitly".into(),
            ),
            (
                RecommendationKind::HumanApprovalGate,
                format!("Gate intent escalations behind approval: {src}"),
                "route out-of-scope intents to a human before the agent acts".into(),
            ),
        ],
        FindingKind::PolicyViolation | FindingKind::HarnessViolation => vec![
            (
                RecommendationKind::PolicyChange,
                format!("Review policy rule that fired: {src}"),
                "confirm the deny is correct, then add a policy test so the rule stays \
                 enforced"
                    .into(),
            ),
            (
                RecommendationKind::HarnessRuleUpdate,
                format!("Add harness rule for: {src}"),
                "encode the violated expectation as a runtime harness check".into(),
            ),
        ],
        FindingKind::ToolMisuse | FindingKind::DangerousAutonomy => vec![
            (
                RecommendationKind::ToolPermissionChange,
                format!("Restrict tool permissions after: {src}"),
                "narrow the tool allow-list or scope the tool's permissions".into(),
            ),
            (
                RecommendationKind::HumanApprovalGate,
                format!("Require approval for sensitive tools: {src}"),
                "sensitive/irreversible tools should require a recorded human approval".into(),
            ),
        ],
        FindingKind::RepeatedFailure | FindingKind::Failure => vec![(
            RecommendationKind::ReleaseRollback,
            format!("Consider rollback after repeated failures: {src}"),
            "repeated failures on a fresh release usually indicate a regression; roll \
             back to the last attested release"
                .into(),
        )],
        FindingKind::ReplayDivergence | FindingKind::LowReplayFidelity => vec![(
            RecommendationKind::RiskMatrixUpdate,
            format!("Record replay-fidelity risk: {src}"),
            "low replay fidelity weakens release evidence; track it as an explicit risk".into(),
        )],
        FindingKind::MissingHumanApproval => vec![(
            RecommendationKind::HumanApprovalGate,
            format!("Enforce the missing approval gate: {src}"),
            "an approval that should have been recorded was absent; enforce it at the \
             tool boundary gate"
                .into(),
        )],
        FindingKind::Anomaly
        | FindingKind::MemoryMisuse
        | FindingKind::SuspiciousOutput
        | FindingKind::UnexpectedWorkflowTransition => vec![(
            RecommendationKind::ContractChange,
            format!("Add behavior-contract check for: {src}"),
            "encode the expected behavior as a deterministic contract rule".into(),
        )],
        FindingKind::RiskGap | FindingKind::CoverageGap => vec![(
            RecommendationKind::RiskMatrixUpdate,
            format!("Update the risk matrix: {src}"),
            "close the identified gap in the risk matrix and cover it with a scenario".into(),
        )],
        FindingKind::ContractViolation
        | FindingKind::Regression
        | FindingKind::ScenarioFailure
        | FindingKind::Other => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: FindingKind, severity: Severity, title: &str) -> Finding {
        Finding::new(
            "monitor",
            "mon_1",
            "agent://acme/claims",
            kind,
            severity,
            title,
            "msg",
        )
    }

    #[test]
    fn identical_findings_dedup_into_one_alert() {
        let findings: Vec<Finding> = (0..5)
            .map(|_| finding(FindingKind::Loop, Severity::High, "same loop"))
            .collect();
        let out = ProtectEngine::default()
            .run("agent://acme/claims", &findings, None)
            .unwrap();
        assert_eq!(out.alerts.len(), 1);
        assert_eq!(out.alerts[0].occurrence_count, 5);
        assert!(out.alerts[0].throttled); // 5 > DEFAULT_THROTTLE_LIMIT
    }

    #[test]
    fn routing_matches_rules() {
        let findings = vec![finding(
            FindingKind::PolicyViolation,
            Severity::Critical,
            "deny fired",
        )];
        let out = ProtectEngine::default()
            .run("agent://acme/claims", &findings, None)
            .unwrap();
        let alert = out
            .alerts
            .iter()
            .find(|a| a.dedup_key.starts_with("policy_violation:"))
            .expect("policy alert present");
        assert!(alert
            .routes
            .iter()
            .any(|r| r.target == "security-oncall" && r.channel == "pagerduty"));
        assert!(alert.escalated);
    }

    #[test]
    fn repeated_failures_become_anomaly() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(FindingKind::Failure, Severity::Medium, &format!("f{i}")))
            .collect();
        let out = ProtectEngine::default()
            .run("agent://acme/claims", &findings, None)
            .unwrap();
        assert!(out
            .anomaly_findings
            .iter()
            .any(|f| f.kind == FindingKind::RepeatedFailure));
    }

    #[test]
    fn high_severity_alert_gets_action_plan() {
        let findings = vec![finding(
            FindingKind::PolicyViolation,
            Severity::Critical,
            "deny fired",
        )];
        let out = ProtectEngine::default()
            .run("agent://acme/claims", &findings, None)
            .unwrap();
        assert!(!out.action_plans.is_empty());
        let plan = &out.action_plans[0];
        // Critical plans include a containment step requiring approval.
        assert!(plan
            .steps
            .iter()
            .any(|s| s.phase == "mitigate" && s.requires_human_approval));
        // Recommendations referenced by the plan are high-impact and gated.
        assert!(out
            .recommendations
            .iter()
            .filter(|r| r.kind == RecommendationKind::PolicyChange)
            .all(|r| r.requires_human_approval));
    }

    #[test]
    fn recommendations_deduplicate() {
        let findings: Vec<Finding> = (0..3)
            .map(|_| finding(FindingKind::Drift, Severity::Medium, "same drift"))
            .collect();
        let out = ProtectEngine::default()
            .run("agent://acme/claims", &findings, None)
            .unwrap();
        let drift_recs: Vec<_> = out
            .recommendations
            .iter()
            .filter(|r| r.kind == RecommendationKind::MonitoringThresholdUpdate)
            .collect();
        assert_eq!(drift_recs.len(), 1);
    }
}
