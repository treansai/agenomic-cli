//! Core RMP domain model: sessions, findings, alerts, recommendations,
//! action plans, evaluation history, and the feedback event that closes the
//! Review → Monitor → Protect → Review loop.
//!
//! All types are serde-serializable, carry an explicit `spec_version`, and
//! are safe for CLI/cloud output: they hold hashes and redacted previews,
//! never raw payloads or secrets.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::Severity;

/// Version stamped on every RMP wire type. Bump on breaking field changes.
pub const RMP_SPEC_VERSION: &str = "agenomic.rmp/v0.1";

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new())
}

/// Processing mode of an RMP session, mirroring the ledger's durability
/// vocabulary ([`agenomic_ledger_local::LedgerMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RmpMode {
    BestEffortLowLatency,
    /// Default: monitor ingestion returns after the WAL append; sealing and
    /// heavy evaluation happen on background workers.
    #[default]
    DurableLowLatency,
    /// Synchronous sealing; for strict policy gating.
    StrictVerified,
    /// Reserved for cloud-synchronous operation.
    StrictCloud,
}

impl RmpMode {
    pub fn to_ledger_mode(self) -> agenomic_ledger_local::LedgerMode {
        use agenomic_ledger_local::LedgerMode as L;
        match self {
            Self::BestEffortLowLatency => L::BestEffortLowLatency,
            Self::DurableLowLatency => L::DurableLowLatency,
            Self::StrictVerified => L::StrictVerified,
            Self::StrictCloud => L::StrictCloud,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::BestEffortLowLatency => "best_effort_low_latency",
            Self::DurableLowLatency => "durable_low_latency",
            Self::StrictVerified => "strict_verified",
            Self::StrictCloud => "strict_cloud",
        }
    }
}

/// Lifecycle of an RMP session and its sub-sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RmpSessionStatus {
    Active,
    Completed,
    Cancelled,
    Failed,
}

impl RmpSessionStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// The umbrella session tying one Review + Monitor + Protect pass together
/// for a single agent/release/environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmpSession {
    pub spec_version: String,
    pub session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub environment: String,
    pub mode: RmpMode,
    /// Whether events are recorded into the cryptographic ledger.
    pub ledger_enabled: bool,
    pub status: RmpSessionStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect_session_id: Option<String>,
}

impl RmpSession {
    pub fn new(agent_id: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            session_id: new_id("rmp"),
            agent_id: agent_id.into(),
            genome_hash: None,
            release_id: None,
            environment: environment.into(),
            mode: RmpMode::default(),
            ledger_enabled: false,
            status: RmpSessionStatus::Active,
            started_at: now(),
            ended_at: None,
            review_session_id: None,
            monitor_session_id: None,
            protect_session_id: None,
        }
    }
}

/// One Review pass over an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSession {
    pub spec_version: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rmp_session_id: Option<String>,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub status: RmpSessionStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Scenario ids selected for this pass.
    #[serde(default)]
    pub scenario_ids: Vec<String>,
}

impl ReviewSession {
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            session_id: new_id("rev"),
            rmp_session_id: None,
            agent_id: agent_id.into(),
            genome_hash: None,
            release_id: None,
            status: RmpSessionStatus::Active,
            started_at: now(),
            ended_at: None,
            scenario_ids: Vec::new(),
        }
    }
}

/// One Monitor pass (wraps an online tracking session).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSession {
    pub spec_version: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rmp_session_id: Option<String>,
    /// The underlying `agenomic-track` session id.
    pub tracking_session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub environment: String,
    pub mode: RmpMode,
    pub ledger_enabled: bool,
    pub status: RmpSessionStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
}

impl MonitorSession {
    /// Wrap an existing tracking session as a monitor session (used when
    /// resuming from the tracking store across CLI invocations).
    pub fn from_tracking(
        tracking: &agenomic_track::TrackingSession,
        mode: RmpMode,
        ledger_enabled: bool,
    ) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            session_id: format!("mon_{}", tracking.session_id),
            rmp_session_id: None,
            tracking_session_id: tracking.session_id.clone(),
            agent_id: tracking.agent_id.clone(),
            genome_hash: tracking.genome_hash.clone(),
            release_id: tracking.release_id.clone(),
            environment: tracking.environment.clone(),
            mode,
            ledger_enabled,
            status: if tracking.status.is_terminal() {
                RmpSessionStatus::Completed
            } else {
                RmpSessionStatus::Active
            },
            started_at: tracking.started_at,
            ended_at: tracking.ended_at,
        }
    }
}

/// One Protect pass over monitor/review findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectSession {
    pub spec_version: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rmp_session_id: Option<String>,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub status: RmpSessionStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
}

impl ProtectSession {
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            session_id: new_id("prt"),
            rmp_session_id: None,
            agent_id: agent_id.into(),
            genome_hash: None,
            release_id: None,
            status: RmpSessionStatus::Active,
            started_at: now(),
            ended_at: None,
        }
    }
}

/// Which loop a finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    // Review
    RiskGap,
    ContractViolation,
    PolicyViolation,
    Regression,
    ScenarioFailure,
    CoverageGap,
    ReplayDivergence,
    // Monitor
    Drift,
    Loop,
    IntentShift,
    Failure,
    HarnessViolation,
    // Protect
    Anomaly,
    ToolMisuse,
    MemoryMisuse,
    DangerousAutonomy,
    ForbiddenIntent,
    UnexpectedWorkflowTransition,
    RepeatedFailure,
    LowReplayFidelity,
    MissingHumanApproval,
    SuspiciousOutput,
    Other,
}

impl FindingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::RiskGap => "risk_gap",
            Self::ContractViolation => "contract_violation",
            Self::PolicyViolation => "policy_violation",
            Self::Regression => "regression",
            Self::ScenarioFailure => "scenario_failure",
            Self::CoverageGap => "coverage_gap",
            Self::ReplayDivergence => "replay_divergence",
            Self::Drift => "drift",
            Self::Loop => "loop",
            Self::IntentShift => "intent_shift",
            Self::Failure => "failure",
            Self::HarnessViolation => "harness_violation",
            Self::Anomaly => "anomaly",
            Self::ToolMisuse => "tool_misuse",
            Self::MemoryMisuse => "memory_misuse",
            Self::DangerousAutonomy => "dangerous_autonomy",
            Self::ForbiddenIntent => "forbidden_intent",
            Self::UnexpectedWorkflowTransition => "unexpected_workflow_transition",
            Self::RepeatedFailure => "repeated_failure",
            Self::LowReplayFidelity => "low_replay_fidelity",
            Self::MissingHumanApproval => "missing_human_approval",
            Self::SuspiciousOutput => "suspicious_output",
            Self::Other => "other",
        }
    }
}

/// Shared finding shape. `ReviewFinding` / `MonitorFinding` /
/// `ProtectFinding` are aliases that fix the `loop_stage` discriminator; the
/// wire format is identical so findings can flow between the three engines
/// without conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub spec_version: String,
    pub finding_id: String,
    /// `review` | `monitor` | `protect`.
    pub loop_stage: String,
    pub session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    /// Risk items this finding maps onto.
    #[serde(default)]
    pub risk_ids: Vec<String>,
    /// Producer event ids / ledger entry ids / report hashes backing this
    /// finding. Always deterministic references, never payloads.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
    pub blocks_release: bool,
    pub requires_human_review: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Finding {
    pub fn new(
        loop_stage: &str,
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        kind: FindingKind,
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            finding_id: new_id("fnd"),
            loop_stage: loop_stage.into(),
            session_id: session_id.into(),
            agent_id: agent_id.into(),
            genome_hash: None,
            kind,
            severity,
            title: title.into(),
            message: message.into(),
            created_at: now(),
            risk_ids: Vec::new(),
            evidence_refs: Vec::new(),
            observed: None,
            expected: None,
            recommended_action: None,
            blocks_release: matches!(severity, Severity::Critical),
            requires_human_review: matches!(severity, Severity::Critical | Severity::High),
            details: None,
        }
    }

    pub fn with_evidence(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.evidence_refs.extend(refs);
        self
    }

    pub fn with_risks(mut self, risk_ids: impl IntoIterator<Item = String>) -> Self {
        self.risk_ids.extend(risk_ids);
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// A finding produced by the Review engine (`loop_stage == "review"`).
pub type ReviewFinding = Finding;
/// A finding produced by the Monitor engine (`loop_stage == "monitor"`).
pub type MonitorFinding = Finding;
/// A finding produced by the Protect engine (`loop_stage == "protect"`).
pub type ProtectFinding = Finding;
/// A Protect finding classified as anomalous behavior.
pub type AnomalyFinding = Finding;
/// A Protect/Review finding for a policy violation.
pub type PolicyViolationFinding = Finding;

/// Result of one evaluation (a review pass, a replay, a scenario run).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationResult {
    Pass,
    Warn,
    Fail,
}

impl EvaluationResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One entry in an agent's evaluation history. History powers regression
/// detection in Review and baseline comparison in Monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationHistoryEntry {
    pub spec_version: String,
    pub entry_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// `review` | `monitor` | `protect` | `replay`.
    pub source: String,
    pub session_id: String,
    pub result: EvaluationResult,
    /// 0.0 (worst) ..= 1.0 (best).
    pub score: f64,
    pub metrics: serde_json::Value,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl EvaluationHistoryEntry {
    pub fn new(
        agent_id: impl Into<String>,
        source: &str,
        session_id: impl Into<String>,
        result: EvaluationResult,
        score: f64,
    ) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            entry_id: new_id("evl"),
            agent_id: agent_id.into(),
            genome_hash: None,
            release_id: None,
            source: source.into(),
            session_id: session_id.into(),
            result,
            score: score.clamp(0.0, 1.0),
            metrics: serde_json::Value::Null,
            created_at: now(),
            evidence_refs: Vec::new(),
        }
    }
}

/// Alert lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

/// Where an alert is delivered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertRoute {
    /// Team / channel identifier, e.g. `security-oncall`, `ml-platform`.
    pub target: String,
    /// `slack` | `email` | `webhook` | `pagerduty` | `stdout` — transport is
    /// resolved by the hosting integration; this crate only records routing.
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routed_at: Option<DateTime<Utc>>,
}

/// An operator-facing alert produced by Protect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub spec_version: String,
    pub alert_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub severity: Severity,
    pub status: AlertStatus,
    pub title: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    /// Findings folded into this alert (deduplication groups incidents).
    #[serde(default)]
    pub finding_ids: Vec<String>,
    /// Stable key used for dedup/grouping (`kind:agent:signature`).
    pub dedup_key: String,
    /// How many times this alert fired (dedup increments instead of
    /// re-raising).
    pub occurrence_count: u64,
    #[serde(default)]
    pub routes: Vec<AlertRoute>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// True when the alert was withheld from notification by throttling.
    pub throttled: bool,
    pub escalated: bool,
}

/// The kind of change a recommendation proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationKind {
    PromptImprovement,
    PolicyChange,
    ContractChange,
    WorkflowGuardrail,
    ToolPermissionChange,
    HumanApprovalGate,
    ReplayScenario,
    RiskMatrixUpdate,
    ReleaseRollback,
    MonitoringThresholdUpdate,
    HarnessRuleUpdate,
}

impl RecommendationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PromptImprovement => "prompt_improvement",
            Self::PolicyChange => "policy_change",
            Self::ContractChange => "contract_change",
            Self::WorkflowGuardrail => "workflow_guardrail",
            Self::ToolPermissionChange => "tool_permission_change",
            Self::HumanApprovalGate => "human_approval_gate",
            Self::ReplayScenario => "replay_scenario",
            Self::RiskMatrixUpdate => "risk_matrix_update",
            Self::ReleaseRollback => "release_rollback",
            Self::MonitoringThresholdUpdate => "monitoring_threshold_update",
            Self::HarnessRuleUpdate => "harness_rule_update",
        }
    }

    /// High-impact kinds always require human approval before being applied.
    pub fn is_high_impact(self) -> bool {
        matches!(
            self,
            Self::PolicyChange
                | Self::ContractChange
                | Self::ToolPermissionChange
                | Self::ReleaseRollback
                | Self::WorkflowGuardrail
        )
    }
}

/// A structural / prompt / policy change proposed by Protect. Never applied
/// automatically: `requires_human_approval` gates every high-impact kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub spec_version: String,
    pub recommendation_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub kind: RecommendationKind,
    pub severity: Severity,
    pub title: String,
    /// Deterministic rationale (always present, even when an LLM narrative
    /// is attached separately).
    pub rationale: String,
    /// The proposed change as structured data (e.g. a policy rule hint, a
    /// threshold value). Advisory only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<serde_json::Value>,
    pub requires_human_approval: bool,
    /// `proposed` | `approved` | `rejected` | `applied`.
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub source_finding_ids: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl Recommendation {
    pub fn new(
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        kind: RecommendationKind,
        severity: Severity,
        title: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            recommendation_id: new_id("rec"),
            session_id: session_id.into(),
            agent_id: agent_id.into(),
            kind,
            severity,
            title: title.into(),
            rationale: rationale.into(),
            proposal: None,
            requires_human_approval: kind.is_high_impact()
                || matches!(severity, Severity::High | Severity::Critical),
            status: "proposed".into(),
            created_at: now(),
            source_finding_ids: Vec::new(),
            evidence_refs: Vec::new(),
        }
    }
}

/// One step of an action plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPlanStep {
    pub step_id: String,
    pub order: u32,
    pub title: String,
    pub description: String,
    /// `investigate` | `mitigate` | `remediate` | `verify` | `document`.
    pub phase: String,
    pub requires_human_approval: bool,
    #[serde(default)]
    pub recommendation_ids: Vec<String>,
    /// `pending` | `in_progress` | `done` | `skipped`.
    pub status: String,
}

/// An ordered remediation plan generated from an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPlan {
    pub spec_version: String,
    pub plan_id: String,
    pub alert_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub severity: Severity,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub steps: Vec<ActionPlanStep>,
    /// Scenario enrichment proposals attached to this plan.
    #[serde(default)]
    pub scenario_proposal_ids: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

/// A reference container for an exported RMP evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmpEvidenceBundle {
    pub spec_version: String,
    pub bundle_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub created_at: DateTime<Utc>,
    /// Relative file names contained in the bundle.
    pub files: Vec<String>,
    /// blake3 hash of the manifest content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub ledger_included: bool,
}

/// The feedback event closing the loop: a Monitor/Protect output flowing
/// back into Review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmpFeedbackEvent {
    pub spec_version: String,
    pub feedback_id: String,
    /// `monitor` | `protect`.
    pub source_stage: String,
    pub source_session_id: String,
    pub agent_id: String,
    /// `scenario_proposal` | `risk_item` | `contract_check` |
    /// `policy_suggestion` | `human_review_requirement`.
    pub feedback_kind: String,
    /// Id of the produced artifact (proposal id, risk id, …).
    pub artifact_id: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl RmpFeedbackEvent {
    pub fn new(
        source_stage: &str,
        source_session_id: impl Into<String>,
        agent_id: impl Into<String>,
        feedback_kind: &str,
        artifact_id: impl Into<String>,
    ) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            feedback_id: new_id("fbk"),
            source_stage: source_stage.into(),
            source_session_id: source_session_id.into(),
            agent_id: agent_id.into(),
            feedback_kind: feedback_kind.into(),
            artifact_id: artifact_id.into(),
            created_at: now(),
            evidence_refs: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_roundtrip() {
        let f = Finding::new(
            "monitor",
            "sess-1",
            "agent://acme/claims",
            FindingKind::Loop,
            Severity::High,
            "Tool loop",
            "claims_db.lookup called 12 times",
        );
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, FindingKind::Loop);
        assert!(back.requires_human_review);
        assert_eq!(back.spec_version, RMP_SPEC_VERSION);
    }

    #[test]
    fn critical_finding_blocks_release() {
        let f = Finding::new(
            "review",
            "s",
            "agent://a/b",
            FindingKind::PolicyViolation,
            Severity::Critical,
            "t",
            "m",
        );
        assert!(f.blocks_release);
    }

    #[test]
    fn high_impact_recommendation_requires_approval() {
        let r = Recommendation::new(
            "s",
            "agent://a/b",
            RecommendationKind::PolicyChange,
            Severity::Low,
            "t",
            "r",
        );
        assert!(r.requires_human_approval);
        let r2 = Recommendation::new(
            "s",
            "agent://a/b",
            RecommendationKind::PromptImprovement,
            Severity::Low,
            "t",
            "r",
        );
        assert!(!r2.requires_human_approval);
    }
}
