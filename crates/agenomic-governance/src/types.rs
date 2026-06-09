//! Public types shared by the three governance engines.
//!
//! The flow is `FlaggedTrace → Cluster → Proposal → Critique`, all
//! JSON-serializable so the CLI can pass them between subcommands as files.

use serde::{Deserialize, Serialize};

/// One production trace that an external feedback loop has flagged as
/// negative (an escalation, a complaint, a refund granted, …). The shape is
/// intentionally small and self-contained so feedback pipelines can produce
/// it without depending on the much larger trace-event schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlaggedTrace {
    pub trace_id: String,
    pub agent_id: String,
    /// Skill that handled the input, e.g. `compensation_disambiguation`.
    pub skill: String,
    /// Optional pinned version of the skill (e.g. `@7`).
    #[serde(default)]
    pub skill_version: Option<String>,
    pub signal: FailureSignal,
    /// Short user-visible input snippet (the diagnostic engine keyword-mines this).
    #[serde(default)]
    pub input_snippet: String,
    /// Short agent-output snippet.
    #[serde(default)]
    pub output_snippet: String,
}

/// Why a trace was flagged. Free-form `Other` is preserved for forward
/// compatibility — clustering treats it as a distinct signal per literal
/// string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FailureSignal {
    Escalation,
    Complaint,
    RefundGranted,
    ContractViolation,
    HumanOverride,
    Other(String),
}

impl FailureSignal {
    /// Stable label used for cluster IDs and report ordering.
    pub fn label(&self) -> &str {
        match self {
            FailureSignal::Escalation => "escalation",
            FailureSignal::Complaint => "complaint",
            FailureSignal::RefundGranted => "refund_granted",
            FailureSignal::ContractViolation => "contract_violation",
            FailureSignal::HumanOverride => "human_override",
            FailureSignal::Other(s) => s.as_str(),
        }
    }
}

/// A group of traces sharing a `(signal, skill)` and overlapping keywords.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cluster {
    pub id: String,
    pub signal: FailureSignal,
    pub skill: String,
    pub size: usize,
    pub members: Vec<String>,
    /// Top stopword-filtered keywords mined from input + output snippets, in
    /// descending frequency then lexicographic order.
    pub keywords: Vec<String>,
    /// Up to 3 representative snippets (the first member-snippet for each of
    /// the cluster's three most-frequent keywords).
    pub exemplars: Vec<String>,
}

/// A textual remediation proposal generated for a cluster. **No code is
/// changed**: the hypothesis agent only proposes, a human approves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub id: String,
    pub cluster_id: String,
    pub target_skill: String,
    #[serde(default)]
    pub target_version: Option<String>,
    /// Human-readable hypothesis ("the skill X@v does not cover the case Y").
    pub hypothesis: String,
    pub suggested_action: ProposalAction,
    /// Number of cluster members backing this proposal — fed straight into
    /// the adversarial reviewer's "sample size" check.
    pub evidence_count: usize,
}

/// What the proposal asks the operator to consider. Mutating the bundle is
/// always the operator's call; this is only a typed recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalAction {
    /// Extend the skill's prompt with N additional examples covering the cluster's keywords.
    ExtendSkillExamples { count: usize },
    /// Narrow the skill's scope to exclude inputs containing the listed keywords.
    NarrowSkillScope { excluded_keywords: Vec<String> },
    /// Add a policy rule anchored on a keyword phrase.
    AddPolicyRule { rule_hint: String },
    /// Re-design the escalation path (used for refund-granted / human-override on critical skills).
    EscalationOverhaul,
    /// No action; the cluster's signal does not map to a known remediation.
    None,
}

impl ProposalAction {
    /// Stable label for hashing and reporting.
    pub fn label(&self) -> &'static str {
        match self {
            ProposalAction::ExtendSkillExamples { .. } => "extend_skill_examples",
            ProposalAction::NarrowSkillScope { .. } => "narrow_skill_scope",
            ProposalAction::AddPolicyRule { .. } => "add_policy_rule",
            ProposalAction::EscalationOverhaul => "escalation_overhaul",
            ProposalAction::None => "none",
        }
    }
}

/// The adversarial reviewer's verdict over one proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Critique {
    pub proposal_id: String,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub area: String,
    pub title: String,
    pub body: String,
    pub citations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Mapping from the maximum severity in `findings` to a top-line verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No findings, or only `info`.
    Pass,
    /// Highest finding severity is `low` or `medium` — operator may proceed
    /// with awareness.
    Warn,
    /// Highest finding severity is `high` or `critical` — proposal must be
    /// revised before approval.
    Block,
}

impl Verdict {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let max = findings.iter().map(|f| f.severity).max();
        match max {
            None | Some(Severity::Info) => Verdict::Pass,
            Some(Severity::Low) | Some(Severity::Medium) => Verdict::Warn,
            Some(Severity::High) | Some(Severity::Critical) => Verdict::Block,
        }
    }
}
