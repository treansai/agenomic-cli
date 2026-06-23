//! The gate's verdict types and their stable human rendering.

use serde::Serialize;

use agenomic_policy::PolicyDecision;

use crate::toolcall::Provenance;

/// The severity of a single gate finding. Declaration order is the precedence
/// order used by [`decide`] and by sorting: `Block` outranks `RequireApproval`
/// outranks `Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    Block,
    RequireApproval,
    Info,
}

/// One reason the gate reached its verdict, carrying a **stable rule id** so the
/// decision is auditable and snapshot-stable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GateReason {
    pub kind: ReasonKind,
    /// Stable identifier, e.g. `"self_modification"`, `"pii_external_egress"`.
    pub rule: String,
    pub message: String,
}

impl GateReason {
    pub fn block(rule: &str, message: impl Into<String>) -> Self {
        Self {
            kind: ReasonKind::Block,
            rule: rule.into(),
            message: message.into(),
        }
    }
    pub fn require_approval(rule: &str, message: impl Into<String>) -> Self {
        Self {
            kind: ReasonKind::RequireApproval,
            rule: rule.into(),
            message: message.into(),
        }
    }
    pub fn info(rule: &str, message: impl Into<String>) -> Self {
        Self {
            kind: ReasonKind::Info,
            rule: rule.into(),
            message: message.into(),
        }
    }
}

/// The gate's terminal decision for a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Allow,
    Block,
    RequireHumanApproval,
}

impl GateDecision {
    /// Stable uppercase label used in human output.
    pub fn label(self) -> &'static str {
        match self {
            GateDecision::Allow => "ALLOW",
            GateDecision::Block => "BLOCK",
            GateDecision::RequireHumanApproval => "REVIEW",
        }
    }
}

/// Collapse a set of reasons into one decision. Any `Block` wins; otherwise any
/// `RequireApproval` wins; otherwise `Allow`. Total and deterministic.
pub fn decide(reasons: &[GateReason]) -> GateDecision {
    if reasons.iter().any(|r| r.kind == ReasonKind::Block) {
        GateDecision::Block
    } else if reasons
        .iter()
        .any(|r| r.kind == ReasonKind::RequireApproval)
    {
        GateDecision::RequireHumanApproval
    } else {
        GateDecision::Allow
    }
}

/// The full, auditable result of evaluating one tool call at the boundary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateOutcome {
    pub tool: String,
    pub provenance: Provenance,
    pub decision: GateDecision,
    /// Findings, sorted (blocks first, then by rule id).
    pub reasons: Vec<GateReason>,
    /// The reused Rego policy decision (empty bundle ⇒ allowed).
    pub policy: PolicyDecision,
}

impl GateOutcome {
    /// `true` when the call may proceed without interruption.
    pub fn is_allowed(&self) -> bool {
        self.decision == GateDecision::Allow
    }

    /// Render a stable, colour-free human summary (used for snapshot tests and
    /// the CLI's `human` output).
    pub fn render_human(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Tool Boundary Gate — {}\n", self.decision.label()));
        s.push_str(&format!("  tool:       {}\n", self.tool));
        s.push_str(&format!("  provenance: {}\n", self.provenance.label()));
        if self.reasons.is_empty() {
            s.push_str("  reasons:    (none — no invariant tripped)\n");
        } else {
            s.push_str("  reasons:\n");
            for r in &self.reasons {
                let tag = match r.kind {
                    ReasonKind::Block => "BLOCK",
                    ReasonKind::RequireApproval => "REVIEW",
                    ReasonKind::Info => "INFO",
                };
                s.push_str(&format!("    [{tag}] {}: {}\n", r.rule, r.message));
            }
        }
        let rego = if self.policy.policies.is_empty() {
            "  rego:       (no policies)\n".to_string()
        } else {
            format!(
                "  rego:       {} policy/policies, allowed={}{}\n",
                self.policy.policies.len(),
                self.policy.allowed,
                if self.policy.denies.is_empty() {
                    String::new()
                } else {
                    format!(", denies={}", self.policy.denies.join(" | "))
                }
            )
        };
        s.push_str(&rego);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_block_over_review_over_allow() {
        assert_eq!(decide(&[]), GateDecision::Allow);
        assert_eq!(
            decide(&[GateReason::require_approval("a", "x")]),
            GateDecision::RequireHumanApproval
        );
        assert_eq!(
            decide(&[
                GateReason::require_approval("a", "x"),
                GateReason::block("b", "y"),
            ]),
            GateDecision::Block
        );
    }

    #[test]
    fn reasons_sort_blocks_first() {
        let mut v = [
            GateReason::info("z", "i"),
            GateReason::require_approval("m", "r"),
            GateReason::block("a", "b"),
        ];
        v.sort();
        assert_eq!(v[0].kind, ReasonKind::Block);
        assert_eq!(v[2].kind, ReasonKind::Info);
    }
}
