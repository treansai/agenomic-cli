//! The unit the gate inspects: a *proposed* tool call, intercepted at the
//! boundary **before any effect**.
//!
//! A tool call carries its arguments plus the one thing the gate treats as
//! load-bearing: the **provenance** of those arguments. Anything derived from
//! model output, tool output, an MCP server response, or a skill file is
//! [`Provenance::Untrusted`] and is held to stricter rules — the gate never
//! "trusts" text the LLM produced.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Where a tool call's arguments came from.
///
/// The gate's whole premise is that defenses must not depend on the LLM, so
/// the **default is [`Provenance::Untrusted`]**: a call with no explicit
/// provenance is assumed to be attacker-influenced until proven otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Originated from the operator or trusted local configuration.
    Trusted,
    /// Derived from model output, tool/MCP output, or a skill file. Never
    /// trusted by the gate — and the default, so a call with no stated
    /// provenance is assumed attacker-influenced.
    #[default]
    Untrusted,
}

impl Provenance {
    /// Stable lowercase label.
    pub fn label(self) -> &'static str {
        match self {
            Provenance::Trusted => "trusted",
            Provenance::Untrusted => "untrusted",
        }
    }
}

/// A reviewer's signed-off decision, attached on resume after the gate raised
/// [`crate::GateDecision::RequireHumanApproval`].
///
/// The `role`, `justification` and `timestamp` are mandatory and travel into
/// the signed `human.review.*` ATEP event so the interruption is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanApproval {
    pub disposition: Disposition,
    /// The reviewer's role (e.g. `"oncall-sre"`, `"compliance"`).
    pub role: String,
    /// Why the reviewer reached this decision.
    pub justification: String,
    /// RFC3339 timestamp of the decision.
    pub timestamp: String,
}

/// The three ways a human can resolve a held tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Approved,
    Rejected,
    Modified,
}

impl HumanApproval {
    /// `true` when the reviewer approved the held call.
    pub fn is_approved(&self) -> bool {
        self.disposition == Disposition::Approved
    }
}

/// A proposed tool call intercepted at the boundary, before any effect.
///
/// ```
/// use agenomic_gate::{ToolCall, Provenance};
/// let call: ToolCall = serde_json::from_value(serde_json::json!({
///     "tool": "send_email",
///     "provenance": "untrusted",
///     "arguments": { "to": "x@example.com", "body": "hi" }
/// })).unwrap();
/// assert_eq!(call.tool, "send_email");
/// assert_eq!(call.provenance, Provenance::Untrusted);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// The tool/function being invoked (e.g. `"send_email"`, `"fs.write"`).
    pub tool: String,
    /// Structured arguments. Never logged in the clear by the gate — only its
    /// content-addressed hash is emitted.
    #[serde(default)]
    pub arguments: serde_json::Value,
    /// Provenance of the arguments. Defaults to [`Provenance::Untrusted`].
    #[serde(default)]
    pub provenance: Provenance,
    /// Capabilities/scopes the call requests.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Explicit egress destinations when they are not inferable from
    /// `arguments` (recipients / URLs / hosts).
    #[serde(default)]
    pub destinations: Vec<String>,
    /// A reviewer's signed approval, present only on resume.
    #[serde(default)]
    pub human_approval: Option<HumanApproval>,
}

/// Argument keys whose string values are treated as egress destinations.
const DEST_KEYS: &[&str] = &[
    "to",
    "recipient",
    "recipients",
    "url",
    "endpoint",
    "host",
    "hostname",
    "webhook",
    "dest",
    "destination",
    "target_url",
    "email",
    "address",
];

impl ToolCall {
    /// `true` when the call carries an approved [`HumanApproval`].
    pub fn is_approved(&self) -> bool {
        self.human_approval
            .as_ref()
            .is_some_and(HumanApproval::is_approved)
    }

    /// Every egress destination this call would reach: the explicit
    /// [`ToolCall::destinations`] plus any string value found under a
    /// recipient/URL/host argument key. Sorted and de-duplicated for
    /// determinism.
    pub fn resolved_destinations(&self) -> Vec<String> {
        let mut out: BTreeSet<String> = self.destinations.iter().cloned().collect();
        collect_by_keys(&self.arguments, DEST_KEYS, &mut out);
        out.into_iter().collect()
    }
}

/// Recursively collect string values (and string array elements) stored under
/// any of `keys` anywhere in `value`.
fn collect_by_keys(value: &serde_json::Value, keys: &[&str], out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if keys.contains(&k.as_str()) {
                    push_strings(v, out);
                }
                collect_by_keys(v, keys, out);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_by_keys(v, keys, out);
            }
        }
        _ => {}
    }
}

/// Push `v` if it is a string, or each string element if it is an array.
fn push_strings(v: &serde_json::Value, out: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
        }
        serde_json::Value::Array(items) => {
            for it in items {
                if let serde_json::Value::String(s) = it {
                    out.insert(s.clone());
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provenance_is_untrusted() {
        let call: ToolCall = serde_json::from_value(serde_json::json!({ "tool": "x" })).unwrap();
        assert_eq!(call.provenance, Provenance::Untrusted);
    }

    #[test]
    fn destinations_are_inferred_from_args() {
        let call: ToolCall = serde_json::from_value(serde_json::json!({
            "tool": "send_email",
            "arguments": { "to": "a@b.com", "cc": ["c@d.com"], "subject": "hi" },
            "destinations": ["explicit@e.com"],
        }))
        .unwrap();
        let dests = call.resolved_destinations();
        assert!(dests.contains(&"a@b.com".to_string()));
        assert!(dests.contains(&"explicit@e.com".to_string()));
        // "cc" is not a destination key, so it is not collected as one.
        assert!(!dests.contains(&"c@d.com".to_string()));
    }
}
