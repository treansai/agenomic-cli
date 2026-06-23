//! The deterministic rule set the gate enforces.
//!
//! These are **non-negotiable invariants** evaluated in pure Rust, entirely
//! outside the LLM. The defaults are safe out of the box; an operator can
//! extend them with a `gate.json` next to the Rego `policies/` directory, but
//! they can never be weakened below the built-in floor at runtime by untrusted
//! input.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The configurable surface of the gate. Every field has a safe default; the
/// `#[serde(default)]` on each means a partial `gate.json` only overrides what
/// it names and inherits the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRuleSet {
    /// When non-empty, **only** these tools may run (fail-closed allowlist).
    #[serde(default)]
    pub allowed_tools: BTreeSet<String>,
    /// Per-tool permitted scopes. A requested scope outside the listed set is a
    /// hard block. Tools absent from the map are unconstrained on scope.
    #[serde(default)]
    pub allowed_scopes: BTreeMap<String, BTreeSet<String>>,
    /// Tools whose effects cannot be undone — require human approval first.
    #[serde(default = "default_irreversible")]
    pub irreversible_tools: BTreeSet<String>,
    /// Tools that send data to an external recipient (egress surface).
    #[serde(default = "default_external_sinks")]
    pub external_sink_tools: BTreeSet<String>,
    /// Tools that, by name, mutate the agent's own instructions/policy.
    #[serde(default = "default_self_mutation")]
    pub self_mutation_tools: BTreeSet<String>,
    /// Tools that write to the filesystem or execute commands. Their path
    /// arguments are checked against [`GateRuleSet::protected_paths`] and for
    /// traversal.
    #[serde(default = "default_effectful_write")]
    pub effectful_write_tools: BTreeSet<String>,
    /// Recipients (addresses / domains / hosts) approved for egress.
    #[serde(default)]
    pub approved_recipients: BTreeSet<String>,
    /// Path fragments that may never be written or modified (substring match).
    #[serde(default = "default_protected_paths")]
    pub protected_paths: Vec<String>,
}

impl Default for GateRuleSet {
    fn default() -> Self {
        Self {
            allowed_tools: BTreeSet::new(),
            allowed_scopes: BTreeMap::new(),
            irreversible_tools: default_irreversible(),
            external_sink_tools: default_external_sinks(),
            self_mutation_tools: default_self_mutation(),
            effectful_write_tools: default_effectful_write(),
            approved_recipients: BTreeSet::new(),
            protected_paths: default_protected_paths(),
        }
    }
}

impl GateRuleSet {
    /// Parse a rule set from JSON, inheriting defaults for any omitted field.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// `true` when an allowlist is in force.
    pub fn has_allowlist(&self) -> bool {
        !self.allowed_tools.is_empty()
    }
}

fn default_irreversible() -> BTreeSet<String> {
    set(&[
        "delete_record",
        "delete_file",
        "delete_user",
        "drop_table",
        "db.delete",
        "db.drop",
        "deploy",
        "publish",
        "publish_release",
        "send_payment",
        "transfer_funds",
        "wire_transfer",
        "issue_refund",
        "rm",
        "rmrf",
        "destroy",
        "terminate_instance",
        "revoke_access",
        "rotate_keys",
    ])
}

fn default_external_sinks() -> BTreeSet<String> {
    set(&[
        "send_email",
        "email.send",
        "http_post",
        "http.post",
        "http_request",
        "http.request",
        "webhook",
        "post_message",
        "upload",
        "upload_file",
        "fetch_url",
        "curl",
        "slack.post",
        "sms.send",
        "publish_message",
        "dns_lookup",
    ])
}

fn default_self_mutation() -> BTreeSet<String> {
    set(&[
        "set_system_prompt",
        "update_system_prompt",
        "modify_prompt",
        "update_instructions",
        "write_genome",
        "edit_policy",
        "update_policy",
        "self_update",
        "patch_self",
        "rewrite_instructions",
    ])
}

fn default_effectful_write() -> BTreeSet<String> {
    set(&[
        "fs.write",
        "file.write",
        "write_file",
        "edit_file",
        "edit",
        "shell",
        "exec",
        "bash",
        "run_command",
        "apply_patch",
        "fs.append",
        "fs.move",
    ])
}

fn default_protected_paths() -> Vec<String> {
    [
        "genome.yaml",
        "system_prompt",
        "system-prompt",
        "/policies/",
        "\\policies\\",
        ".rego",
        ".agenomic/",
        "gate.json",
        "gate.toml",
        ".env",
        ".pem",
        ".key",
        "id_rsa",
        "id_ed25519",
        ".ssh/",
        "/etc/passwd",
        "/etc/shadow",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_populated() {
        let r = GateRuleSet::default();
        assert!(r.irreversible_tools.contains("delete_record"));
        assert!(r.external_sink_tools.contains("send_email"));
        assert!(r.self_mutation_tools.contains("set_system_prompt"));
        assert!(!r.has_allowlist());
    }

    #[test]
    fn partial_json_inherits_defaults() {
        // Override only the allowlist; the irreversible defaults must survive.
        let r = GateRuleSet::from_json(r#"{ "allowed_tools": ["read_file"] }"#).unwrap();
        assert!(r.has_allowlist());
        assert!(r.allowed_tools.contains("read_file"));
        assert!(r.irreversible_tools.contains("delete_record"));
    }
}
