//! Deterministic secret detection and redaction for RMP outputs.
//!
//! Reports, alerts, and evidence must never carry raw tokens. This module
//! provides a conservative, dependency-free scanner: key-name heuristics
//! plus well-known token prefixes. It intentionally over-redacts rather
//! than under-redacts.

use serde::{Deserialize, Serialize};

/// Placeholder written in place of redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Key substrings that mark a JSON field as sensitive.
const SENSITIVE_KEYS: &[&str] = &[
    "api_key", "apikey", "secret", "token", "password", "passwd", "credential",
    "authorization", "auth_header", "private_key", "session_key", "access_key",
];

/// Value prefixes of well-known credential formats.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "agm_", "AKIA",
    "-----BEGIN PRIVATE KEY", "-----BEGIN OPENSSH PRIVATE KEY", "Bearer ",
];

/// Result of scanning a value for secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretScan {
    /// JSON paths (dotted) where secrets were found and redacted.
    pub redacted_paths: Vec<String>,
}

impl SecretScan {
    /// Whether anything was redacted.
    pub fn found_any(&self) -> bool {
        !self.redacted_paths.is_empty()
    }
}

fn key_is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|s| k.contains(s))
}

fn value_is_sensitive(value: &str) -> bool {
    SENSITIVE_VALUE_PREFIXES
        .iter()
        .any(|p| value.starts_with(p))
}

/// Redact a plain string: returns [`REDACTED`] when the value looks like a
/// credential, otherwise the input unchanged.
///
/// ```
/// use agenomic_rmp::redact::{redact_text, REDACTED};
/// assert_eq!(redact_text("sk-abc123"), REDACTED);
/// assert_eq!(redact_text("hello"), "hello");
/// ```
pub fn redact_text(value: &str) -> &str {
    if value_is_sensitive(value) {
        REDACTED
    } else {
        value
    }
}

/// Recursively redact a JSON value in place, returning the scan report.
///
/// ```
/// use agenomic_rmp::redact::redact_json;
/// let mut v = serde_json::json!({"api_key": "abc", "note": "ok"});
/// let scan = redact_json(&mut v);
/// assert!(scan.found_any());
/// assert_eq!(v["api_key"], "[REDACTED]");
/// assert_eq!(v["note"], "ok");
/// ```
pub fn redact_json(value: &mut serde_json::Value) -> SecretScan {
    let mut scan = SecretScan::default();
    walk(value, "$", &mut scan);
    scan
}

fn walk(value: &mut serde_json::Value, path: &str, scan: &mut SecretScan) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let child_path = format!("{path}.{k}");
                if key_is_sensitive(k) {
                    *v = serde_json::Value::String(REDACTED.into());
                    scan.redacted_paths.push(child_path);
                } else {
                    walk(v, &child_path, scan);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter_mut().enumerate() {
                walk(v, &format!("{path}[{i}]"), scan);
            }
        }
        serde_json::Value::String(s) => {
            if value_is_sensitive(s) {
                *s = REDACTED.into();
                scan.redacted_paths.push(path.to_string());
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_nested_and_arrays() {
        let mut v = serde_json::json!({
            "outer": {"password": "hunter2"},
            "list": ["ghp_abcdef", "fine"],
        });
        let scan = redact_json(&mut v);
        assert_eq!(v["outer"]["password"], REDACTED);
        assert_eq!(v["list"][0], REDACTED);
        assert_eq!(v["list"][1], "fine");
        assert_eq!(scan.redacted_paths.len(), 2);
    }

    #[test]
    fn bearer_header_redacted() {
        let mut v = serde_json::json!({"header": "Bearer eyJ..."});
        redact_json(&mut v);
        assert_eq!(v["header"], REDACTED);
    }
}
