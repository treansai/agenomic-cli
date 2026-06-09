//! Evaluate OPA / Rego policies shipped in a bundle's `policies/` directory
//! against an Agenomic launch (or any JSON input).
//!
//! This upgrades policy from the advisory env/allow-list filtering in
//! `agenomic-os` to a real, fail-closed decision engine using the pure-Rust
//! [`regorus`] OPA interpreter — no external `opa` binary, so the offline-first
//! invariant holds.
//!
//! # Policy contract
//!
//! Bundle policies declare `package agenomic` and are evaluated with two
//! conventional rules:
//!
//! - `allow` (boolean) — the permit. **Defaults to `false`** when the rule is
//!   undefined, so a bundle with no usable policy is denied (fail-closed).
//! - `deny[reason]` (set of strings) — human-readable violations.
//!
//! The final decision is:
//!
//! ```text
//! allowed = allow == true  AND  deny is empty
//! ```
//!
//! This supports both idioms:
//! - **Restrictive** policies write `allow { <conditions> }` (base deny) and
//!   need no `deny` rules.
//! - **Permissive-with-exceptions** policies write `default allow := true` and
//!   list violations via `deny[msg]`.
//!
//! ```
//! use agenomic_policy::PolicyBundle;
//! let rego = r#"
//! package agenomic
//! default allow := false
//! allow if input.criticality == "low"
//! deny contains msg if {
//!     input.network_allow_count > 0
//!     msg := "network egress is not permitted"
//! }
//! "#;
//! let bundle = PolicyBundle::from_sources(vec![("inline.rego".into(), rego.into())]);
//! let input = serde_json::json!({ "criticality": "low", "network_allow_count": 0 });
//! let decision = bundle.evaluate(&input).unwrap();
//! assert!(decision.allowed);
//! ```

mod error;

use std::path::Path;

pub use error::{PolicyError, PolicyResult};

/// Conventional package + rule paths queried during evaluation.
const ALLOW_QUERY: &str = "data.agenomic.allow";
const DENY_RULE: &str = "data.agenomic.deny";

/// A set of Rego policy sources, ready to evaluate. Sources are kept sorted by
/// filename so evaluation order (and therefore any error reporting) is
/// deterministic.
#[derive(Debug, Clone, Default)]
pub struct PolicyBundle {
    sources: Vec<(String, String)>,
}

/// The outcome of evaluating a [`PolicyBundle`] against an input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicyDecision {
    /// Final fail-closed verdict: `allow == true && deny.is_empty()`.
    pub allowed: bool,
    /// Deny reasons, sorted and de-duplicated.
    pub denies: Vec<String>,
    /// `true` when the `allow` rule evaluated to `true`.
    pub allow_rule: bool,
    /// Filenames of the policies that were evaluated, sorted.
    pub policies: Vec<String>,
}

impl PolicyBundle {
    /// Build a bundle from in-memory `(filename, rego)` pairs. Filenames are
    /// only used for diagnostics and ordering.
    pub fn from_sources(mut sources: Vec<(String, String)>) -> Self {
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        Self { sources }
    }

    /// Discover and load every `policies/*.rego` file under `bundle_dir`.
    ///
    /// A bundle with no `policies/` directory, or no `.rego` files in it,
    /// yields an empty bundle (see [`PolicyBundle::is_empty`]) — callers decide
    /// whether "no policy" means "skip the gate" (backward compatible) or
    /// "deny".
    pub fn load(bundle_dir: &Path) -> PolicyResult<Self> {
        let dir = bundle_dir.join("policies");
        if !dir.is_dir() {
            return Ok(Self::default());
        }
        let pattern = dir.join("*.rego");
        let pattern = pattern.to_string_lossy();
        let mut sources = Vec::new();
        // glob() only errors on a malformed pattern; our pattern is built from a
        // path so that is effectively impossible, but stay fail-loud anyway.
        let paths =
            glob::glob(&pattern).map_err(|e| PolicyError::Load(format!("glob {pattern}: {e}")))?;
        for entry in paths {
            let path = entry.map_err(|e| PolicyError::Load(format!("glob entry: {e}")))?;
            let text = std::fs::read_to_string(&path).map_err(|e| PolicyError::Io {
                path: path.clone(),
                source: e,
            })?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned());
            sources.push((name, text));
        }
        Ok(Self::from_sources(sources))
    }

    /// `true` when there are no policy sources to evaluate.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Number of loaded policy files.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Names of the loaded policy files, in evaluation order.
    pub fn policy_files(&self) -> Vec<&str> {
        self.sources.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Evaluate the bundle against `input` and return the fail-closed decision.
    ///
    /// An empty bundle returns `allowed = true` (there is nothing to forbid);
    /// the *caller* is responsible for deciding whether a bundle that declares
    /// `.rego` policies but fails to compile should block. A compile or
    /// evaluation error here is surfaced as [`PolicyError`], never silently
    /// allowed.
    pub fn evaluate(&self, input: &serde_json::Value) -> PolicyResult<PolicyDecision> {
        if self.sources.is_empty() {
            return Ok(PolicyDecision {
                allowed: true,
                denies: Vec::new(),
                allow_rule: true,
                policies: Vec::new(),
            });
        }

        let mut engine = regorus::Engine::new();
        for (name, text) in &self.sources {
            engine
                .add_policy(name.clone(), text.clone())
                .map_err(|e| PolicyError::Compile {
                    policy: name.clone(),
                    reason: e.to_string(),
                })?;
        }

        let input_json =
            serde_json::to_string(input).map_err(|e| PolicyError::Input(e.to_string()))?;
        engine
            .set_input_json(&input_json)
            .map_err(|e| PolicyError::Input(e.to_string()))?;

        // `allow` is fail-closed: undefined or non-true → false.
        let allow_rule = engine.eval_allow_query(ALLOW_QUERY.to_string(), false);

        let denies = self.collect_denies(&mut engine)?;

        Ok(PolicyDecision {
            allowed: allow_rule && denies.is_empty(),
            denies,
            allow_rule,
            policies: self.sources.iter().map(|(n, _)| n.clone()).collect(),
        })
    }

    /// Evaluate `data.agenomic.deny` and collect it as a sorted, de-duplicated
    /// list of strings. An undefined rule yields an empty list.
    fn collect_denies(&self, engine: &mut regorus::Engine) -> PolicyResult<Vec<String>> {
        let value = match engine.eval_rule(DENY_RULE.to_string()) {
            Ok(v) => v,
            // An undefined deny rule is not an error: it means "no violations".
            Err(_) => return Ok(Vec::new()),
        };
        let json = serde_json::to_value(&value).map_err(|e| PolicyError::Eval(e.to_string()))?;
        let mut out: Vec<String> = match json {
            // Sets and arrays both serialize to a JSON array.
            serde_json::Value::Array(items) => items
                .into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                })
                .collect(),
            // A bare string deny (unusual but harmless).
            serde_json::Value::String(s) => vec![s],
            // Undefined serializes to null; anything else means "no set".
            _ => Vec::new(),
        };
        out.sort();
        out.dedup();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(rego: &str) -> PolicyBundle {
        PolicyBundle::from_sources(vec![("test.rego".into(), rego.into())])
    }

    #[test]
    fn empty_bundle_allows() {
        let d = PolicyBundle::default()
            .evaluate(&serde_json::json!({}))
            .unwrap();
        assert!(d.allowed);
        assert!(d.policies.is_empty());
    }

    #[test]
    fn undefined_allow_is_fail_closed() {
        // A policy that defines neither allow nor deny → denied.
        let d = bundle("package agenomic\n")
            .evaluate(&serde_json::json!({}))
            .unwrap();
        assert!(!d.allowed);
        assert!(!d.allow_rule);
    }

    #[test]
    fn restrictive_allow_gates_on_condition() {
        let rego = r#"
package agenomic
default allow := false
allow if input.criticality == "low"
"#;
        let b = bundle(rego);
        assert!(
            b.evaluate(&serde_json::json!({"criticality": "low"}))
                .unwrap()
                .allowed
        );
        assert!(
            !b.evaluate(&serde_json::json!({"criticality": "high"}))
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn deny_blocks_even_when_allowed() {
        let rego = r#"
package agenomic
default allow := true
deny contains msg if {
    input.network_allow_count > 0
    msg := sprintf("network egress to %d host(s) is not permitted", [input.network_allow_count])
}
"#;
        let b = bundle(rego);
        let permitted = b
            .evaluate(&serde_json::json!({"network_allow_count": 0}))
            .unwrap();
        assert!(permitted.allowed);
        assert!(permitted.denies.is_empty());

        let blocked = b
            .evaluate(&serde_json::json!({"network_allow_count": 2}))
            .unwrap();
        assert!(!blocked.allowed);
        assert_eq!(blocked.denies.len(), 1);
        assert!(blocked.denies[0].contains("network egress"));
    }

    #[test]
    fn denies_are_sorted_and_deduped() {
        let rego = r#"
package agenomic
default allow := true
deny contains "b-violation"
deny contains "a-violation"
deny contains "a-violation"
"#;
        let d = bundle(rego).evaluate(&serde_json::json!({})).unwrap();
        assert_eq!(d.denies, vec!["a-violation", "b-violation"]);
        assert!(!d.allowed);
    }

    #[test]
    fn malformed_policy_is_an_error_not_an_allow() {
        let d = bundle("package agenomic\nallow if {").evaluate(&serde_json::json!({}));
        assert!(matches!(d, Err(PolicyError::Compile { .. })));
    }

    #[test]
    fn load_from_dir_globs_rego_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("policies")).unwrap();
        std::fs::write(
            dir.path().join("policies/a.rego"),
            "package agenomic\ndefault allow := true\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("policies/notes.md"), "ignore me").unwrap();
        let b = PolicyBundle::load(dir.path()).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b.policy_files(), vec!["a.rego"]);
        assert!(b.evaluate(&serde_json::json!({})).unwrap().allowed);
    }

    #[test]
    fn missing_policies_dir_is_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        assert!(PolicyBundle::load(dir.path()).unwrap().is_empty());
    }
}
