//! Fixture-based tests for the three validation levels.

use std::path::PathBuf;

use agentlock_core::{Severity, ValidationLevel};
use agentlock_validate::validate_bundle;

fn fix(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn valid_bundle_passes_all_levels() {
    for lvl in [
        ValidationLevel::Basic,
        ValidationLevel::Strict,
        ValidationLevel::Ci,
    ] {
        let r = validate_bundle(&fix("valid-bundle"), lvl).unwrap();
        assert!(
            r.valid,
            "level {lvl:?}: not valid: errors={:?} warnings={:?}",
            r.errors, r.warnings
        );
    }
}

#[test]
fn missing_genome_fails_basic() {
    let r = validate_bundle(&fix("invalid-missing-genome"), ValidationLevel::Basic).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.code == "agentlock::bundle::missing_required_file"));
}

#[test]
fn bad_lockfile_fails_strict() {
    let r = validate_bundle(&fix("invalid-bad-lockfile"), ValidationLevel::Strict).unwrap();
    assert!(!r.valid);
}

#[test]
fn tool_mismatch_warns_at_strict() {
    let r = validate_bundle(&fix("invalid-tool-mismatch"), ValidationLevel::Strict).unwrap();
    // Warnings should include tool xref. Strict does not turn them into errors.
    assert!(r
        .warnings
        .iter()
        .any(|w| w.code.starts_with("agentlock::xref::tool_in_genome_not_locked")));
}

#[test]
fn secret_in_tree_fails_ci() {
    let r = validate_bundle(&fix("invalid-secret-in-tree"), ValidationLevel::Ci).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.severity >= Severity::High && e.code.starts_with("agentlock::security::")));
}

#[test]
fn missing_fingerprint_passes_strict_fails_ci() {
    let strict = validate_bundle(&fix("invalid-missing-fingerprint"), ValidationLevel::Strict)
        .unwrap();
    assert!(strict.valid, "expected valid at strict, got {strict:?}");
    let ci = validate_bundle(&fix("invalid-missing-fingerprint"), ValidationLevel::Ci).unwrap();
    assert!(!ci.valid);
    assert!(ci
        .errors
        .iter()
        .any(|e| e.code == "agentlock::ci::missing_model_fingerprint"));
}
