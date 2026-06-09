//! Fixture-based tests for the three validation levels.

use std::path::PathBuf;

use agenomic_core::{Severity, ValidationLevel};
use agenomic_validate::{
    validate_bundle, validate_manifest_file, validate_system, validate_workflow,
};

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
        .any(|e| e.code == "agenomic::bundle::missing_required_file"));
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
    assert!(r.warnings.iter().any(|w| w
        .code
        .starts_with("agenomic::xref::tool_in_genome_not_locked")));
}

#[test]
fn secret_in_tree_fails_ci() {
    let r = validate_bundle(&fix("invalid-secret-in-tree"), ValidationLevel::Ci).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.severity >= Severity::High && e.code.starts_with("agenomic::security::")));
}

#[test]
fn missing_fingerprint_passes_strict_fails_ci() {
    let strict =
        validate_bundle(&fix("invalid-missing-fingerprint"), ValidationLevel::Strict).unwrap();
    assert!(strict.valid, "expected valid at strict, got {strict:?}");
    let ci = validate_bundle(&fix("invalid-missing-fingerprint"), ValidationLevel::Ci).unwrap();
    assert!(!ci.valid);
    assert!(ci
        .errors
        .iter()
        .any(|e| e.code == "agenomic::ci::missing_model_fingerprint"));
}

#[test]
fn valid_system_bundle_passes_all_levels() {
    for lvl in [
        ValidationLevel::Basic,
        ValidationLevel::Strict,
        ValidationLevel::Ci,
    ] {
        let r = validate_bundle(&fix("valid-system-bundle"), lvl).unwrap();
        assert!(
            r.valid,
            "level {lvl:?}: not valid: errors={:?} warnings={:?}",
            r.errors, r.warnings
        );
    }
}

#[test]
fn system_bundle_unknown_role_fails_strict() {
    let basic =
        validate_bundle(&fix("invalid-system-unknown-role"), ValidationLevel::Basic).unwrap();
    assert!(basic.valid, "basic only parses YAML, got {basic:?}");
    let strict =
        validate_bundle(&fix("invalid-system-unknown-role"), ValidationLevel::Strict).unwrap();
    assert!(!strict.valid);
    assert!(strict
        .errors
        .iter()
        .any(|e| e.code == "agenomic::system::unknown_role"));
}

#[test]
fn workflow_unknown_dependency_fails() {
    let yaml = r#"
spec_version: '0.2'
workflow:
  id: 'workflow://acme/flow'
  name: 'Flow'
steps:
  - id: a
    type: agent
    agent: 'agent://acme/foo'
  - id: b
    type: agent
    agent: 'agent://acme/foo'
    depends_on: [ghost]
"#;
    let r = validate_workflow(yaml).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.code == "agenomic::workflow::unknown_dependency"));
}

#[test]
fn workflow_duplicate_step_id_fails() {
    let yaml = r#"
spec_version: '0.2'
workflow:
  id: 'workflow://acme/flow'
  name: 'Flow'
steps:
  - id: a
    type: agent
    agent: 'agent://acme/foo'
  - id: a
    type: tool
    tool: { name: rules }
"#;
    let r = validate_workflow(yaml).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.code == "agenomic::workflow::duplicate_step_id"));
}

#[test]
fn standalone_manifest_files_validate_by_kind() {
    let wf = validate_manifest_file(&fix("valid-system-bundle/workflows/lifecycle.yaml")).unwrap();
    assert!(wf.valid, "workflow manifest: {wf:?}");
    let sys = validate_manifest_file(&fix("valid-system-bundle/system.yaml")).unwrap();
    assert!(sys.valid, "system manifest: {sys:?}");
    let genome = validate_manifest_file(&fix("valid-bundle/genome.yaml")).unwrap();
    assert!(genome.valid, "genome manifest: {genome:?}");
}

#[test]
fn system_duplicate_role_fails() {
    let yaml = r#"
spec_version: '0.2'
system:
  id: 'system://acme/orchestra'
  name: 'Orchestra'
agents:
  - role: intake
    id: 'agent://acme/a'
  - role: intake
    id: 'agent://acme/b'
orchestration:
  style: pipeline
"#;
    let r = validate_system(yaml).unwrap();
    assert!(!r.valid);
    assert!(r
        .errors
        .iter()
        .any(|e| e.code == "agenomic::system::duplicate_role"));
}
