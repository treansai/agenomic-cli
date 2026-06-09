//! Integration tests for the `compile` and `policy` commands against the
//! built binary.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

/// Minimal spec-0.2 bundle with an execution block and one skill, written to a
/// fresh temp dir. Returns the bundle path's parent tempdir (keep it alive).
fn fixture() -> tempfile::TempDir {
    let d = tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("prompts/skills")).unwrap();
    std::fs::create_dir_all(d.path().join("policies")).unwrap();
    std::fs::write(
        d.path().join("genome.yaml"),
        r#"spec_version: '0.2'
agent:
  id: 'agent://test/claims'
  name: 'Claims'
  domain: 'insurance'
  criticality: 'high'
runtime:
  model_provider: 'openai'
  model_id: 'gpt-4o'
  temperature: 0.0
tools: []
skills:
  - name: 'classify'
    prompt: 'prompts/skills/classify.md'
knowledge: []
policies: []
execution:
  entrypoint:
    kind: command
    command: /bin/echo
    args: ["ran"]
  runtime:
    kind: binary
  permissions:
    network:
      allow: []
"#,
    )
    .unwrap();
    std::fs::write(d.path().join("prompts/system.md"), "You triage claims.").unwrap();
    std::fs::write(d.path().join("prompts/skills/classify.md"), "Classify it.").unwrap();
    d
}

#[test]
fn compile_all_targets_writes_runtime_tree() {
    let d = fixture();
    let out = agenomic()
        .args(["compile", d.path().to_str().unwrap(), "--all"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for (target, entry) in [
        ("plain.compiled", "agent.py"),
        ("langgraph.compiled", "graph.py"),
        ("crewai.compiled", "crew.py"),
    ] {
        let dir = d.path().join("runtime").join(target);
        assert!(dir.join(entry).is_file(), "missing {target}/{entry}");
        assert!(
            dir.join("manifest.json").is_file(),
            "missing {target}/manifest.json"
        );
        assert!(
            dir.join("prompts/system.md").is_file(),
            "missing embedded prompt for {target}"
        );
    }
}

#[test]
fn compile_dry_run_writes_nothing() {
    let d = fixture();
    let out = agenomic()
        .args([
            "compile",
            d.path().to_str().unwrap(),
            "--target",
            "plain",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !d.path().join("runtime").exists(),
        "--dry-run must not write the runtime tree"
    );
}

#[test]
fn policy_eval_allows_then_denies() {
    let d = fixture();
    // Restrictive policy: deny any declared network egress.
    std::fs::write(
        d.path().join("policies/launch.rego"),
        r#"package agenomic
default allow := false
allow if { count(object.get(input, "network_allow", [])) == 0 }
deny contains "network egress not permitted" if {
    count(object.get(input, "network_allow", [])) > 0
}
"#,
    )
    .unwrap();

    // Derived context has empty network allow → allowed (exit 0).
    let allowed = agenomic()
        .args(["policy", "eval", d.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "expected allow, got: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    // Explicit denying input → exit code 16 (OsPolicyViolation).
    let input = d.path().join("deny.json");
    std::fs::write(&input, r#"{"network_allow":["x"],"network_allow_count":1}"#).unwrap();
    let denied = agenomic()
        .args([
            "policy",
            "eval",
            d.path().to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(16), "deny must exit 16");
}

#[test]
fn run_is_gated_by_rego_policy_before_spawn() {
    let d = fixture();
    // Make the genome declare network egress so the deny rule fires.
    let genome = std::fs::read_to_string(d.path().join("genome.yaml"))
        .unwrap()
        .replace("      allow: []", "      allow: [\"api.example.com\"]");
    std::fs::write(d.path().join("genome.yaml"), genome).unwrap();
    std::fs::write(
        d.path().join("policies/launch.rego"),
        r#"package agenomic
default allow := false
deny contains "no egress" if { count(object.get(input, "network_allow", [])) > 0 }
"#,
    )
    .unwrap();

    let out = agenomic()
        .args([
            "run",
            "agent://test/claims",
            "--bundle-path",
            d.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(16), "gated run must exit 16");
    // The entrypoint (/bin/echo "ran") must NOT have executed.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("ran"),
        "entrypoint ran despite policy denial"
    );
}
