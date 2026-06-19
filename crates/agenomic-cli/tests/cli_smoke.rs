//! Smoke tests against the built binary.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

#[test]
fn help_works() {
    let output = agenomic().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(predicates::str::contains("Agenomic CLI").eval(&stdout));
    assert!(predicates::str::contains("bucket").eval(&stdout));
}

#[test]
fn init_then_validate_then_build() {
    let d = tempdir().unwrap();
    let bundle = d.path().join("agent");

    let s = agenomic()
        .args([
            "init",
            bundle.to_str().unwrap(),
            "--agent-id",
            "agent://test/x",
        ])
        .output()
        .unwrap();
    assert!(
        s.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&s.stderr)
    );

    let s = agenomic()
        .args(["validate", bundle.to_str().unwrap(), "--level", "strict"])
        .output()
        .unwrap();
    assert!(s.status.success());

    let archive = d.path().join("a.bundle.tar.zst");
    let s = agenomic()
        .args([
            "build",
            bundle.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(s.status.success());

    let s = agenomic()
        .args(["hash", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(s.status.success());
    assert_eq!(s.stdout.iter().filter(|c| **c != b'\n').count(), 64);
}

#[test]
fn validate_invalid_returns_1() {
    let d = tempdir().unwrap();
    // Empty dir → missing required files
    let s = agenomic()
        .args(["validate", d.path().to_str().unwrap(), "--level", "basic"])
        .output()
        .unwrap();
    assert_eq!(s.status.code(), Some(1));
}

#[test]
fn doctor_runs() {
    let s = agenomic().arg("doctor").output().unwrap();
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
}

#[test]
fn completions_bash_emits_script() {
    let s = agenomic().args(["completions", "bash"]).output().unwrap();
    assert!(s.status.success());
    let txt = String::from_utf8_lossy(&s.stdout);
    assert!(txt.contains("_agenomic"));
}

#[test]
fn bundle_compile_runtime_writes_artifacts() {
    let d = tempdir().unwrap();
    let bundle = d.path().join("agent");
    std::fs::create_dir_all(bundle.join("prompts")).unwrap();
    std::fs::write(
        bundle.join("genome.yaml"),
        r#"spec_version: '0.1'
agent:
  id: 'agent://test/runtime'
  name: 'Runtime Test'
  domain: 'general'
  criticality: 'low'
runtime:
  framework: 'langgraph'
  runtime_kind: 'python'
  model_provider: 'anthropic'
  model_id: 'claude-sonnet-4-6'
  entrypoint: 'runtime_test.__main__:main'
tools: []
skills: []
knowledge: []
policies: []
"#,
    )
    .unwrap();
    std::fs::write(bundle.join("agent.lock.yaml"), "spec_version: '0.1'\n").unwrap();
    std::fs::write(
        bundle.join("behavior.contract.yaml"),
        "spec_version: '0.1'\n",
    )
    .unwrap();
    std::fs::write(bundle.join("prompts/system.md"), "system").unwrap();

    let s = agenomic()
        .args(["bundle", "compile-runtime", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        s.status.success(),
        "compile-runtime failed: {}",
        String::from_utf8_lossy(&s.stderr)
    );

    assert!(bundle.join("runtime/plain.compiled").is_file());
    assert!(bundle.join("runtime/langgraph.compiled").is_file());
}

#[test]
fn cloud_login_defaults_to_hosted_endpoint() {
    let d = tempdir().unwrap();

    // No --endpoint: the profile should be saved against the hosted cloud
    // API gateway (api.agenomic.io), not the dashboard origin (app.agenomic.io),
    // which 404s on the `/v1/*` routes the CLI calls.
    let s = agenomic()
        .env("HOME", d.path())
        .env("XDG_CONFIG_HOME", d.path().join("xdg-config"))
        .args(["cloud", "login", "--api-key", "k"])
        .output()
        .unwrap();
    assert!(
        s.status.success(),
        "login failed: {}",
        String::from_utf8_lossy(&s.stderr)
    );
    let stdout = String::from_utf8_lossy(&s.stdout);
    assert!(
        predicates::str::contains("logged in to https://api.agenomic.io").eval(&stdout),
        "unexpected login output: {stdout}"
    );
}
