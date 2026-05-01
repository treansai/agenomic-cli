//! Smoke tests against the built binary.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use tempfile::tempdir;

fn agentlock() -> Command {
    Command::cargo_bin("agentlock").expect("binary built")
}

#[test]
fn help_works() {
    let output = agentlock().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(
        predicates::str::contains("AgentLock CLI").eval(&String::from_utf8_lossy(&output.stdout))
    );
}

#[test]
fn init_then_validate_then_build() {
    let d = tempdir().unwrap();
    let bundle = d.path().join("agent");

    let s = agentlock()
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

    let s = agentlock()
        .args(["validate", bundle.to_str().unwrap(), "--level", "strict"])
        .output()
        .unwrap();
    assert!(s.status.success());

    let archive = d.path().join("a.bundle.tar.zst");
    let s = agentlock()
        .args([
            "build",
            bundle.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(s.status.success());

    let s = agentlock()
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
    let s = agentlock()
        .args(["validate", d.path().to_str().unwrap(), "--level", "basic"])
        .output()
        .unwrap();
    assert_eq!(s.status.code(), Some(1));
}

#[test]
fn doctor_runs() {
    let s = agentlock().arg("doctor").output().unwrap();
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
}

#[test]
fn completions_bash_emits_script() {
    let s = agentlock().args(["completions", "bash"]).output().unwrap();
    assert!(s.status.success());
    let txt = String::from_utf8_lossy(&s.stdout);
    assert!(txt.contains("_agentlock"));
}
