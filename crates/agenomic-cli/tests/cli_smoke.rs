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
