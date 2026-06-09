//! Integration test: `governance audit --atep` writes a signed, verifiable
//! audit trail onto the ATEP `governance` stream.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

const TRACES: &str = concat!(
    r#"{"trace_id":"t1","agent_id":"agent://acme/x","skill":"classify","signal":"escalation","input_snippet":"refund partial credit"}"#,
    "\n",
    r#"{"trace_id":"t2","agent_id":"agent://acme/x","skill":"classify","signal":"escalation","input_snippet":"refund partial advance"}"#,
    "\n",
    r#"{"trace_id":"t3","agent_id":"agent://acme/x","skill":"classify","signal":"escalation","input_snippet":"partial credit refund"}"#,
    "\n",
);

#[test]
fn audit_emits_signed_governance_trail_that_verifies() {
    let d = tempdir().unwrap();
    let store = d.path().join("store");
    let key = d.path().join("key.pem");
    let traces = d.path().join("traces.jsonl");
    std::fs::write(&traces, TRACES).unwrap();

    // 1. Init the ATEP store + signing key.
    let init = agenomic()
        .args([
            "atep",
            "init",
            store.to_str().unwrap(),
            "--agent-id",
            "agent://acme/x",
            "--signing-key",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // 2. Audit with emission.
    let audit = agenomic()
        .args([
            "governance",
            "audit",
            traces.to_str().unwrap(),
            "--atep",
            store.to_str().unwrap(),
            "--signing-key",
            key.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "audit: {}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    // 1 cluster + 1 proposal + 1 critique + 1 summary = 4 events.
    assert_eq!(v["atep"]["events_appended"], 4);
    assert_eq!(v["atep"]["stream_seq_start"], 0);
    assert_eq!(v["atep"]["stream"], "governance");

    // 3. Verify the signed store: every event signature + merkle root.
    let verify = agenomic()
        .args([
            "atep",
            "verify",
            store.to_str().unwrap(),
            "--public-key",
            key.with_extension("pem.pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(r["valid"], true);
    assert_eq!(r["stream_counts"]["governance"], 4);
    assert_eq!(r["verified_signatures"], 4);
}

#[test]
fn second_audit_continues_the_hash_chain() {
    let d = tempdir().unwrap();
    let store = d.path().join("store");
    let key = d.path().join("key.pem");
    let traces = d.path().join("traces.jsonl");
    std::fs::write(&traces, TRACES).unwrap();
    agenomic()
        .args([
            "atep",
            "init",
            store.to_str().unwrap(),
            "--agent-id",
            "agent://acme/x",
            "--signing-key",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let run = |label: &str| -> serde_json::Value {
        let out = agenomic()
            .args([
                "governance",
                "audit",
                traces.to_str().unwrap(),
                "--atep",
                store.to_str().unwrap(),
                "--signing-key",
                key.to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };

    let first = run("first");
    let second = run("second");
    // The second batch continues stream_seq where the first left off (4 events).
    assert_eq!(first["atep"]["stream_seq_start"], 0);
    assert_eq!(second["atep"]["stream_seq_start"], 4);

    // Store still verifies with 8 governance events total.
    let verify = agenomic()
        .args([
            "atep",
            "verify",
            store.to_str().unwrap(),
            "--public-key",
            key.with_extension("pem.pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let r: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(r["valid"], true);
    assert_eq!(r["stream_counts"]["governance"], 8);
}

#[test]
fn atep_flag_requires_signing_key() {
    let d = tempdir().unwrap();
    let traces = d.path().join("traces.jsonl");
    std::fs::write(&traces, TRACES).unwrap();
    let out = agenomic()
        .args([
            "governance",
            "audit",
            traces.to_str().unwrap(),
            "--atep",
            d.path().join("store").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // --atep without --signing-key is an internal-error usage failure (exit 3).
    assert!(!out.status.success());
}
