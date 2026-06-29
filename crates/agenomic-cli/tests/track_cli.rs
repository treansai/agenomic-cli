//! Integration test: `agenomic track` runs an offline tracking session for a
//! sample bundle — start → ingest events → status → report → stop — detecting
//! deterministic drift and mapping a release-blocking alert to exit code 7.

use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

/// Write a minimal but valid bundle (genome + lockfile) under `dir`.
fn scaffold_bundle(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("genome.yaml"),
        "spec_version: '0.1'\n\
         agent:\n  id: 'agent://acme/claims'\n  name: 'Claims'\n  domain: 'insurance'\n  criticality: 'high'\n\
         runtime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\n\
         tools:\n  - name: 'classify_claim'\n    protocol: 'mcp'\n\
         skills: []\nknowledge: []\npolicies: []\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("agent.lock.yaml"),
        "spec_version: '0.1'\nagent_id: 'agent://acme/claims'\n\
         model:\n  provider: 'openai'\n  model_id: 'gpt-4o'\n\
         tools:\n  - name: 'classify_claim'\n    protocol: 'mcp'\nknowledge: []\n",
    )
    .unwrap();
}

fn start_session(bundle: &Path, store: &Path) -> String {
    let out = agenomic()
        .args([
            "--format",
            "json",
            "track",
            "start",
            bundle.to_str().unwrap(),
            "--release",
            "release_123",
            "--env",
            "production",
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agent_id"], "agent://acme/claims");
    assert_eq!(v["release_id"], "release_123");
    v["session_id"].as_str().unwrap().to_string()
}

fn ingest(store: &Path, session: &str, event_json: &str, file: &Path) -> std::process::Output {
    std::fs::write(file, event_json).unwrap();
    agenomic()
        .args([
            "track",
            "event",
            "--session",
            session,
            "--file",
            file.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

#[test]
fn track_offline_session_detects_drift_and_exports_report() {
    let dir = tempdir().unwrap();
    let bundle = dir.path().join("bundle");
    let store = dir.path().join("store");
    scaffold_bundle(&bundle);

    let session = start_session(&bundle, &store);

    // 1. An authorized tool call raises no alert and exits 0.
    let ev = dir.path().join("ev.json");
    let ok = ingest(
        &store,
        &session,
        r#"{"type":"tool.call.completed","tool":{"name":"classify_claim"},"input_hash":"blake3:a"}"#,
        &ev,
    );
    assert!(ok.status.success());

    // 2. An unauthorized tool call raises a critical drift alert → exit 7.
    let bad = ingest(
        &store,
        &session,
        r#"{"type":"tool.call.completed","tool":{"name":"shell.exec"},"input_hash":"blake3:b"}"#,
        &ev,
    );
    assert_eq!(bad.status.code(), Some(7), "blocking alert should exit 7");
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(stdout.contains("tool_permission"), "stdout: {stdout}");

    // 3. Idempotent retry of an event with a fixed id is a no-op.
    let fixed = r#"{"event_id":"FIXED","type":"tool.call.completed","tool":{"name":"classify_claim"},"input_hash":"blake3:c"}"#;
    assert!(ingest(&store, &session, fixed, &ev).status.success());
    let again = ingest(&store, &session, fixed, &ev);
    assert!(String::from_utf8_lossy(&again.stdout).contains("idempotent"));

    // 4. status reflects the recorded alerts.
    let status = agenomic()
        .args([
            "--format",
            "json",
            "track",
            "status",
            "--session",
            &session,
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let s: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(s["summary"]["critical"], 1);

    // 5. report exports JSON and fails (exit 7) because of the critical alert.
    let report_path = dir.path().join("report.json");
    let report = agenomic()
        .args([
            "track",
            "report",
            "--session",
            &session,
            "--output",
            report_path.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(7));
    let r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(r["report_version"], "agenomic.track/v0.1");
    assert_eq!(r["final_status"], "fail");
    assert!(r["report_hash"].as_str().unwrap().starts_with("blake3:"));

    // 6. stop finalizes the session.
    let stop = agenomic()
        .args([
            "--format",
            "json",
            "track",
            "stop",
            "--session",
            &session,
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // exit 7 (still failing) but the session is now terminal.
    assert_eq!(stop.status.code(), Some(7));
    let status2 = agenomic()
        .args([
            "--format",
            "json",
            "track",
            "status",
            "--session",
            &session,
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let s2: serde_json::Value = serde_json::from_slice(&status2.stdout).unwrap();
    assert_eq!(s2["status"], "completed");

    // A stopped session refuses further events (no silent fallback).
    let refused = ingest(
        &store,
        &session,
        r#"{"type":"tool.call.completed","tool":{"name":"classify_claim"}}"#,
        &ev,
    );
    assert!(!refused.status.success());
}
