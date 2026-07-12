//! Integration test: the `agenomic rmp` / `review` / `monitor` / `protect`
//! command family runs the full continuous safety loop offline —
//! rmp start → monitor events → protect → enrich → review → report →
//! evidence export — with the cryptographic ledger enabled.

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

struct Env {
    bundle: std::path::PathBuf,
    rmp_store: std::path::PathBuf,
    tracking_store: std::path::PathBuf,
    ledger_store: std::path::PathBuf,
    ledger_keys: std::path::PathBuf,
}

impl Env {
    fn store_args(&self) -> Vec<String> {
        vec![
            "--store".into(),
            self.rmp_store.display().to_string(),
            "--tracking-store".into(),
            self.tracking_store.display().to_string(),
        ]
    }
}

fn run_json(args: &[&str]) -> serde_json::Value {
    let out = agenomic()
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "command {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid json from {:?}: {e}\n{}",
            args,
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

#[test]
fn full_rmp_loop_via_cli() {
    let tmp = tempdir().unwrap();
    let env = Env {
        bundle: tmp.path().join("bundle"),
        rmp_store: tmp.path().join("rmp"),
        tracking_store: tmp.path().join("tracking"),
        ledger_store: tmp.path().join("ledger"),
        ledger_keys: tmp.path().join("keys"),
    };
    scaffold_bundle(&env.bundle);

    // ---- ledger init ----------------------------------------------------
    let out = agenomic()
        .args([
            "ledger",
            "init",
            "--store",
            env.ledger_store.to_str().unwrap(),
            "--keys",
            env.ledger_keys.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ---- rmp start (with ledger) -----------------------------------------
    let mut args: Vec<String> = vec![
        "rmp".into(),
        "start".into(),
        env.bundle.display().to_string(),
        "--release".into(),
        "release_123".into(),
        "--env".into(),
        "production".into(),
        "--ledger".into(),
        "--ledger-store".into(),
        env.ledger_store.display().to_string(),
        "--ledger-keys".into(),
        env.ledger_keys.display().to_string(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let session_id = v["session"]["session_id"].as_str().unwrap().to_string();
    let tracking_id = v["session"]["monitor_session_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(session_id.starts_with("rmp_"));

    // ---- monitor: ingest an out-of-baseline tool event --------------------
    let event_file = tmp.path().join("event.json");
    std::fs::write(
        &event_file,
        r#"{"type": "tool.call.completed", "tool": {"name": "shell.exec"}}"#,
    )
    .unwrap();
    let mut args: Vec<String> = vec![
        "monitor".into(),
        "event".into(),
        "--session".into(),
        tracking_id.clone(),
        "--file".into(),
        event_file.display().to_string(),
    ];
    args.extend(env.store_args());
    let out = agenomic()
        .args(["--format", "json"])
        .args(&args)
        .output()
        .unwrap();
    // A critical drift alert blocks the release → exit 7.
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ingested"], true);
    assert!(!v["findings"].as_array().unwrap().is_empty());

    // ---- monitor findings + enrichment proposals --------------------------
    let mut args: Vec<String> = vec![
        "monitor".into(),
        "findings".into(),
        "--session".into(),
        tracking_id.clone(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!v["findings"].as_array().unwrap().is_empty());

    let proposals_file = tmp.path().join("proposals.json");
    let mut args: Vec<String> = vec![
        "monitor".into(),
        "enrich-review".into(),
        "--session".into(),
        tracking_id.clone(),
        "--output".into(),
        proposals_file.display().to_string(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!v["proposals"].as_array().unwrap().is_empty());
    assert!(proposals_file.exists());

    // ---- protect: alerts + recommendations + action plan -------------------
    let mut args: Vec<String> = vec![
        "protect".into(),
        "alerts".into(),
        "--session".into(),
        session_id.clone(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let alerts = v["alerts"].as_array().unwrap();
    assert!(!alerts.is_empty());
    let alert_id = alerts[0]["alert_id"].as_str().unwrap().to_string();
    assert!(alert_id.starts_with("alr_"), "alert id: {alert_id}");

    let mut args: Vec<String> = vec![
        "protect".into(),
        "action-plan".into(),
        "--alert".into(),
        alert_id.clone(),
        "--session".into(),
        session_id.clone(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!v["steps"].as_array().unwrap().is_empty());

    // ---- review (feedback loop closes) -------------------------------------
    let mut args: Vec<String> = vec![
        "rmp".into(),
        "review".into(),
        env.bundle.display().to_string(),
        "--session".into(),
        session_id.clone(),
    ];
    args.extend(env.store_args());
    let out = agenomic()
        .args(["--format", "json"])
        .args(&args)
        .output()
        .unwrap();
    // Carried critical monitor findings do not fail review by themselves,
    // but the command must succeed either way.
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ---- unified report with ledger proof ---------------------------------
    let report_file = tmp.path().join("rmp-report.json");
    let mut args: Vec<String> = vec![
        "rmp".into(),
        "report".into(),
        "--session".into(),
        session_id.clone(),
        "--output".into(),
        report_file.display().to_string(),
        "--include-ledger-proof".into(),
    ];
    args.extend(env.store_args());
    let out = agenomic()
        .args(["--format", "json"])
        .args(&args)
        .output()
        .unwrap();
    // Critical production findings → Block → exit 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_file).unwrap()).unwrap();
    assert_eq!(report["release_recommendation"], "block");
    assert_eq!(report["verification_status"], "verified");
    assert!(report["report_hash"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    assert!(report["ledger_proof"]["verification_passed"]
        .as_bool()
        .unwrap());

    // ---- evidence export ----------------------------------------------------
    let evidence_dir = tmp.path().join("evidence");
    let mut args: Vec<String> = vec![
        "rmp".into(),
        "export-evidence".into(),
        "--session".into(),
        session_id.clone(),
        "--output".into(),
        evidence_dir.display().to_string(),
        "--include-ledger".into(),
    ];
    args.extend(env.store_args());
    let v = run_json(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(v["files"].as_array().unwrap().len() >= 3);
    assert!(evidence_dir.join("rmp_report.json").exists());
    assert!(evidence_dir.join("manifest.json").exists());
    assert!(evidence_dir.join("ledger_proof.json").exists());

    // ---- ledger contains RMP events and verifies ----------------------------
    let out = agenomic()
        .args([
            "--format",
            "json",
            "ledger",
            "verify",
            "--store",
            env.ledger_store.to_str().unwrap(),
            "--keys",
            env.ledger_keys.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn review_scenarios_and_risk_matrix() {
    let tmp = tempdir().unwrap();
    let bundle = tmp.path().join("bundle");
    scaffold_bundle(&bundle);

    // Init the risk matrix.
    let v = run_json(&["review", "risk-matrix", bundle.to_str().unwrap()]);
    assert_eq!(v["agent_id"], "agent://acme/claims");

    // Add a scenario to the corpus.
    let scenario_file = tmp.path().join("scenario.json");
    std::fs::write(
        &scenario_file,
        serde_json::json!({
            "spec_version": "agenomic.rmp.scenario/v0.1",
            "scenario_id": "sc_payment_risk",
            "title": "Payment above threshold requires approval",
            "source": "manual",
            "agent_id": "agent://acme/claims",
            "severity": "high",
            "created_at": "2026-07-12T00:00:00Z",
            "expected_tool_calls": ["classify_claim"],
            "forbidden_behaviors": ["final_decision_without_approval"]
        })
        .to_string(),
    )
    .unwrap();
    let v = run_json(&[
        "review",
        "scenarios",
        "add",
        bundle.to_str().unwrap(),
        "--file",
        scenario_file.to_str().unwrap(),
    ]);
    assert_eq!(v["scenarios"][0]["scenario_id"], "sc_payment_risk");

    let v = run_json(&["review", "scenarios", "list", bundle.to_str().unwrap()]);
    assert_eq!(v["scenarios"].as_array().unwrap().len(), 1);

    // Run a review: the corpus scenario is picked up.
    let v = run_json(&["review", "run", bundle.to_str().unwrap()]);
    assert_eq!(v["coverage"]["total_scenarios"], 1);
    assert_eq!(v["result"], "pass");
}

#[test]
fn enrich_scenarios_from_findings_file() {
    let tmp = tempdir().unwrap();
    let findings_file = tmp.path().join("findings.json");
    std::fs::write(
        &findings_file,
        serde_json::json!([{
            "spec_version": "agenomic.rmp/v0.1",
            "finding_id": "fnd_x",
            "loop_stage": "monitor",
            "session_id": "mon_x",
            "agent_id": "agent://acme/claims",
            "kind": "loop",
            "severity": "high",
            "title": "Tool loop on claims_db.lookup",
            "message": "12 identical calls",
            "created_at": "2026-07-12T00:00:00Z",
            "blocks_release": false,
            "requires_human_review": true
        }])
        .to_string(),
    )
    .unwrap();
    let out_file = tmp.path().join("proposals.json");
    let v = run_json(&[
        "rmp",
        "enrich-scenarios",
        "--from-findings",
        findings_file.to_str().unwrap(),
        "--output",
        out_file.to_str().unwrap(),
    ]);
    let proposals = v["proposals"].as_array().unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0]["human_approval_required"], true);
    assert_eq!(
        proposals[0]["proposed_scenario"]["source"],
        "monitor_derived"
    );
    assert!(out_file.exists());
}
