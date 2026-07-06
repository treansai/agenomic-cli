//! Phase 5 integration scenarios: tracking → ledger, governance dual-emit,
//! replay --from-ledger with mandatory pre-verification, and evidence
//! export/verify (offline, exit 19 on tamper).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn workspace_example(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(rel)
        .canonicalize()
        .unwrap()
}

struct Env {
    root: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }
    fn ledger_flags(&self) -> [String; 4] {
        [
            "--ledger-store".into(),
            self.path("ledger").display().to_string(),
            "--ledger-keys".into(),
            self.path("keys").display().to_string(),
        ]
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::cargo_bin("agenomic").unwrap();
        c.current_dir(self.root.path());
        c.args(args);
        c
    }
}

fn write_json(path: &Path, v: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string(v).unwrap()).unwrap();
}

/// Start a ledger-bound tracking session and return its id.
fn start_session(env: &Env) -> String {
    let out = env
        .cmd(&[
            "track",
            "start",
            "--agent",
            "agent://acme/support",
            "--store",
            env.path("tracking").to_str().unwrap(),
            "--ledger",
            "--format",
            "json",
        ])
        .args(env.ledger_flags())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    v["session_id"].as_str().unwrap().to_string()
}

#[test]
fn tracking_session_events_land_in_the_ledger_with_proof() {
    let env = Env::new();
    let session = start_session(&env);

    // Ingest two events; each must land in the ledger too.
    for (n, ty) in [(0u64, "model.call.started"), (1, "model.call.completed")] {
        let event = env.path(&format!("ev{n}.json"));
        write_json(
            &event,
            &serde_json::json!({ "type": ty, "sequence_number": n }),
        );
        env.cmd(&[
            "track",
            "event",
            "--session",
            &session,
            "--file",
            event.to_str().unwrap(),
            "--store",
            env.path("tracking").to_str().unwrap(),
        ])
        .assert()
        .success();
    }

    // The ledger holds session-started + 2 events under run = session id.
    env.cmd(&[
        "ledger",
        "verify",
        "--run",
        &session,
        "--store",
        env.path("ledger").to_str().unwrap(),
        "--keys",
        env.path("keys").to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("PASSED").and(predicate::str::contains("entries: 3")));

    // Report with the ledger proof attached; the proof names this run and
    // the hash covers it.
    let out = env
        .cmd(&[
            "track",
            "report",
            "--session",
            &session,
            "--include-ledger-proof",
            "--store",
            env.path("tracking").to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let proof = &report["ledger_proof"];
    assert_eq!(proof["run_id"], session);
    assert_eq!(proof["run_entry_count"], 3);
    assert_eq!(proof["verification_passed"], true);
    assert_eq!(proof["dead_lettered"], 0);
    assert!(proof["ledger_head_hash"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    assert!(report["report_hash"].as_str().is_some());

    // Stop appends the completion event to the ledger.
    env.cmd(&[
        "track",
        "stop",
        "--session",
        &session,
        "--store",
        env.path("tracking").to_str().unwrap(),
    ])
    .assert()
    .success();
    env.cmd(&[
        "ledger",
        "tail",
        "--run",
        &session,
        "--store",
        env.path("ledger").to_str().unwrap(),
        "--keys",
        env.path("keys").to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(
        predicate::str::contains("tracking.session.started")
            .and(predicate::str::contains("tracking.session.completed")),
    );
}

#[test]
fn report_without_ledger_binding_refuses_proof() {
    let env = Env::new();
    // Session WITHOUT --ledger.
    let out = env
        .cmd(&[
            "track",
            "start",
            "--agent",
            "agent://acme/support",
            "--store",
            env.path("tracking").to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let session = v["session_id"].as_str().unwrap();

    env.cmd(&[
        "track",
        "report",
        "--session",
        session,
        "--include-ledger-proof",
        "--store",
        env.path("tracking").to_str().unwrap(),
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("not ledger-bound"));
}

#[test]
fn governance_dual_emits_to_atep_and_ledger() {
    let env = Env::new();
    let traces = workspace_example("claims-agent/governance/flagged-traces.jsonl");

    // ATEP store + signing key for the existing trail.
    let atep = env.path("atep");
    let key = env.path("gov-key.pem");
    env.cmd(&[
        "atep",
        "init",
        atep.to_str().unwrap(),
        "--agent-id",
        "agent://acme/claims",
        "--signing-key",
        key.to_str().unwrap(),
    ])
    .assert()
    .success();

    let out = env
        .cmd(&[
            "governance",
            "cluster",
            traces.to_str().unwrap(),
            "--atep",
            atep.to_str().unwrap(),
            "--signing-key",
            key.to_str().unwrap(),
            "--ledger",
            "--format",
            "json",
        ])
        .args(env.ledger_flags())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let emitted = v["atep"]["ledger_events_appended"].as_u64().unwrap();
    assert!(emitted > 0, "ledger events appended: {v}");
    assert_eq!(v["atep"]["events_appended"].as_u64().unwrap(), emitted);

    // The governance run verifies on the ledger.
    env.cmd(&[
        "ledger",
        "verify",
        "--run",
        "governance",
        "--store",
        env.path("ledger").to_str().unwrap(),
        "--keys",
        env.path("keys").to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("PASSED"));

    // And the ATEP trail still verifies (dual-emit, not replacement).
    env.cmd(&[
        "atep",
        "verify",
        atep.to_str().unwrap(),
        "--public-key",
        &format!("{}.pub", key.display()),
    ])
    .assert()
    .success();
}

#[test]
fn replay_from_ledger_verifies_first_and_attaches_proof() {
    let env = Env::new();
    let bundle = workspace_example("claims-agent");
    let traces = workspace_example("claims-agent/traces/synthetic_claim_traces.jsonl");

    // A verified ledger run to anchor the replay.
    env.cmd(&["ledger", "init"])
        .args([
            "--store",
            env.path("ledger").to_str().unwrap(),
            "--keys",
            env.path("keys").to_str().unwrap(),
        ])
        .assert()
        .success();
    let event = env.path("e.json");
    write_json(
        &event,
        &serde_json::json!({
            "agent_id": "agent://acme/claims",
            "run_id": "sess-replay",
            "event_type": "agent.started",
            "payload": { "n": 1 },
        }),
    );
    env.cmd(&["ledger", "append", "--event", event.to_str().unwrap()])
        .args([
            "--store",
            env.path("ledger").to_str().unwrap(),
            "--keys",
            env.path("keys").to_str().unwrap(),
        ])
        .assert()
        .success();

    let report_path = env.path("replay.json");
    env.cmd(&[
        "replay",
        bundle.to_str().unwrap(),
        traces.to_str().unwrap(),
        "--from-ledger",
        "sess-replay",
        "--output",
        report_path.to_str().unwrap(),
    ])
    .args(env.ledger_flags())
    .assert()
    .success();

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    // Statistical framing intact; ledger proof attached.
    assert_eq!(report["mode"], "deterministic_offline");
    let proof = &report["ledger_proof"];
    assert_eq!(proof["run_id"], "sess-replay");
    assert_eq!(proof["verification_passed"], true);
    assert_eq!(proof["run_entry_count"], 1);

    // Tamper the run's entry → pre-replay verification refuses (exit 19).
    let log = env.path("ledger/store/ledger.jsonl");
    let raw = std::fs::read_to_string(&log).unwrap();
    let tampered = raw.replacen("agent.started", "agent.stopped", 1);
    std::fs::write(&log, tampered).unwrap();
    env.cmd(&[
        "replay",
        bundle.to_str().unwrap(),
        traces.to_str().unwrap(),
        "--from-ledger",
        "sess-replay",
    ])
    .args(env.ledger_flags())
    .assert()
    .code(19)
    .stderr(predicate::str::contains(
        "refusing to replay unverified history",
    ));
}

#[test]
fn evidence_bundle_exports_and_verifies_offline_then_fails_on_tamper() {
    let env = Env::new();
    env.cmd(&["ledger", "init"])
        .args([
            "--store",
            env.path("ledger").to_str().unwrap(),
            "--keys",
            env.path("keys").to_str().unwrap(),
        ])
        .assert()
        .success();
    for n in 0..3u64 {
        let event = env.path("e.json");
        write_json(
            &event,
            &serde_json::json!({
                "agent_id": "agent://acme/support",
                "run_id": "run-ev",
                "event_type": "agent.started",
                "payload": { "n": n },
                "event_id": format!("e-{n}"),
            }),
        );
        env.cmd(&["ledger", "append", "--event", event.to_str().unwrap()])
            .args([
                "--store",
                env.path("ledger").to_str().unwrap(),
                "--keys",
                env.path("keys").to_str().unwrap(),
            ])
            .assert()
            .success();
    }
    env.cmd(&["ledger", "seal"])
        .args([
            "--store",
            env.path("ledger").to_str().unwrap(),
            "--keys",
            env.path("keys").to_str().unwrap(),
        ])
        .assert()
        .success();

    let bundle = env.path("bundle");
    env.cmd(&[
        "evidence",
        "export",
        "--run",
        "run-ev",
        "--include-ledger",
        "--output",
        bundle.to_str().unwrap(),
    ])
    .args([
        "--store",
        env.path("ledger").to_str().unwrap(),
        "--keys",
        env.path("keys").to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("non-probative"));

    // Move the bundle away from every ledger dir: verification must need
    // nothing else (scenario 9: clean machine, no network).
    let clean = env.path("clean-machine");
    std::fs::create_dir_all(&clean).unwrap();
    let moved = clean.join("bundle");
    std::fs::rename(&bundle, &moved).unwrap();
    env.cmd(&["evidence", "verify", moved.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));

    // Tamper one member byte → exit 19 with the member named.
    let member = moved.join("run_chain.jsonl");
    let raw = std::fs::read_to_string(&member).unwrap();
    std::fs::write(&member, raw.replacen("agent.started", "agent.stopped", 1)).unwrap();
    env.cmd(&["evidence", "verify", moved.to_str().unwrap()])
        .assert()
        .code(19)
        .stdout(
            predicate::str::contains("FAILED").and(predicate::str::contains("run_chain.jsonl")),
        );
}
