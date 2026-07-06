//! `agenomic ledger` end-to-end scenarios (prompt §10): init → append →
//! verify → export; tamper → verify fails at the right entry with exit 19;
//! duplicate/conflict semantics; key rotation mid-run; dead-letter list +
//! replay; queue drain.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

struct Env {
    root: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn keys(&self) -> PathBuf {
        self.root.path().join("keys")
    }
    fn store(&self) -> PathBuf {
        self.root.path().join("ledger")
    }
    fn ledger_log(&self) -> PathBuf {
        self.store().join("store").join("ledger.jsonl")
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::cargo_bin("agenomic").unwrap();
        c.current_dir(self.root.path());
        c.args(["ledger"]);
        c.args(args);
        c.args([
            "--store",
            self.store().to_str().unwrap(),
            "--keys",
            self.keys().to_str().unwrap(),
        ]);
        c
    }
    fn write_event(&self, name: &str, run: &str, event_type: &str, n: u64) -> PathBuf {
        self.write_event_with_id(name, run, event_type, n, None)
    }
    fn write_event_with_id(
        &self,
        name: &str,
        run: &str,
        event_type: &str,
        n: u64,
        event_id: Option<&str>,
    ) -> PathBuf {
        let path = self.root.path().join(name);
        let mut event = serde_json::json!({
            "agent_id": "agent://acme/support",
            "run_id": run,
            "event_type": event_type,
            "payload": { "n": n },
        });
        if let Some(id) = event_id {
            event["event_id"] = serde_json::json!(id);
        }
        std::fs::write(&path, serde_json::to_string(&event).unwrap()).unwrap();
        path
    }
    fn init(&self) {
        self.cmd(&["init"]).assert().success();
    }
    fn append(&self, event: &Path) {
        self.cmd(&["append", "--event", event.to_str().unwrap()])
            .assert()
            .success();
    }
}

#[test]
fn scenario_init_track_verify_export() {
    let env = Env::new();
    env.init();
    let e1 = env.write_event("e1.json", "run-1", "agent.started", 1);
    let e2 = env.write_event("e2.json", "run-1", "agent.completed", 2);
    env.append(&e1);
    env.append(&e2);

    env.cmd(&["seal"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sealed block"));

    env.cmd(&["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));

    // Export a valid JSONL chain: every line parses, sequences contiguous.
    let export = env.root.path().join("export.jsonl");
    env.cmd(&[
        "export",
        "--run",
        "run-1",
        "--output",
        export.to_str().unwrap(),
    ])
    .assert()
    .success();
    let raw = std::fs::read_to_string(&export).unwrap();
    let mut seq = 0u64;
    for line in raw.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["run_sequence_number"], seq);
        assert!(v["entry_hash"].as_str().unwrap().starts_with("blake3:"));
        seq += 1;
    }
    assert_eq!(seq, 2);

    // Status + tail + inspect smoke.
    env.cmd(&["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entries:  2"));
    env.cmd(&["tail", "--run", "run-1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent.completed"));
    let first: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
    env.cmd(&["inspect", "--entry", first["event_id"].as_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent.started"));
}

#[test]
fn scenario_tamper_one_byte_fails_verify_with_exit_19() {
    let env = Env::new();
    env.init();
    for n in 0..3u64 {
        let e = env.write_event(&format!("e{n}.json"), "run-1", "agent.started", n);
        env.append(&e);
    }
    env.cmd(&["seal"]).assert().success();

    // Flip one hex char of entry 1's payload hash (JSON stays parseable).
    let log = env.ledger_log();
    let raw = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = raw.lines().map(String::from).collect();
    let needle = "\"event_payload_hash\":\"blake3:";
    let pos = lines[1].find(needle).unwrap() + needle.len();
    let mut bytes = lines[1].clone().into_bytes();
    bytes[pos] = if bytes[pos] == b'0' { b'1' } else { b'0' };
    lines[1] = String::from_utf8(bytes).unwrap();
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();

    env.cmd(&["verify"]).assert().code(19).stdout(
        predicate::str::contains("FAILED")
            .and(predicate::str::contains("first invalid sequence: 1"))
            .and(predicate::str::contains("tampering")),
    );
}

#[test]
fn scenario_duplicate_idempotent_then_conflict() {
    let env = Env::new();
    env.init();
    let e = env.write_event_with_id("e.json", "run-1", "agent.started", 1, Some("fixed-id"));
    env.append(&e);

    // Same event id + same payload: idempotent success.
    env.cmd(&["append", "--event", e.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("duplicate (idempotent)"));

    // Same event id + different payload: conflict, exit 19, dead-lettered.
    let fork =
        env.write_event_with_id("fork.json", "run-1", "agent.started", 999, Some("fixed-id"));
    env.cmd(&["append", "--event", fork.to_str().unwrap()])
        .assert()
        .code(19)
        .stderr(predicate::str::contains("conflict"));

    env.cmd(&["queue", "dead-letter", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("reason=conflict").and(predicate::str::contains("fixed-id")),
        );

    // Replaying the conflicting record fails again and keeps the record.
    env.cmd(&["queue", "dead-letter", "replay"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 failed"));
    env.cmd(&["queue", "dead-letter", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reason=conflict"));

    // The ledger still holds exactly one entry and verifies.
    env.cmd(&["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entries: 1"));
}

#[test]
fn scenario_rotate_keys_mid_run_history_still_verifies() {
    let env = Env::new();
    env.init();
    let e1 = env.write_event("e1.json", "run-1", "agent.started", 1);
    env.append(&e1);

    env.cmd(&["keys", "rotate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated to"));

    let e2 = env.write_event("e2.json", "run-1", "agent.completed", 2);
    env.append(&e2);

    env.cmd(&["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));
    env.cmd(&["verify", "--run", "run-1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));

    // Two keys listed; the rotated one signed the first entry.
    env.cmd(&["keys", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Rotated").and(predicate::str::contains("Active")));

    // Revoking the rotated key flags (does not fail) verification.
    let keys_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.keys().join("keys-manifest.json")).unwrap(),
    )
    .unwrap();
    let rotated_id = keys_manifest["keys"]
        .as_object()
        .unwrap()
        .values()
        .find(|k| k["status"] == "rotated")
        .unwrap()["key_id"]
        .as_str()
        .unwrap()
        .to_string();
    env.cmd(&["keys", "revoke", &rotated_id]).assert().success();
    env.cmd(&["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("revoked keys"));
}

#[test]
fn verify_block_scope_and_unknown_ids_error() {
    let env = Env::new();
    env.init();
    for n in 0..2u64 {
        let e = env.write_event(&format!("e{n}.json"), "run-1", "agent.started", n);
        env.append(&e);
    }
    env.cmd(&["seal"]).assert().success();

    let blocks_raw = std::fs::read_to_string(env.store().join("blocks.jsonl")).unwrap();
    let block: serde_json::Value =
        serde_json::from_str(blocks_raw.lines().next().unwrap()).unwrap();
    let block_id = block["block_id"].as_str().unwrap();

    env.cmd(&["verify", "--block", block_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASSED"));
    env.cmd(&["verify", "--block", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown block"));
    env.cmd(&["inspect", "--entry", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no entry"));
}

#[test]
fn keys_export_public_prints_pem_only() {
    let env = Env::new();
    env.init();
    env.cmd(&["keys", "export-public"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("BEGIN PUBLIC KEY")
                .and(predicate::str::contains("PRIVATE").not()),
        );
}

#[test]
fn queue_flush_reports_recovery_counts() {
    let env = Env::new();
    env.init();
    let e = env.write_event("e.json", "run-1", "agent.started", 1);
    env.append(&e);
    env.cmd(&["queue", "flush"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 pending after"));
    env.cmd(&["queue", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dead-letter: 0"));
}

#[test]
fn json_format_outputs_are_machine_readable() {
    let env = Env::new();
    env.init();
    let e = env.write_event("e.json", "run-1", "agent.started", 1);
    env.append(&e);

    let out = env
        .cmd(&["verify", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["passed"], true);
    assert_eq!(v["report"]["report_version"], "agenomic.ledger.verify/v0.1");

    let out = env
        .cmd(&["status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["entry_count"], 1);
}

#[test]
fn human_verify_output_snapshot() {
    let env = Env::new();
    env.init();
    for n in 0..2u64 {
        let run = if n == 0 { "run-a" } else { "run-b" };
        let e = env.write_event(&format!("e{n}.json"), run, "agent.started", n);
        env.append(&e);
    }
    env.cmd(&["seal"]).assert().success();
    let out = env
        .cmd(&["verify"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    // Hashes are real, generated by this run — scrubbed only because keys
    // (and therefore every hash) are fresh per test execution.
    let scrubbed = scrub_hashes(&text);
    insta::assert_snapshot!("verify_human", scrubbed);
}

/// Replace every `blake3:<64 hex>` with `blake3:[hash]` (no regex dep).
fn scrub_hashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(idx) = rest.find("blake3:") {
        let (before, after) = rest.split_at(idx + "blake3:".len());
        out.push_str(before);
        let hex_len = after.chars().take_while(|c| c.is_ascii_hexdigit()).count();
        if hex_len == 64 {
            out.push_str("[hash]");
            rest = &after[64..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}
