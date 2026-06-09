//! Integration tests for `agenomic governance *` against the built binary.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

/// Write `traces` (lines of JSON) to a tempfile in `dir`. Returns its path.
fn write_traces(dir: &std::path::Path, traces: &[&str]) -> std::path::PathBuf {
    let path = dir.join("traces.jsonl");
    let mut body = String::new();
    for t in traces {
        body.push_str(t);
        body.push('\n');
    }
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn audit_clusters_proposes_and_critiques_end_to_end() {
    let d = tempdir().unwrap();
    let traces = write_traces(
        d.path(),
        &[
            r#"{"trace_id":"t1","agent_id":"a","skill":"classify","signal":"escalation","input_snippet":"refund partial credit"}"#,
            r#"{"trace_id":"t2","agent_id":"a","skill":"classify","signal":"escalation","input_snippet":"refund partial advance"}"#,
            r#"{"trace_id":"t3","agent_id":"a","skill":"classify","signal":"escalation","input_snippet":"partial credit refund"}"#,
        ],
    );
    let out = agenomic()
        .args([
            "governance",
            "audit",
            traces.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["clusters"].as_array().unwrap().len(), 1);
    assert_eq!(v["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(v["critiques"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["proposals"][0]["suggested_action"]["kind"],
        "extend_skill_examples"
    );
}

#[test]
fn audit_fail_on_block_exits_16_for_single_trace_clusters() {
    let d = tempdir().unwrap();
    let traces = write_traces(
        d.path(),
        &[
            r#"{"trace_id":"only","agent_id":"a","skill":"s","signal":"escalation","input_snippet":"x"}"#,
        ],
    );
    let out = agenomic()
        .args([
            "governance",
            "audit",
            traces.to_str().unwrap(),
            "--fail-on-block",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(16), "expected Block → exit 16");
}

#[test]
fn critique_subcommand_blocks_unanchored_policy_rule() {
    let d = tempdir().unwrap();
    let p = d.path().join("proposal.json");
    std::fs::write(
        &p,
        r#"{
            "id":"p1","cluster_id":"c1","target_skill":"compensation",
            "hypothesis":"...",
            "suggested_action":{"kind":"add_policy_rule","rule_hint":""},
            "evidence_count":10
        }"#,
    )
    .unwrap();
    let out = agenomic()
        .args(["governance", "critique", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(16), "expected Block → exit 16");
}

#[test]
fn cluster_then_hypothesize_round_trips_via_json() {
    let d = tempdir().unwrap();
    let traces = write_traces(
        d.path(),
        &[
            r#"{"trace_id":"t1","agent_id":"a","skill":"comp","signal":"contract_violation","input_snippet":"pii leak"}"#,
            r#"{"trace_id":"t2","agent_id":"a","skill":"comp","signal":"contract_violation","input_snippet":"customer pii"}"#,
            r#"{"trace_id":"t3","agent_id":"a","skill":"comp","signal":"contract_violation","input_snippet":"pii surfaced"}"#,
        ],
    );
    // Step 1: cluster.
    let clusters_out = agenomic()
        .args([
            "governance",
            "cluster",
            traces.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(clusters_out.status.success());
    let clusters_file = d.path().join("clusters.json");
    std::fs::write(&clusters_file, &clusters_out.stdout).unwrap();

    // Step 2: hypothesize, taking the previous output verbatim.
    let proposals_out = agenomic()
        .args([
            "governance",
            "hypothesize",
            clusters_file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        proposals_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&proposals_out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&proposals_out.stdout).unwrap();
    let proposals = v["proposals"].as_array().unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0]["suggested_action"]["kind"], "add_policy_rule");
    let hint = proposals[0]["suggested_action"]["rule_hint"]
        .as_str()
        .unwrap();
    assert!(
        hint.contains("\"pii\""),
        "rule should anchor on pii, got: {hint}"
    );
}
