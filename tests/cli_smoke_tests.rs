use std::fs;
use std::path::PathBuf;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

#[test]
fn starter_bundle_roundtrip_works() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let bundle_dir = temp.path().join("starter-agent");
    let trace_path = temp.path().join("trace.jsonl");
    let report_path = temp.path().join("replay-report.json");

    bin()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized bundle"));

    bin()
        .args(["validate", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle is valid"));

    let bundle_archive = temp.path().join("starter-agent.tar.zst");
    bin()
        .args([
            "build",
            bundle_dir.to_str().unwrap(),
            "--output",
            bundle_archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle hash:"));

    bin()
        .args(["inspect", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent_id: starter-agent"));

    fs::write(
        &trace_path,
        "{\"trace_id\":\"starter-trace\",\"step\":1,\"event\":\"assistant_output\",\"content\":\"starter reply\"}\n",
    )?;

    let replay_output = bin()
        .args([
            "replay",
            bundle_dir.to_str().unwrap(),
            trace_path.to_str().unwrap(),
            "--runs",
            "1",
        ])
        .output()?;
    assert!(replay_output.status.success());
    fs::write(&report_path, &replay_output.stdout)?;

    let replay_json: Value = serde_json::from_slice(&replay_output.stdout)?;
    assert_eq!(replay_json["summary"]["contract_passed"], true);

    bin()
        .args([
            "attest",
            bundle_dir.to_str().unwrap(),
            "--replay-report",
            report_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("release_attestation.json"));

    assert!(bundle_dir.join("release_attestation.json").exists());
    Ok(())
}

#[test]
fn claims_agent_example_smoke_flow_works() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let example = repo_root.join("examples/claims-agent");
    let traces = example.join("traces/sample_traces.jsonl");
    let temp = TempDir::new()?;
    let bundle_archive = temp.path().join("claims-agent.tar.zst");

    bin()
        .args(["validate", example.to_str().unwrap()])
        .assert()
        .success();

    bin()
        .args([
            "build",
            example.to_str().unwrap(),
            "--output",
            bundle_archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let hash_folder = stdout_string(bin().args(["hash", example.to_str().unwrap()]).output()?);
    let hash_bundle = stdout_string(
        bin()
            .args(["hash", bundle_archive.to_str().unwrap()])
            .output()?,
    );
    assert_eq!(hash_folder.trim(), hash_bundle.trim());

    bin()
        .args(["inspect", bundle_archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent_id: claims-agent"));

    let replay_output = bin()
        .args([
            "replay",
            example.to_str().unwrap(),
            traces.to_str().unwrap(),
            "--runs",
            "2",
        ])
        .output()?;
    assert!(replay_output.status.success());
    let replay_json: Value = serde_json::from_slice(&replay_output.stdout)?;
    assert_eq!(replay_json["summary"]["runs_requested"], 2);
    assert_eq!(replay_json["summary"]["contract_passed"], true);

    Ok(())
}

fn bin() -> std::process::Command {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut command = std::process::Command::new(cargo);
    command.args([
        "run",
        "--quiet",
        "-p",
        "agentlock-cli",
        "--bin",
        "agentlock",
        "--",
    ]);
    command
}

fn stdout_string(output: std::process::Output) -> String {
    String::from_utf8(output.stdout).expect("stdout should be valid utf-8")
}
