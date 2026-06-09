use std::path::Path;
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn agenomic() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

fn with_config_env<'a>(cmd: &'a mut Command, home: &Path) -> &'a mut Command {
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg-config"))
}

fn run_ok(cmd: &mut Command) -> Output {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn init_bundle(home: &Path, bundle_dir: &Path, archive: &Path) {
    run_ok(
        with_config_env(agenomic().args(["init"]), home)
            .arg(bundle_dir)
            .args([
                "--agent-id",
                "agent://test/cloud-bucket",
                "--name",
                "Cloud Bucket",
                "--no-detect",
            ]),
    );

    run_ok(
        with_config_env(agenomic().args(["build"]), home)
            .arg(bundle_dir)
            .arg("--output")
            .arg(archive),
    );
}

fn bucket_record(id: &str, slug: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "org_id": "org-1",
        "slug": slug,
        "name": slug,
        "description": null,
        "visibility": "private",
        "content_version": 1,
        "created_at": "2026-06-08T00:00:00Z",
        "updated_at": "2026-06-08T00:00:00Z"
    })
}

fn agent_record(id: &str, name: &str, slug: &str, bucket_id: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "org_id": "org-1",
        "name": name,
        "slug": slug,
        "bucket_id": bucket_id,
        "domain": null,
        "description": null,
        "criticality": "standard",
        "created_at": "2026-06-08T00:00:00Z",
        "updated_at": "2026-06-08T00:00:00Z"
    })
}

fn bundle_record(agent_id: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "bundle-1",
        "org_id": "org-1",
        "agent_id": agent_id,
        "version": version,
        "bundle_hash": "blake3:1234",
        "hash_algorithm": "blake3",
        "storage_key": "bundles/bundle-1",
        "size_bytes": 128,
        "genome_summary": {},
        "lockfile_summary": {},
        "validation_status": "valid",
        "validation_errors": null,
        "created_at": "2026-06-08T00:00:00Z"
    })
}

#[tokio::test]
#[ignore = "requires binding a local TCP port for the mock cloud API"]
async fn cloud_push_agent_creates_default_bucket_and_moves_agent() {
    let server = MockServer::start().await;
    let temp = tempdir().unwrap();
    let bundle_dir = temp.path().join("agent");
    let archive = temp.path().join("agent.bundle.tar.zst");
    init_bundle(temp.path(), &bundle_dir, &archive);

    run_ok(
        with_config_env(agenomic().args(["cloud", "login"]), temp.path()).args([
            "--endpoint",
            &server.uri(),
            "--api-key",
            "secret",
        ]),
    );

    Mock::given(method("GET"))
        .and(path("/v1/buckets"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "buckets": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/buckets"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": bucket_record("bucket-1", "default")
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/agents"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent": agent_record("agent-1", "Cloud Bucket Agent", "cloud-bucket-agent", None)
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-1/move-to-bucket"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent": agent_record("agent-1", "Cloud Bucket Agent", "cloud-bucket-agent", Some("bucket-1"))
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/bundles"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bundle": bundle_record("agent-1", "v0.2.0")
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = run_ok(
        with_config_env(agenomic().args(["cloud", "push-agent"]), temp.path())
            .arg(&archive)
            .args(["--name", "Cloud Bucket Agent", "--version", "v0.2.0"]),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("created agent agent-1"));
    assert!(stdout.contains("uploaded bundle bundle-1"));
}

#[tokio::test]
#[ignore = "requires binding a local TCP port for the mock cloud API"]
async fn bucket_use_sets_active_bucket_for_push_agent() {
    let server = MockServer::start().await;
    let temp = tempdir().unwrap();
    let bundle_dir = temp.path().join("agent");
    let archive = temp.path().join("agent.bundle.tar.zst");
    init_bundle(temp.path(), &bundle_dir, &archive);

    run_ok(
        with_config_env(agenomic().args(["cloud", "login"]), temp.path()).args([
            "--endpoint",
            &server.uri(),
            "--api-key",
            "secret",
        ]),
    );

    Mock::given(method("GET"))
        .and(path("/v1/buckets"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "buckets": [bucket_record("bucket-bench", "bench")]
        })))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/agents"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent": agent_record("agent-2", "Bench Agent", "bench-agent", None)
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-2/move-to-bucket"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent": agent_record("agent-2", "Bench Agent", "bench-agent", Some("bucket-bench"))
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/bundles"))
        .and(header("x-api-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bundle": bundle_record("agent-2", "v0.3.0")
        })))
        .expect(1)
        .mount(&server)
        .await;

    let use_output = run_ok(
        with_config_env(agenomic().args(["bucket", "use"]), temp.path()).args(["--name", "bench"]),
    );
    assert!(String::from_utf8_lossy(&use_output.stdout).contains("bench"));

    let push_output = run_ok(
        with_config_env(agenomic().args(["cloud", "push-agent"]), temp.path())
            .arg(&archive)
            .args(["--name", "Bench Agent", "--version", "v0.3.0"]),
    );
    assert!(String::from_utf8_lossy(&push_output.stdout).contains("uploaded bundle bundle-1"));
}
