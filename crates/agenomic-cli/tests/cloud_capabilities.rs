use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::json;
use tempfile::{tempdir, TempDir};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "secret";

async fn cloud() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/capabilities"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "edition": "cloud",
            "capabilities": {
                "agm.assistant": { "enabled": true, "reason": "enabled", "visibility": "visible" },
                "rmp.review": {
                    "enabled": false,
                    "reason": "not_entitled",
                    "visibility": "visible",
                    "required_plan": "starter"
                },
                "ledger.cloud_sync": { "enabled": false, "reason": "not_in_edition", "visibility": "hidden" },
                "track.export": { "enabled": false, "reason": "beta_restricted", "visibility": "visible" }
            }
        })))
        .mount(&server)
        .await;
    server
}

fn run(server: &MockServer, home: &TempDir, args: &[&str]) -> Output {
    let output = Command::cargo_bin("agenomic")
        .expect("binary built")
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg-config"))
        .env_remove("AGENOMIC_PROFILE")
        .env_remove("AGENOMIC_FORMAT")
        .env("AGENOMIC_ENDPOINT", server.uri())
        .env("AGENOMIC_API_KEY", KEY)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[tokio::test]
async fn capabilities_human_table() {
    let server = cloud().await;
    let home = tempdir().unwrap();
    let output = run(&server, &home, &["cloud", "capabilities"]);
    insta::assert_snapshot!(
        "capabilities_human",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn capabilities_honor_json_format() {
    let server = cloud().await;
    let home = tempdir().unwrap();
    let output = run(
        &server,
        &home,
        &["--format", "json", "cloud", "capabilities"],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["edition"], "cloud");
    assert_eq!(
        value["capabilities"]["rmp.review"]["required_plan"],
        "starter"
    );
    assert_eq!(value["capabilities"]["agm.assistant"]["enabled"], true);
}
