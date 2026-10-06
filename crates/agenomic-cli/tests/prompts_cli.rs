use std::path::Path;
use std::process::{Command, Output};

use agenomic_prompt::{artifact_set_digest, prompt_digest, signing_digest};
use assert_cmd::cargo::CommandCargoExt;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use wiremock::matchers::{any, body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "secret";
const WORKSPACE: &str = "0b6c2f1e-7a44-4c8e-9f1d-2a3b4c5d6e7f";
const AGENT: &str = "2b1e5c3a-8d4f-4e6a-9b0c-1d2e3f4a5b6c";
const RELEASE: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const CANDIDATE: &str = "8f0c2d4e-6a1b-4c3d-9e5f-7a8b9c0d1e2f";
const PREVIOUS: &str = "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c";

struct Env {
    home: TempDir,
    endpoint: Option<String>,
}

impl Env {
    fn offline() -> Self {
        Self {
            home: tempdir().unwrap(),
            endpoint: None,
        }
    }

    fn cloud(server: &MockServer) -> Self {
        Self {
            home: tempdir().unwrap(),
            endpoint: Some(server.uri()),
        }
    }

    fn dir(&self) -> &Path {
        self.home.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::cargo_bin("agenomic").expect("binary built");
        command
            .args(args)
            .current_dir(self.dir())
            .env("HOME", self.dir())
            .env("XDG_CONFIG_HOME", self.dir().join("xdg-config"))
            .env_remove("AGENOMIC_PROFILE")
            .env_remove("AGENOMIC_FORMAT")
            .env_remove("AGENOMIC_NO_COLOR")
            .env_remove("AGENOMIC_WEB_URL")
            .env_remove("AGENOMIC_ENDPOINT")
            .env_remove("AGENOMIC_API_KEY");
        if let Some(endpoint) = &self.endpoint {
            command
                .env("AGENOMIC_ENDPOINT", endpoint)
                .env("AGENOMIC_API_KEY", KEY);
        }
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn write(&self, name: &str, value: &Value) -> String {
        let path = self.dir().join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path.display().to_string()
    }

    fn redact(&self, text: &str) -> String {
        let mut text = text.replace(&self.dir().display().to_string(), "[TMP]");
        if let Some(endpoint) = &self.endpoint {
            text = text.replace(endpoint, "[SERVER]");
        }
        text.replace('\\', "/")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn assert_stderr(output: &Output, needle: &str) {
    assert!(stderr(output).contains(needle), "{}", stderr(output));
}

fn content(kind: &str, body: Value, variables: Value, partials: Value, fragments: Value) -> Value {
    json!({
        "schema": "agenomic.prompt_content/v1",
        "template_format": "agenomic-fstring/v1",
        "renderer_version": "1",
        "kind": kind,
        "body": body,
        "variables": variables,
        "partials": partials,
        "output_contract": null,
        "fragments": fragments,
    })
}

fn safety() -> Value {
    content(
        "text",
        json!("Never share internal notes."),
        json!({}),
        json!({}),
        json!({}),
    )
}

fn planner() -> Value {
    content(
        "text",
        json!("Plan the next step for {question}.\n{>safety}"),
        json!({ "question": { "type": "string", "required": true } }),
        json!({}),
        json!({ "safety": { "prompt_id": "prm_safety", "version": 2, "content_digest": digest(&safety()) } }),
    )
}

fn chat() -> Value {
    content(
        "chat",
        json!([
            { "role": "system", "content": "You plan support work for locale {locale}." },
            { "placeholder": "history", "optional": true },
            { "role": "user", "content": "{question}" }
        ]),
        json!({
            "history": { "type": "messages", "required": false },
            "locale": { "type": "string", "required": false },
            "question": { "type": "string", "required": true }
        }),
        json!({ "locale": "en" }),
        json!({}),
    )
}

fn digest(value: &Value) -> String {
    prompt_digest(value).unwrap()
}

fn prompt_view(prompt_id: &str, kind: &str, latest: Option<u32>) -> Value {
    json!({
        "prompt_id": prompt_id,
        "kind": kind,
        "name": "Support planner",
        "description": "Plans the next support step.",
        "owner": null,
        "tags": ["support"],
        "status": "active",
        "latest_version": latest,
        "metadata_revision": 3,
        "created_at": "2026-10-04T20:11:02Z",
        "created_by": { "user_id": null, "api_key_id": null },
        "updated_at": "2026-10-04T20:40:13Z",
        "archived_at": null,
        "uri_prefix": format!("agenomic://{WORKSPACE}/prompts/{prompt_id}")
    })
}

fn version_view(prompt_id: &str, version: u32, content: &Value, parent: Option<u32>) -> Value {
    json!({
        "prompt_id": prompt_id,
        "version": version,
        "ref": format!("{prompt_id}:{version}"),
        "canonical_uri": format!("agenomic://{WORKSPACE}/prompts/{prompt_id}/versions/{version}"),
        "content_digest": digest(content),
        "content": content,
        "parent_version": parent,
        "change_message": "Ask for the order id first",
        "variable_descriptions": {},
        "author": { "user_id": null, "api_key_id": null },
        "provenance": { "source": "api", "draft_revision": null, "import_id": null, "item_id": null, "source_file": null, "source_line": null },
        "created_at": "2026-10-04T20:40:13Z"
    })
}

fn bundle_document(planner_content: &Value) -> Value {
    let planner_digest = digest(planner_content);
    let manifest = json!({
        "schema": "agenomic.prompt_manifest/v1",
        "agent_id": AGENT,
        "slots": { "planner.instructions": { "prompt_id": "prm_planner", "version": 7, "content_digest": planner_digest } },
        "children": {}
    });
    let mut document = json!({
        "schema": "agenomic.prompt_bundle/v1",
        "workspace_id": WORKSPACE,
        "agent_id": AGENT,
        "source": { "channel": "production", "channel_generation": 12 },
        "release": { "release_id": RELEASE, "release_name": "av_0042", "genome_version": format!("sha256:{}", "3".repeat(64)), "bundle_id": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b", "bundle_hash": format!("blake3:{}", "0".repeat(64)), "legacy": false },
        "prompt_manifest_digest": digest(&manifest),
        "manifest": manifest,
        "children": {},
        "prompts": {
            "prm_planner:7": { "prompt_id": "prm_planner", "version": 7, "prompt_kind": "text", "content_digest": planner_digest, "content": planner_content },
            "prm_safety:2": { "prompt_id": "prm_safety", "version": 2, "prompt_kind": "fragment", "content_digest": digest(&safety()), "content": safety() }
        },
        "governance": { "release_status": "production", "channel": "production", "channel_protected": true, "approved": true },
        "exported_at": "2026-10-04T21:10:00Z",
        "expires_at": "2099-01-01T00:00:00Z"
    });
    document["prompt_bundle_digest"] = json!(artifact_set_digest(&document).unwrap());
    document
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn signed(mut document: Value, key: &SigningKey) -> Value {
    document["issuer"] = json!({ "key_id": "orgkey_test", "algorithm": "ed25519" });
    let signature = key.sign(&signing_digest(&document));
    document["signature"] = json!({
        "algorithm": "ed25519",
        "value": STANDARD.encode(signature.to_bytes()),
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nembedded keys are never trusted\n-----END PUBLIC KEY-----\n"
    });
    document
}

fn public_pem(key: &SigningKey) -> String {
    key.verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
}

async fn mount_whoami(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/whoami"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "org_id": WORKSPACE,
            "user_id": null,
            "api_key_id": "6e7f8a9b-0c1d-4e2f-8a3b-4c5d6e7f8a9b",
            "api_key_name": "ci"
        })))
        .mount(server)
        .await;
}

async fn mount_planner(server: &MockServer, served: &Value) {
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt": prompt_view("prm_planner", "text", Some(7)),
            "latest": null,
            "aliases": [],
            "draft": null
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner/versions/7"))
        .and(query_param("include", "fragments"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": served,
            "fragments": [version_view("prm_safety", 2, &safety(), Some(1))]
        })))
        .mount(server)
        .await;
}

fn requests(received: &[Request]) -> Vec<String> {
    received
        .iter()
        .map(|request| {
            let query = request
                .url
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default();
            format!("{} {}{query}", request.method, request.url.path())
        })
        .collect()
}

#[test]
fn render_a_prompt_file_offline_with_no_cloud_profile() {
    let env = Env::offline();
    let file = env.write(
        "planner.prompt.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_greeter",
            "kind": "text",
            "content": content(
                "text",
                json!("Hello {name}, you have {count} tasks."),
                json!({ "name": { "type": "string", "required": true }, "count": { "type": "integer", "required": true } }),
                json!({}),
                json!({})
            ),
            "parent_version": null
        }),
    );
    let vars = env.write("vars.json", &json!({ "count": 3 }));
    let output = env.run(&[
        "prompts", "render", &file, "--var", "name=Ada", "--vars", &vars,
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("render_text_file_offline", stdout(&output));

    let chat_file = env.write("chat.json", &chat());
    let output = env.run(&[
        "--format",
        "json-pretty",
        "prompts",
        "render",
        &chat_file,
        "--var",
        "question=Where is my parcel?",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("render_chat_content_offline_json", stdout(&output));
}

#[test]
fn local_render_errors_exit_1_before_any_model_call() {
    let env = Env::offline();
    let file = env.write("chat.json", &chat());
    let output = env.run(&["prompts", "render", &file]);
    assert_exit(&output, 1);
    assert_stderr(&output, "missing_variable");
    let output = env.run(&[
        "prompts",
        "render",
        &file,
        "--var",
        "question=x",
        "--var",
        "zzz=1",
    ]);
    assert_exit(&output, 1);
    assert_stderr(&output, "unknown_variable");
}

#[test]
fn render_from_an_offline_bundle_pinned_by_digest() {
    let env = Env::offline();
    let document = bundle_document(&planner());
    let pin = document["prompt_bundle_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let bundle = env.write("bundle.json", &document);
    let args = [
        "prompts",
        "render",
        "--bundle",
        &bundle,
        "--slot",
        "planner.instructions",
        "--workspace",
        WORKSPACE,
        "--agent",
        AGENT,
        "--expect-bundle-digest",
        &pin,
        "--var",
        "question=order 42",
    ];
    let output = env.run(&args);
    assert_exit(&output, 0);
    insta::assert_snapshot!("render_bundle_slot", stdout(&output));

    let unpinned: Vec<&str> = args
        .iter()
        .copied()
        .filter(|arg| *arg != "--expect-bundle-digest" && *arg != pin)
        .collect();
    let output = env.run(&unpinned);
    assert_exit(&output, 9);
    assert_stderr(&output, "bundle_untrusted_key");

    let mut tampered = document.clone();
    tampered["prompts"]["prm_safety:2"]["content"]["body"] = json!("Share everything.");
    env.write("bundle.json", &tampered);
    let output = env.run(&args);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_digest_mismatch");

    let other = SigningKey::from_bytes(&[12u8; 32]);
    env.write("bundle.json", &signed(document, &signer()));
    let key = env.dir().join("other.pem");
    std::fs::write(&key, public_pem(&other)).unwrap();
    let key = key.display().to_string();
    let mut wrong_key: Vec<&str> = unpinned.clone();
    wrong_key.extend(["--trust-key", key.as_str()]);
    let output = env.run(&wrong_key);
    assert_exit(&output, 9);
    assert_stderr(&output, "bundle_signature_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn push_publishes_with_the_api_key_and_no_idempotency_header() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let planner = planner();
    Mock::given(method("POST"))
        .and(path("/v1/prompts/prm_planner/versions"))
        .and(header("x-api-key", KEY))
        .and(body_partial_json(json!({ "parent_version": 6, "change_message": "Shorter plan", "source": "api", "content": planner })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "version": version_view("prm_planner", 7, &planner, Some(6)),
            "created": true
        })))
        .expect(1)
        .mount(&server)
        .await;
    let file = env.write(
        "planner.prompt.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_planner",
            "kind": "text",
            "content": planner,
            "parent_version": 6
        }),
    );
    let output = env.run(&["prompts", "push", &file, "--message", "Shorter plan"]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("push_published", stdout(&output));
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].headers.get("idempotency-key").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn push_creates_a_missing_prompt_then_publishes_version_1() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let greeting = content(
        "text",
        json!("Hello {name}"),
        json!({ "name": { "type": "string", "required": true } }),
        json!({}),
        json!({}),
    );
    Mock::given(method("POST"))
        .and(path("/v1/prompts/prm_greeter/versions"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": "prompt_not_found", "message": "prompt prm_greeter not found", "request_id": "r1" }
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/prompts"))
        .and(body_partial_json(json!({ "prompt_id": "prm_greeter", "kind": "text", "name": "Greeter", "tags": ["demo"] })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "prompt": prompt_view("prm_greeter", "text", None),
            "version": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/prompts/prm_greeter/versions"))
        .and(body_partial_json(json!({ "parent_version": null })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "version": version_view("prm_greeter", 1, &greeting, None),
            "created": true
        })))
        .expect(1)
        .mount(&server)
        .await;
    let file = env.write(
        "greeter.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_greeter",
            "name": "Greeter",
            "tags": ["demo"],
            "kind": "text",
            "content": greeting,
            "parent_version": null
        }),
    );
    let output = env.run(&["--format", "json", "prompts", "push", &file]);
    assert_exit(&output, 0);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["ref"], "prm_greeter:1");
    assert_eq!(summary["created"], true);
    assert_eq!(summary["content_digest"], json!(digest(&greeting)));
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn push_conflict_exits_21_and_dry_run_sends_nothing() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    Mock::given(method("POST"))
        .and(path("/v1/prompts/prm_planner/versions"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": { "code": "prompt_version_conflict", "message": "parent_version 5 is not the latest version", "request_id": "r2", "details": { "latest_version": 7 } }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let file = env.write(
        "planner.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_planner",
            "kind": "text",
            "content": planner(),
            "parent_version": 5
        }),
    );
    let output = env.run(&["prompts", "push", &file]);
    assert_exit(&output, 21);
    assert_stderr(&output, "prompt_version_conflict");

    let output = env.run(&["prompts", "push", &file, "--dry-run"]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("push_dry_run", stdout(&output));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn push_refuses_a_stale_file_digest_and_a_diverging_server_digest() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let planner = planner();
    let stale = env.write(
        "stale.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_planner",
            "kind": "text",
            "content": planner,
            "parent_version": 6,
            "version": 7,
            "content_digest": digest(&safety())
        }),
    );
    let output = env.run(&["prompts", "push", &stale]);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_digest_mismatch");

    let mut served = version_view("prm_planner", 7, &planner, Some(6));
    served["content_digest"] = json!(format!("sha256:{}", "e".repeat(64)));
    Mock::given(method("POST"))
        .and(path("/v1/prompts/prm_planner/versions"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({ "version": served, "created": true })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let fresh = env.write(
        "fresh.json",
        &json!({
            "schema": "agenomic.prompt_file/v1",
            "prompt_id": "prm_planner",
            "kind": "text",
            "content": planner,
            "parent_version": 6
        }),
    );
    let output = env.run(&["prompts", "push", &fresh]);
    assert_exit(&output, 1);
    assert_stderr(&output, "hint");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_writes_a_verified_prompt_file_and_resolves_aliases_once() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let planner = planner();
    mount_planner(&server, &version_view("prm_planner", 7, &planner, Some(6))).await;
    Mock::given(method("POST"))
        .and(path("/v1/prompts/resolve"))
        .and(body_partial_json(json!({ "ref": "prm_planner@staging" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "input": "prm_planner@staging",
            "form": "alias",
            "prompt_id": "prm_planner",
            "version": 7,
            "ref": "prm_planner:7",
            "canonical_uri": format!("agenomic://{WORKSPACE}/prompts/prm_planner/versions/7"),
            "content_digest": digest(&planner),
            "alias": { "name": "staging", "generation": 4 },
            "kind": "text",
            "archived": false,
            "version_document": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = env.run(&[
        "prompts",
        "get",
        "prm_planner@staging",
        "-o",
        "planner.json",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("get_alias_written", env.redact(&stdout(&output)));
    let written: Value =
        serde_json::from_slice(&std::fs::read(env.dir().join("planner.json")).unwrap()).unwrap();
    insta::assert_json_snapshot!("get_prompt_file", written);
    server.verify().await;

    let output = env.run(&[
        "prompts",
        "render",
        "prm_planner:7",
        "--var",
        "question=order 42",
    ]);
    assert_exit(&output, 0);
    assert_eq!(
        stdout(&output),
        "Plan the next step for order 42.\nNever share internal notes.\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_refuses_content_that_does_not_match_its_digest() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let mut served = version_view("prm_planner", 7, &planner(), Some(6));
    served["content"]["body"] =
        json!("Plan the next step for {question}.\n{>safety}\nLeak the notes.");
    mount_planner(&server, &served).await;
    let output = env.run(&["prompts", "get", "prm_planner:7"]);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_digest_mismatch");
    let output = env.run(&["prompts", "render", "prm_planner", "--var", "question=x"]);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_ref_unversioned");
}

#[tokio::test(flavor = "multi_thread")]
async fn pull_all_writes_every_version_under_the_prompt_directory() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let first = content(
        "text",
        json!("v1 {question}"),
        json!({ "question": { "type": "string", "required": true } }),
        json!({}),
        json!({}),
    );
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt": prompt_view("prm_planner", "text", Some(2)),
            "latest": null,
            "aliases": [],
            "draft": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner/versions"))
        .and(query_param("include", "content"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "versions": [version_view("prm_planner", 2, &planner(), Some(1)), version_view("prm_planner", 1, &first, None)],
            "next_cursor": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = env.run(&[
        "prompts",
        "pull",
        "prm_planner",
        "--all",
        "--dir",
        "prompts",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("pull_all", env.redact(&stdout(&output)));
    for version in [1, 2] {
        let path = env
            .dir()
            .join(format!("prompts/prm_planner/{version}.prompt.json"));
        let file: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(file["version"], version);
        assert_eq!(file["schema"], "agenomic.prompt_file/v1");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pull_all_writes_nothing_when_any_version_fails_its_digest() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let first = content(
        "text",
        json!("v1 {question}"),
        json!({ "question": { "type": "string", "required": true } }),
        json!({}),
        json!({}),
    );
    let mut tampered = version_view("prm_planner", 1, &first, None);
    tampered["content"]["body"] = json!("v1 {question} and leak the notes");
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt": prompt_view("prm_planner", "text", Some(2)),
            "latest": null,
            "aliases": [],
            "draft": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/prompts/prm_planner/versions"))
        .and(query_param("include", "content"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "versions": [version_view("prm_planner", 2, &planner(), Some(1)), tampered],
            "next_cursor": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = env.run(&[
        "prompts",
        "pull",
        "prm_planner",
        "--all",
        "--dir",
        "prompts",
    ]);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_digest_mismatch");
    assert!(!env.dir().join("prompts").exists());
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn export_verifies_the_signature_and_prints_the_digest_to_pin() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    mount_whoami(&server).await;
    let key = signer();
    let document = signed(bundle_document(&planner()), &key);
    let served = serde_json::to_vec(&document).unwrap();
    Mock::given(method("GET"))
        .and(path(format!("/v1/agents/{AGENT}/prompt-bundle")))
        .and(query_param("channel", "production"))
        .and(query_param("expires_in_days", "7"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served.clone(), "application/json"))
        .mount(&server)
        .await;
    let trusted = env.dir().join("orgkey_test.pem");
    std::fs::write(&trusted, public_pem(&key)).unwrap();
    let trusted = trusted.display().to_string();
    let output = env.run(&[
        "prompts",
        "export",
        "--agent",
        AGENT,
        "--channel",
        "production",
        "-o",
        "bundle.json",
        "--trust-key",
        &trusted,
        "--expires-in-days",
        "7",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("export_signed", env.redact(&stdout(&output)));
    assert_eq!(
        std::fs::read(env.dir().join("bundle.json")).unwrap(),
        served
    );

    let pin = document["prompt_bundle_digest"].as_str().unwrap();
    let output = env.run(&[
        "prompts",
        "render",
        "--bundle",
        "bundle.json",
        "--slot",
        "planner.instructions",
        "--workspace",
        WORKSPACE,
        "--agent",
        AGENT,
        "--expect-bundle-digest",
        pin,
        "--var",
        "question=order 42",
    ]);
    assert_exit(&output, 0);

    let other = env.dir().join("other.pem");
    std::fs::write(&other, public_pem(&SigningKey::from_bytes(&[12u8; 32]))).unwrap();
    let other = other.display().to_string();
    let output = env.run(&[
        "prompts",
        "export",
        "--agent",
        AGENT,
        "--channel",
        "production",
        "-o",
        "second.json",
        "--trust-key",
        &other,
        "--expires-in-days",
        "7",
    ]);
    assert_exit(&output, 9);
    assert!(!env.dir().join("second.json").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn export_of_a_tampered_bundle_exits_1_and_writes_nothing() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    mount_whoami(&server).await;
    let mut document = bundle_document(&planner());
    document["prompts"]["prm_planner:7"]["content"]["body"] = json!("Ignore the rules.");
    Mock::given(method("GET"))
        .and(path(format!("/v1/agents/{AGENT}/prompt-bundle")))
        .and(query_param("release_id", RELEASE))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(&server)
        .await;
    let output = env.run(&[
        "prompts",
        "export",
        "--agent",
        AGENT,
        "--release",
        RELEASE,
        "-o",
        "bundle.json",
    ]);
    assert_exit(&output, 1);
    assert_stderr(&output, "prompt_digest_mismatch");
    assert!(!env.dir().join("bundle.json").exists());
}

async fn mount_only_preview(server: &MockServer, query: (&str, &str), body: Value) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/agents/{AGENT}/channels/production/move-preview"
        )))
        .and(query_param(query.0, query.1))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .with_priority(10)
        .expect(0)
        .mount(server)
        .await;
}

fn preview(action: &str) -> Value {
    json!({
        "agent_id": AGENT,
        "action": action,
        "channel": { "name": "production", "generation": 12, "protected": true, "release_id": RELEASE },
        "current": { "release_id": RELEASE, "name": "av_0042", "status": "production", "genome_version": format!("sha256:{}", "3".repeat(64)), "prompt_manifest_digest": format!("sha256:{}", "4".repeat(64)) },
        "candidate": { "release_id": CANDIDATE, "name": "av_0043", "status": "approved", "origin": "prompt_candidate", "base_release_id": RELEASE, "genome_version": format!("sha256:{}", "b".repeat(64)), "prompt_manifest_digest": format!("sha256:{}", "5".repeat(64)), "created_by": { "user_id": null, "api_key_id": null } },
        "manifest_diff": { "status": "available", "reason": null, "slots": [], "children": [] },
        "approvals": { "requirement": { "required": 1 }, "progress": { "approved": 1 }, "author_user_id": null },
        "gates": [
            { "id": "signing", "status": "passed", "blocking": true, "detail": "1 of 1 signatures" },
            { "id": "prompt_experiment", "status": "not_required", "blocking": false, "detail": "floor flag off" }
        ],
        "rollback": { "default_target": { "release_id": PREVIOUS, "name": "av_0041", "status": "approved" }, "options": [ { "release_id": PREVIOUS, "name": "av_0041", "status": "approved" } ] },
        "rollback_target_after": { "release_id": RELEASE, "name": "av_0042" },
        "actions": { "promote": false, "rollback": false, "reasons": ["session_required"] },
        "move_url": format!("/agents/{AGENT}/channels/production?candidate={CANDIDATE}")
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn channels_promote_is_a_hand_off_that_only_reads_the_move_preview() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    mount_only_preview(&server, ("release_id", CANDIDATE), preview("promote")).await;
    let output = env
        .command(&[
            "channels",
            "promote",
            "--agent",
            AGENT,
            "production",
            "--release",
            CANDIDATE,
        ])
        .env("AGENOMIC_WEB_URL", "https://app.example.test/")
        .output()
        .unwrap();
    assert_exit(&output, 0);
    insta::assert_snapshot!("channels_promote_hand_off", stdout(&output));
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        requests(&received),
        vec![format!(
            "GET /v1/agents/{AGENT}/channels/production/move-preview?action=promote&release_id={CANDIDATE}"
        )]
    );
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn channels_rollback_is_a_hand_off_that_only_reads_the_move_preview() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    mount_only_preview(&server, ("action", "rollback"), preview("rollback")).await;
    let output = env.run(&[
        "--format",
        "json",
        "channels",
        "rollback",
        "--agent",
        AGENT,
        "production",
    ]);
    assert_exit(&output, 0);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["moved"], false);
    assert_eq!(
        result["move_url"],
        format!("/agents/{AGENT}/channels/production?candidate={CANDIDATE}")
    );
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        requests(&received),
        vec![format!(
            "GET /v1/agents/{AGENT}/channels/production/move-preview?action=rollback"
        )]
    );
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn channels_rollback_to_release_prints_the_evaluated_target() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let mut body = preview("rollback");
    body["candidate"] = json!({ "release_id": CANDIDATE, "name": "av_0043", "status": "rolled_back", "origin": "prompt_candidate", "base_release_id": RELEASE, "genome_version": format!("sha256:{}", "b".repeat(64)), "prompt_manifest_digest": format!("sha256:{}", "5".repeat(64)) });
    body["gates"] = json!([{ "id": "signing", "status": "failed", "blocking": true, "detail": "the release is rolled_back" }]);
    body["actions"] = json!({ "promote": false, "rollback": false, "reasons": ["session_required", "rollback_target_invalid"] });
    body["move_url"] = json!(format!("/agents/{AGENT}/channels/production"));
    mount_only_preview(&server, ("to_release_id", CANDIDATE), body).await;
    let output = env.run(&[
        "channels",
        "rollback",
        "--agent",
        AGENT,
        "production",
        "--to-release",
        CANDIDATE,
    ]);
    assert_exit(&output, 0);
    let text = stdout(&output);
    assert!(text.contains(&format!("target:    av_0043 {CANDIDATE} (rolled_back)")));
    assert!(text.contains(&format!("default:   av_0041 {PREVIOUS} (approved)")));
    insta::assert_snapshot!("channels_rollback_hand_off_to_release", text);
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        requests(&received),
        vec![format!(
            "GET /v1/agents/{AGENT}/channels/production/move-preview?action=rollback&to_release_id={CANDIDATE}"
        )]
    );
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn list_prompts_channels_and_history() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    Mock::given(method("GET"))
        .and(path("/v1/prompts"))
        .and(query_param("q", "support plan"))
        .and(query_param("tags", "support,team-a"))
        .and(query_param("limit", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompts": [prompt_view("prm_planner", "text", Some(7)), prompt_view("prm_safety", "fragment", Some(2))],
            "next_cursor": "WyJ4Il0"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/agents/{AGENT}/channels")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": AGENT,
            "channels": [
                { "agent_id": AGENT, "name": "production", "release_id": RELEASE, "release": { "release_id": RELEASE, "agent_id": AGENT, "name": "av_0042", "status": "production" }, "generation": 12, "protected": true, "materialized": true, "updated_by": { "user_id": null, "api_key_id": null }, "updated_at": "2026-10-03T09:12:44Z" },
                { "agent_id": AGENT, "name": "staging", "release_id": null, "release": null, "generation": 1, "protected": false, "materialized": true, "updated_by": { "user_id": null, "api_key_id": null }, "updated_at": null }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/agents/{AGENT}/channels/production/history")))
        .and(query_param("after", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events": [
                { "generation": 11, "action": "promote", "from_release_id": PREVIOUS, "to_release_id": RELEASE, "actor": { "user_id": "5d0b0e7c-3c1a-4b0e-9d77-1f2e3a4b5c6d", "api_key_id": null }, "approval_ids": [], "evidence_refs": [], "reason": "planner asks for the order id", "created_at": "2026-10-03T09:12:44Z" },
                { "generation": 12, "action": "rollback", "from_release_id": RELEASE, "to_release_id": PREVIOUS, "actor": { "user_id": "5d0b0e7c-3c1a-4b0e-9d77-1f2e3a4b5c6d", "api_key_id": null }, "approval_ids": [], "evidence_refs": [], "reason": null, "created_at": "2026-10-03T10:00:00Z" }
            ],
            "next_after": 12
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = env.run(&[
        "prompts",
        "list",
        "--query",
        "support plan",
        "--tag",
        "support",
        "--tag",
        "team-a",
        "--limit",
        "2",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("prompts_list", stdout(&output));
    let output = env.run(&["channels", "list", "--agent", AGENT]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("channels_list", stdout(&output));
    let output = env.run(&[
        "channels",
        "history",
        "--agent",
        AGENT,
        "production",
        "--after",
        "10",
    ]);
    assert_exit(&output, 0);
    insta::assert_snapshot!("channels_history", stdout(&output));
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn render_server_parity_compares_the_rendered_hash() {
    let server = MockServer::start().await;
    let env = Env::cloud(&server);
    let file = env.write("chat.json", &chat());
    let offline = Env::offline();
    let local = offline.run(&[
        "--format",
        "json",
        "prompts",
        "render",
        &file,
        "--var",
        "question=hi",
    ]);
    assert_exit(&local, 0);
    let local: Value = serde_json::from_slice(&local.stdout).unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/prompts/render"))
        .and(body_partial_json(json!({ "source": { "content": chat() }, "variables": { "question": "hi" }, "strict": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "kind": "chat",
            "rendered_hash": local["rendered_hash"]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/prompts/render"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "kind": "chat",
            "rendered_hash": format!("sha256:{}", "0".repeat(64))
        })))
        .mount(&server)
        .await;
    let args = [
        "--format",
        "json",
        "prompts",
        "render",
        &file,
        "--var",
        "question=hi",
        "--server",
    ];
    let output = env.run(&args);
    assert_exit(&output, 0);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["server"]["matches"], true);
    let output = env.run(&args);
    assert_exit(&output, 1);
}
