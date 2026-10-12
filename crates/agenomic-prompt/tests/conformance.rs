use agenomic_prompt::canonical::{canonical_json, prompt_digest, sha256_prefixed};
use agenomic_prompt::refs::{PromptRef, RefContext};
use agenomic_prompt::render::{
    render, render_messages, render_text, source, tokenize, validate, FragmentSource, RenderError,
    RenderOptions, Rendered, SecretPolicy, Token, VersionEntry, RENDERER_VERSION,
};
use agenomic_prompt::secrets::{self, SECRET_PATTERN_SET};
use agenomic_prompt::{LoadOptions, PromptBundle};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONSUMER: &str = "rust-cli";
const SUITES: [&str; 6] = [
    "digest",
    "prompts-file-yaml",
    "ref",
    "render",
    "secrets",
    "template",
];
const EXPECTED_VECTORS: usize = 241;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn files_under(root: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(relative, path);
            }
        }
    }
    out
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

struct Vector {
    file: String,
    id: String,
    input: Value,
    expected: Value,
}

fn suite_vectors(suite: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    for (relative, path) in files_under(&vectors_dir().join(suite)) {
        if relative.ends_with(".no-rust.json") {
            continue;
        }
        let vector = read_json(&path);
        assert_eq!(
            vector["schema"], "agenomic.conformance_vector/v1",
            "{relative}"
        );
        assert_eq!(vector["suite"], suite, "{relative}");
        let id = vector["id"].as_str().unwrap().to_string();
        assert!(relative.starts_with(&format!("{id}-")), "{relative}");
        let consumers = vector["consumers"].as_array().unwrap();
        if !consumers.iter().any(|consumer| consumer == CONSUMER) {
            continue;
        }
        out.push(Vector {
            file: format!("{suite}/{relative}"),
            id,
            input: vector["input"].clone(),
            expected: vector["expected"].clone(),
        });
    }
    out
}

fn run_suite(suite: &str, check: fn(&Value, &Value) -> Result<(), String>) -> usize {
    let vectors = suite_vectors(suite);
    let mut failures = Vec::new();
    for vector in &vectors {
        if let Err(message) = check(&vector.input, &vector.expected) {
            failures.push(format!("{} ({}): {message}", vector.id, vector.file));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} {suite} vectors failed:\n{}",
        failures.len(),
        vectors.len(),
        failures.join("\n")
    );
    vectors.len()
}

fn subset(expected: &Value, actual: &Value, what: &str) -> Result<(), String> {
    let Some(expected) = expected.as_object() else {
        return Err(format!("{what}: expected an object, got {expected}"));
    };
    for (member, value) in expected {
        let found = actual.get(member).unwrap_or(&Value::Null);
        if found != value {
            return Err(format!(
                "{what}.{member}: expected {value}, got {found} (actual {actual})"
            ));
        }
    }
    Ok(())
}

fn issue_list(expected: &Value, actual: &Value, what: &str) -> Result<(), String> {
    let (Some(expected), Some(actual)) = (expected.as_array(), actual.as_array()) else {
        return Err(format!(
            "{what}: expected two lists, got {expected} and {actual}"
        ));
    };
    if expected.len() != actual.len() {
        return Err(format!("{what}: expected {expected:?}, got {actual:?}"));
    }
    for (index, (want, got)) in expected.iter().zip(actual).enumerate() {
        subset(want, got, &format!("{what}[{index}]"))?;
    }
    Ok(())
}

fn compare_members(expected: &Value, actual: &Value, skip: &[&str]) -> Result<(), String> {
    let Some(expected) = expected.as_object() else {
        return Err(format!("expected an object, got {expected}"));
    };
    for (member, value) in expected {
        if skip.contains(&member.as_str()) {
            continue;
        }
        let found = actual.get(member).unwrap_or(&Value::Null);
        if member == "warnings" {
            issue_list(value, found, "warnings")?;
        } else if found != value {
            return Err(format!("{member}: expected {value}, got {found}"));
        }
    }
    Ok(())
}

fn compare_error(expected: &Value, actual: &Value) -> Result<(), String> {
    let Some(expected) = expected.as_object() else {
        return Err(format!("expected.error is not an object: {expected}"));
    };
    for (member, value) in expected {
        match member.as_str() {
            "item" | "details" => subset(value, &actual[member], &format!("error.{member}"))?,
            _ => {
                if actual.get(member) != Some(value) {
                    return Err(format!("error.{member}: expected {value}, got {actual}"));
                }
            }
        }
    }
    Ok(())
}

fn expect_ok(expected: &Value) -> Result<bool, String> {
    expected["ok"]
        .as_bool()
        .ok_or_else(|| format!("expected.ok is not a boolean: {expected}"))
}

fn fragment_source(fragments: &Value) -> HashMap<String, VersionEntry> {
    fragments
        .as_object()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, entry)| {
            let prompt_kind = entry
                .get("prompt_kind")
                .and_then(Value::as_str)
                .map(str::to_string);
            let content = entry.get("content").cloned().unwrap_or(Value::Null);
            (
                key,
                VersionEntry {
                    prompt_kind,
                    content,
                },
            )
        })
        .collect()
}

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-05T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn check_bundle_load(input: &Value, expected: &Value) -> Result<(), String> {
    let text = |member: &str| {
        input[member]
            .as_str()
            .ok_or_else(|| format!("{member} is not a string"))
    };
    let options = LoadOptions {
        expected_workspace_id: text("expected_workspace_id")?,
        expected_agent_id: text("expected_agent_id")?,
        expected_bundle_digest: input["expected_bundle_digest"].as_str(),
        expected_manifest_digest: None,
        trust_key: None,
        allow_ungoverned_bundle: false,
        now: fixed_now(),
    };
    match PromptBundle::load(input["bundle"].clone(), &options) {
        Ok(bundle) => {
            if !expect_ok(expected)? {
                return Err("expected a load failure, got a bundle".to_string());
            }
            let actual = json!({
                "ok": true,
                "prompt_bundle_digest": bundle.prompt_bundle_digest(),
                "prompt_manifest_digest": bundle.prompt_manifest_digest(),
                "prompt_refs": bundle.prompt_refs(),
                "managed_slots": bundle.managed_slots(),
            });
            compare_members(expected, &actual, &[])
        }
        Err(error) => {
            if expect_ok(expected)? {
                return Err(format!("unexpected load failure {error:?}"));
            }
            let actual = json!({ "code": error.code, "details": error.details });
            compare_error(&expected["error"], &actual)
        }
    }
}

fn check_digest(input: &Value, expected: &Value) -> Result<(), String> {
    match input["operation"].as_str() {
        Some("digest") => {}
        Some("bundle_load") => return check_bundle_load(input, expected),
        other => return Err(format!("unsupported digest operation {other:?}")),
    }
    let document = &input["document"];
    let result = prompt_digest(document);
    if !expect_ok(expected)? {
        let error = result
            .err()
            .ok_or("expected an AJS failure, got a digest")?;
        let actual = json!({ "code": error.reason, "value_path": error.value_path });
        return subset(&expected["error"]["item"], &actual, "error.item");
    }
    let digest = result.map_err(|error| format!("unexpected AJS failure {error}"))?;
    let actual = json!({
        "ok": true,
        "document_type": document["schema"],
        "canonical": canonical_json(document),
        "digest": digest,
    });
    compare_members(expected, &actual, &[])?;
    if let Some(projection) = input.get("projection") {
        let from = &projection["from"];
        let (projected, cited) = match projection["rule"].as_str() {
            Some("content") => (from["content"].clone(), &from["content_digest"]),
            Some("without_plan_digest") => {
                let mut copy = from.clone();
                copy.as_object_mut()
                    .ok_or("projection source is not an object")?
                    .remove("plan_digest");
                (copy, &from["plan_digest"])
            }
            other => return Err(format!("unknown projection rule {other:?}")),
        };
        if &projected != document || cited != &Value::String(digest) {
            return Err("projection does not reproduce the document or its digest".to_string());
        }
    }
    Ok(())
}

fn check_ref(input: &Value, expected: &Value) -> Result<(), String> {
    let text = input["ref"].as_str().ok_or("ref is not a string")?;
    let context = match input["context"].as_str() {
        Some("management") => RefContext::Management,
        Some("execution") => RefContext::Execution,
        other => return Err(format!("unknown context {other:?}")),
    };
    let workspace = match &input["workspace_id"] {
        Value::Null => None,
        Value::String(text) => Some(Uuid::parse_str(text).map_err(|error| error.to_string())?),
        other => {
            return Err(format!(
                "workspace_id is neither null nor a string: {other}"
            ))
        }
    };
    let outcome = PromptRef::parse(text).and_then(|parsed| {
        parsed.require(context, workspace)?;
        Ok(parsed)
    });
    match outcome {
        Err(error) => {
            if expect_ok(expected)? {
                return Err(format!("unexpected error {error:?}"));
            }
            let actual = json!({ "code": error.code, "reason": error.reason });
            subset(&expected["error"], &actual, "error")
        }
        Ok(parsed) => {
            let (version, alias, workspace_id) = match &parsed {
                PromptRef::PromptId { .. } => (Value::Null, Value::Null, Value::Null),
                PromptRef::Version { version, .. } => (json!(version), Value::Null, Value::Null),
                PromptRef::Alias { alias, .. } => (Value::Null, json!(alias), Value::Null),
                PromptRef::Uri {
                    version,
                    workspace_id,
                    ..
                } => (json!(version), Value::Null, json!(workspace_id)),
            };
            let version_ref = parsed
                .version_ref(workspace)
                .map(|(prompt_id, version)| format!("{prompt_id}:{version}"));
            let actual = json!({
                "ok": true,
                "form": parsed.form(),
                "prompt_id": parsed.prompt_id(),
                "version": version,
                "alias": alias,
                "workspace_id": workspace_id,
                "canonical": parsed.to_string(),
                "version_ref": version_ref,
            });
            compare_members(expected, &actual, &[])
        }
    }
}

fn check_secrets(input: &Value, expected: &Value) -> Result<(), String> {
    let actual = match input["operation"].as_str() {
        Some("scan") => {
            let text = input["text"].as_str().ok_or("text is not a string")?;
            json!({ "ok": true, "findings": secrets::scan(text), "scrubbed": secrets::scrub(text) })
        }
        Some("secret_shaped") => {
            let keys = input["keys"].as_array().ok_or("keys is not a list")?;
            let shaped: Vec<bool> = keys
                .iter()
                .map(|key| key.as_str().is_some_and(secrets::secret_shaped_key))
                .collect();
            json!({ "ok": true, "secret_shaped": shaped })
        }
        Some("scrub_json") => {
            json!({ "ok": true, "scrubbed": secrets::scrub_json(&input["value"]) })
        }
        other => return Err(format!("unsupported secrets operation {other:?}")),
    };
    compare_members(expected, &actual, &[])
}

fn token_json(token: &Token) -> Value {
    match token {
        Token::Literal(text) => json!({ "t": "literal", "text": text }),
        Token::Var { name, offset } => json!({ "t": "var", "name": name, "offset": offset }),
        Token::Include { name, offset } => {
            json!({ "t": "include", "name": name, "offset": offset })
        }
    }
}

fn check_template(input: &Value, expected: &Value) -> Result<(), String> {
    if let Some(template) = input.get("template") {
        let template = template.as_str().ok_or("template is not a string")?;
        return match tokenize(template) {
            Ok(tokens) => {
                if !expect_ok(expected)? {
                    return Err("expected a syntax error, got tokens".to_string());
                }
                let actual = json!({
                    "ok": true,
                    "tokens": tokens.iter().map(token_json).collect::<Vec<_>>(),
                    "source": source(&tokens),
                });
                compare_members(expected, &actual, &[])
            }
            Err(error) => {
                if expect_ok(expected)? {
                    return Err(format!("unexpected syntax error {error:?}"));
                }
                let item = json!({
                    "code": "syntax_error",
                    "syntax": error.syntax,
                    "offset": error.offset,
                    "line": error.line,
                    "column": error.column,
                });
                let actual = json!({ "code": "prompt_template_invalid", "item": item });
                compare_error(&expected["error"], &actual)
            }
        };
    }
    let fragments = fragment_source(&input["fragments"]);
    let report = validate(&input["content"], &fragments);
    match report.to_error() {
        None => {
            if !expect_ok(expected)? {
                return Err(format!("expected a validation error, got {report:?}"));
            }
            let actual = json!({
                "variables": report.variables,
                "warnings": report.warnings,
                "content_digest": report.content_digest,
            });
            compare_members(&expected["validation"], &actual, &[])
        }
        Some(error) => {
            if expect_ok(expected)? {
                return Err(format!("unexpected validation error {:?}", report.errors));
            }
            let actual = json!({ "code": error.code, "item": report.errors[0] });
            compare_error(&expected["error"], &actual)
        }
    }
}

fn render_options(options: &Value) -> Result<RenderOptions, String> {
    let history = match &options["history"] {
        Value::Null => None,
        Value::Array(items) => Some(items.clone()),
        other => return Err(format!("history is neither null nor a list: {other}")),
    };
    let secret_policy = match options["secret_policy"].as_str() {
        Some("off") => SecretPolicy::Off,
        Some("error") => SecretPolicy::Error,
        other => return Err(format!("unknown secret_policy {other:?}")),
    };
    Ok(RenderOptions {
        strict: options["strict"]
            .as_bool()
            .ok_or("strict is not a boolean")?,
        history,
        allow_duplicate_system: options["allow_duplicate_system"]
            .as_bool()
            .ok_or("allow_duplicate_system is not a boolean")?,
        secret_policy,
    })
}

fn rendered_json(rendered: &Rendered) -> Value {
    json!({
        "ok": true,
        "kind": rendered.kind,
        "text": rendered.text,
        "messages": rendered.messages,
        "expanded_template": rendered.expanded_template,
        "rendered_document": rendered.rendered_document,
        "rendered_hash": rendered.rendered_hash,
        "warnings": rendered.warnings,
    })
}

fn check_render(input: &Value, expected: &Value) -> Result<(), String> {
    let fragments = fragment_source(&input["fragments"]);
    let variables: Map<String, Value> = input["variables"]
        .as_object()
        .cloned()
        .ok_or("variables is not an object")?;
    let options = render_options(&input["options"])?;
    let content = &input["content"];
    let source: &dyn FragmentSource = &fragments;
    let result: Result<Rendered, RenderError> = match input["method"].as_str() {
        Some("render") => render(content, &variables, source, &options),
        Some("text") => render_text(content, &variables, source, &options),
        Some("messages") => render_messages(content, &variables, source, &options),
        other => return Err(format!("unknown method {other:?}")),
    };
    match result {
        Ok(rendered) => {
            if !expect_ok(expected)? {
                return Err(format!(
                    "expected a render error, got {}",
                    rendered_json(&rendered)
                ));
            }
            compare_members(expected, &rendered_json(&rendered), &["langchain_parity"])?;
            if prompt_digest(&rendered.rendered_document).ok().as_deref()
                != Some(rendered.rendered_hash.as_str())
            {
                return Err("rendered_hash is not the digest of rendered_document".to_string());
            }
            Ok(())
        }
        Err(error) => {
            if expect_ok(expected)? {
                return Err(format!("unexpected render error {:?}", error.errors));
            }
            let actual = json!({ "code": "prompt_render_error", "item": error.errors[0] });
            compare_error(&expected["error"], &actual)
        }
    }
}

#[test]
fn vendored_vectors_match_the_lock_and_the_manifest() {
    let root = vectors_dir();
    let lock = read_json(&root.join("SPEC_VECTORS.lock"));
    let commit = lock["spec_commit"].as_str().unwrap();
    assert!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{commit}"
    );
    let manifest_bytes = fs::read(root.join("MANIFEST.json")).unwrap();
    assert_eq!(lock["manifest_sha256"], sha256_prefixed(&manifest_bytes));
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest["schema"],
        "agenomic.conformance_vector_manifest/v1"
    );
    assert_eq!(manifest["renderer_version"], RENDERER_VERSION);
    assert_eq!(manifest["secret_patterns"], SECRET_PATTERN_SET);
    let listed: BTreeMap<String, String> =
        serde_json::from_value(manifest["files"].clone()).unwrap();
    let mut vendored = files_under(&root);
    vendored.remove("MANIFEST.json");
    vendored.remove("SPEC_VECTORS.lock");
    let listed_names: BTreeSet<&String> = listed.keys().collect();
    let vendored_names: BTreeSet<&String> = vendored.keys().collect();
    assert_eq!(listed_names, vendored_names);
    for (relative, path) in &vendored {
        assert_eq!(
            listed[relative],
            sha256_prefixed(&fs::read(path).unwrap()),
            "{relative}"
        );
    }
}

#[test]
fn every_suite_is_known_and_every_vector_is_accounted_for() {
    let mut total = 0;
    for (relative, _) in files_under(&vectors_dir()) {
        let Some((suite, _)) = relative.split_once('/') else {
            continue;
        };
        assert!(
            SUITES.contains(&suite),
            "unknown suite {suite} ({relative})"
        );
        total += 1;
    }
    assert_eq!(total, EXPECTED_VECTORS);
}

#[test]
fn digest_suite() {
    assert_eq!(run_suite("digest", check_digest), 28);
}

#[test]
fn ref_suite() {
    assert_eq!(run_suite("ref", check_ref), 54);
}

#[test]
fn secrets_suite() {
    assert_eq!(run_suite("secrets", check_secrets), 14);
}

#[test]
fn template_suite() {
    assert_eq!(run_suite("template", check_template), 69);
}

#[test]
fn render_suite() {
    assert_eq!(run_suite("render", check_render), 65);
}

#[test]
fn yaml_profile_vectors_are_not_for_rust() {
    assert_eq!(
        files_under(&vectors_dir().join("prompts-file-yaml")).len(),
        10
    );
    assert!(suite_vectors("prompts-file-yaml").is_empty());
}
