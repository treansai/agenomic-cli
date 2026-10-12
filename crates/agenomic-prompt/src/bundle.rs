use crate::canonical::{canonical_json, ensure_ajs, prompt_digest, sorted_keys};
use crate::digest::{artifact_set_digest, BUNDLE_SCHEMA, MANIFEST_SCHEMA};
use crate::error::{
    PromptError, BUNDLE_EXPIRED, BUNDLE_INCOMPLETE, BUNDLE_SCOPE_MISMATCH,
    BUNDLE_SIGNATURE_INVALID, BUNDLE_UNGOVERNED, BUNDLE_UNTRUSTED_KEY, MANIFEST_DIGEST_MISMATCH,
    PROMPT_DIGEST_MISMATCH,
};
use crate::refs::{parse_version, version_key};
use crate::render::{FragmentSource, VersionEntry};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, NaiveDateTime, Utc};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const SIGNATURE_ALGORITHM: &str = "ed25519";

const RAW_PEM_HEADER: &str = "-----BEGIN ED25519 PUBLIC KEY-----";
const RAW_PEM_FOOTER: &str = "-----END ED25519 PUBLIC KEY-----";

const REQUIRED_MEMBERS: [(&str, Kind); 9] = [
    ("workspace_id", Kind::String),
    ("agent_id", Kind::String),
    ("source", Kind::Object),
    ("release", Kind::Object),
    ("prompt_manifest_digest", Kind::String),
    ("manifest", Kind::Object),
    ("children", Kind::Object),
    ("prompts", Kind::Object),
    ("prompt_bundle_digest", Kind::String),
];

#[derive(Debug, Clone, Copy)]
enum Kind {
    String,
    Object,
}

impl Kind {
    fn matches(self, value: &Value) -> bool {
        match self {
            Kind::String => value.is_string(),
            Kind::Object => value.is_object(),
        }
    }
}

pub fn verifying_key_from_pem(pem: &str) -> Option<VerifyingKey> {
    if let Ok(key) = VerifyingKey::from_public_key_pem(pem) {
        return Some(key);
    }
    let lines: Vec<&str> = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let [RAW_PEM_HEADER, body @ .., RAW_PEM_FOOTER] = lines.as_slice() else {
        return None;
    };
    let raw = STANDARD.decode(body.concat()).ok()?;
    let bytes = <[u8; 32]>::try_from(raw.as_slice()).ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

pub fn signing_digest(document: &Value) -> [u8; 32] {
    let mut unsigned = document.clone();
    if let Some(map) = unsigned.as_object_mut() {
        map.remove("signature");
    }
    *blake3::hash(canonical_json(&unsigned).as_bytes()).as_bytes()
}

#[derive(Debug, Clone)]
pub struct LoadOptions<'a> {
    pub expected_workspace_id: &'a str,
    pub expected_agent_id: &'a str,
    pub expected_bundle_digest: Option<&'a str>,
    pub expected_manifest_digest: Option<&'a str>,
    pub trust_key: Option<&'a VerifyingKey>,
    pub allow_ungoverned_bundle: bool,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PromptBundle {
    document: Value,
    signature_verified: bool,
}

fn incomplete(message: impl Into<String>, reason: &str) -> PromptError {
    PromptError::new(BUNDLE_INCOMPLETE, message).with_reason(reason)
}

impl PromptBundle {
    pub fn load(document: Value, options: &LoadOptions<'_>) -> Result<Self, PromptError> {
        check_shape(&document)?;
        let signed = document.get("signature").is_some();
        let mut signature_verified = false;
        match (options.trust_key, signed) {
            (Some(key), true) => {
                verify_signature(&document, key)?;
                signature_verified = true;
            }
            _ if options.expected_bundle_digest.is_none() => {
                return Err(PromptError::new(
                    BUNDLE_UNTRUSTED_KEY,
                    "the bundle is neither signed by a trusted key nor pinned by digest",
                ));
            }
            _ => {}
        }
        check_integrity(
            &document,
            options.expected_workspace_id,
            options.expected_agent_id,
            options.expected_bundle_digest,
            options.expected_manifest_digest,
            options.now,
        )?;
        if options.expected_bundle_digest.is_none() && !options.allow_ungoverned_bundle {
            let governance = document.get("governance");
            if governance.and_then(|value| value.get("approved")) != Some(&Value::Bool(true)) {
                return Err(PromptError::new(
                    BUNDLE_UNGOVERNED,
                    "the signed bundle pins a release that is not approved",
                )
                .with_detail(
                    "release_status",
                    governance
                        .and_then(|value| value.get("release_status"))
                        .cloned()
                        .unwrap_or(Value::Null),
                ));
            }
        }
        Ok(Self {
            document,
            signature_verified,
        })
    }

    pub fn verify_exported(
        document: Value,
        expected_workspace_id: &str,
        expected_agent_id: &str,
        trust_key: Option<&VerifyingKey>,
        now: DateTime<Utc>,
    ) -> Result<Self, PromptError> {
        check_shape(&document)?;
        let signature_verified = match trust_key {
            Some(key) => {
                verify_signature(&document, key)?;
                true
            }
            None => false,
        };
        check_integrity(
            &document,
            expected_workspace_id,
            expected_agent_id,
            None,
            None,
            now,
        )?;
        Ok(Self {
            document,
            signature_verified,
        })
    }

    pub fn document(&self) -> &Value {
        &self.document
    }

    pub fn signature_verified(&self) -> bool {
        self.signature_verified
    }

    fn text(&self, member: &str) -> &str {
        self.document
            .get(member)
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn workspace_id(&self) -> &str {
        self.text("workspace_id")
    }

    pub fn agent_id(&self) -> &str {
        self.text("agent_id")
    }

    pub fn prompt_bundle_digest(&self) -> &str {
        self.text("prompt_bundle_digest")
    }

    pub fn prompt_manifest_digest(&self) -> &str {
        self.text("prompt_manifest_digest")
    }

    pub fn member(&self, member: &str) -> Value {
        self.document.get(member).cloned().unwrap_or(Value::Null)
    }

    pub fn prompt_refs(&self) -> Vec<String> {
        object(&self.document, "prompts")
            .map(|map| sorted_keys(map).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn managed_slots(&self) -> Vec<String> {
        self.document
            .get("manifest")
            .and_then(|manifest| object(manifest, "slots"))
            .map(|map| sorted_keys(map).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn slot(&self, slot_path: &str) -> Result<(String, u32, VersionEntry), PromptError> {
        let missing = || {
            PromptError::new(
                "slot_not_in_manifest",
                format!("slot {slot_path} is not in the pinned manifest"),
            )
            .with_detail("slot_path", json!(slot_path))
        };
        let pin = self
            .document
            .get("manifest")
            .and_then(|manifest| object(manifest, "slots"))
            .and_then(|slots| slots.get(slot_path))
            .ok_or_else(missing)?;
        let prompt_id = pin
            .get("prompt_id")
            .and_then(Value::as_str)
            .ok_or_else(missing)?;
        let version = pin
            .get("version")
            .and_then(Value::as_u64)
            .and_then(|version| parse_version(&version.to_string()))
            .ok_or_else(missing)?;
        let entry = self.get(prompt_id, version).ok_or_else(missing)?;
        Ok((prompt_id.to_string(), version, entry))
    }
}

impl FragmentSource for PromptBundle {
    fn get(&self, prompt_id: &str, version: u32) -> Option<VersionEntry> {
        let entry = object(&self.document, "prompts")?.get(&version_key(prompt_id, version))?;
        Some(VersionEntry {
            prompt_kind: entry
                .get("prompt_kind")
                .and_then(Value::as_str)
                .map(str::to_string),
            content: entry.get("content").cloned().unwrap_or(Value::Null),
        })
    }
}

fn object<'a>(value: &'a Value, member: &str) -> Option<&'a Map<String, Value>> {
    value.get(member).and_then(Value::as_object)
}

fn check_shape(document: &Value) -> Result<(), PromptError> {
    if let Err(error) = ensure_ajs(document) {
        return Err(
            incomplete("the bundle is outside the JSON subset", error.reason)
                .with_detail("value_path", json!(error.value_path)),
        );
    }
    let Some(map) = document.as_object() else {
        return Err(incomplete(
            "the bundle is not an object",
            "invalid_field_type",
        ));
    };
    if map.get("schema").and_then(Value::as_str) != Some(BUNDLE_SCHEMA) {
        return Err(incomplete(
            "unsupported bundle schema",
            "unsupported_schema",
        ));
    }
    for (member, kind) in REQUIRED_MEMBERS {
        let Some(value) = map.get(member) else {
            return Err(
                incomplete(format!("missing member {member}"), "missing_field")
                    .with_detail("path", json!(format!("/{member}"))),
            );
        };
        if !kind.matches(value) {
            return Err(incomplete(
                format!("member {member} has the wrong type"),
                "invalid_field_type",
            )
            .with_detail("path", json!(format!("/{member}"))));
        }
    }
    if map.contains_key("signature") && map.get("expires_at").is_none_or(Value::is_null) {
        return Err(
            incomplete("a signed bundle carries no expires_at", "missing_field")
                .with_detail("path", json!("/expires_at")),
        );
    }
    Ok(())
}

fn verify_signature(document: &Value, key: &VerifyingKey) -> Result<(), PromptError> {
    let invalid = |message: &str| PromptError::new(BUNDLE_SIGNATURE_INVALID, message);
    let issuer = document.get("issuer");
    let signature = document.get("signature");
    let well_formed = issuer.and_then(|value| value.get("algorithm"))
        == Some(&json!(SIGNATURE_ALGORITHM))
        && signature.and_then(|value| value.get("algorithm")) == Some(&json!(SIGNATURE_ALGORITHM));
    let value = signature
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str);
    let (true, Some(value)) = (well_formed, value) else {
        return Err(invalid("the bundle signature block is malformed"));
    };
    let raw = STANDARD
        .decode(value)
        .map_err(|_| invalid("the bundle signature is not base64"))?;
    let bytes = <[u8; 64]>::try_from(raw.as_slice())
        .map_err(|_| invalid("the bundle signature is not 64 bytes"))?;
    key.verify_strict(&signing_digest(document), &Signature::from_bytes(&bytes))
        .map_err(|_| invalid("the bundle signature does not verify"))
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    if value.len() != 20 {
        return None;
    }
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ")
        .ok()
        .map(|naive| naive.and_utc())
}

fn check_integrity(
    document: &Value,
    workspace_id: &str,
    agent_id: &str,
    expected_bundle_digest: Option<&str>,
    expected_manifest_digest: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), PromptError> {
    match document.get("expires_at") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let expires_at = value
                .as_str()
                .and_then(parse_timestamp)
                .ok_or_else(|| incomplete("expires_at is not a timestamp", "invalid_field_type"))?;
            if expires_at <= now {
                return Err(PromptError::new(BUNDLE_EXPIRED, "the bundle has expired")
                    .with_detail("expires_at", value.clone()));
            }
        }
    }
    check_prompts(document)?;
    check_artifact_set(document, expected_bundle_digest)?;
    check_manifests(document, expected_manifest_digest)?;
    check_closure(document)?;
    let manifest_agent = document
        .get("manifest")
        .and_then(|manifest| manifest.get("agent_id"))
        .and_then(Value::as_str);
    if document.get("workspace_id").and_then(Value::as_str) != Some(workspace_id)
        || document.get("agent_id").and_then(Value::as_str) != Some(agent_id)
        || manifest_agent != Some(agent_id)
    {
        return Err(PromptError::new(
            BUNDLE_SCOPE_MISMATCH,
            "the bundle belongs to another workspace or agent",
        ));
    }
    Ok(())
}

fn check_prompts(document: &Value) -> Result<(), PromptError> {
    let Some(prompts) = object(document, "prompts") else {
        return Ok(());
    };
    for reference in sorted_keys(prompts) {
        let entry = &prompts[reference];
        let Some(content) = entry.get("content").filter(|value| value.is_object()) else {
            return Err(incomplete(
                format!("prompt entry {reference} is malformed"),
                "invalid_field_type",
            ));
        };
        let expected = entry
            .get("content_digest")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let actual = prompt_digest(content).map_err(|error| {
            incomplete(
                format!("prompt entry {reference} is outside the JSON subset"),
                error.reason,
            )
        })?;
        if actual != expected {
            return Err(PromptError::new(
                PROMPT_DIGEST_MISMATCH,
                format!("the content digest of {reference} does not match"),
            )
            .with_detail("ref", json!(reference))
            .with_detail("expected", json!(expected))
            .with_detail("actual", json!(actual)));
        }
    }
    Ok(())
}

fn check_artifact_set(document: &Value, expected: Option<&str>) -> Result<(), PromptError> {
    let actual = artifact_set_digest(document)
        .map_err(|error| incomplete("the artifact set is outside the JSON subset", error.reason))?;
    let in_file = document.get("prompt_bundle_digest").and_then(Value::as_str);
    for pinned in [in_file, expected].into_iter().flatten() {
        if actual != pinned {
            return Err(PromptError::new(
                PROMPT_DIGEST_MISMATCH,
                "the prompt artifact set digest does not match",
            )
            .with_detail("document", json!("artifact_set"))
            .with_detail("expected", json!(pinned))
            .with_detail("actual", json!(actual)));
        }
    }
    Ok(())
}

fn manifest_ok(manifest: Option<&Value>) -> bool {
    manifest.is_some_and(|manifest| {
        manifest.get("schema").and_then(Value::as_str) == Some(MANIFEST_SCHEMA)
            && manifest.get("slots").is_some_and(Value::is_object)
            && manifest.get("children").is_some_and(Value::is_object)
    })
}

fn check_manifests(document: &Value, expected: Option<&str>) -> Result<(), PromptError> {
    let mut manifests: Vec<(Option<&str>, Option<&Value>, Option<&Value>)> = vec![(
        None,
        document.get("manifest"),
        document.get("prompt_manifest_digest"),
    )];
    if let Some(children) = object(document, "children") {
        for child_id in sorted_keys(children) {
            let child = &children[child_id];
            if !child.is_object() {
                return Err(incomplete(
                    format!("child {child_id} is malformed"),
                    "invalid_field_type",
                ));
            }
            manifests.push((
                Some(child_id.as_str()),
                child.get("manifest"),
                child.get("prompt_manifest_digest"),
            ));
        }
    }
    for (owner, manifest, pinned) in manifests {
        if !manifest_ok(manifest) {
            return Err(incomplete("a manifest is malformed", "invalid_field_type"));
        }
        let actual = manifest
            .map(prompt_digest)
            .transpose()
            .map_err(|error| incomplete("a manifest is outside the JSON subset", error.reason))?;
        if actual.as_ref().map(|digest| json!(digest)).as_ref() != pinned {
            return Err(PromptError::new(
                MANIFEST_DIGEST_MISMATCH,
                "a manifest digest does not match",
            )
            .with_detail("child_agent_id", json!(owner))
            .with_detail("expected", pinned.cloned().unwrap_or(Value::Null))
            .with_detail("actual", json!(actual)));
        }
    }
    if let Some(expected) = expected {
        let actual = document
            .get("prompt_manifest_digest")
            .and_then(Value::as_str);
        if actual != Some(expected) {
            return Err(PromptError::new(
                MANIFEST_DIGEST_MISMATCH,
                "the manifest digest differs from the expected digest",
            )
            .with_detail("expected", json!(expected))
            .with_detail("actual", json!(actual)));
        }
    }
    Ok(())
}

fn number_text(value: &Value) -> String {
    match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn pin_ref(pin: &Value) -> String {
    format!(
        "{}:{}",
        pin.get("prompt_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        pin.get("version").map(number_text).unwrap_or_default()
    )
}

fn closure_gaps(
    manifest: &Value,
    prompts: &Map<String, Value>,
    wanted: &mut BTreeSet<String>,
    missing: &mut BTreeSet<String>,
) {
    let mut pending: Vec<&Value> = object(manifest, "slots")
        .map(|slots| slots.values().filter(|pin| pin.is_object()).collect())
        .unwrap_or_default();
    while let Some(pin) = pending.pop() {
        let reference = pin_ref(pin);
        if !wanted.insert(reference.clone()) {
            continue;
        }
        let entry = prompts.get(&reference);
        let digest_matches = entry
            .and_then(|entry| entry.get("content_digest"))
            .is_some_and(|digest| Some(digest) == pin.get("content_digest"));
        let Some(entry) = entry.filter(|entry| entry.is_object() && digest_matches) else {
            missing.insert(reference);
            continue;
        };
        if let Some(fragments) = entry
            .get("content")
            .and_then(|content| object(content, "fragments"))
        {
            pending.extend(fragments.values().filter(|pin| pin.is_object()));
        }
    }
}

fn check_closure(document: &Value) -> Result<(), PromptError> {
    let empty = Map::new();
    let prompts = object(document, "prompts").unwrap_or(&empty);
    let children = object(document, "children").unwrap_or(&empty);
    let mut wanted = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut reached = BTreeSet::new();
    let mut pending: Vec<&Value> = document.get("manifest").into_iter().collect();
    while let Some(manifest) = pending.pop() {
        closure_gaps(manifest, prompts, &mut wanted, &mut missing);
        let Some(pins) = object(manifest, "children") else {
            continue;
        };
        for (child_id, pin) in pins {
            if !reached.insert(child_id.clone()) {
                continue;
            }
            let child = children.get(child_id);
            let consistent = child.is_some_and(|child| {
                pin.is_object()
                    && child.get("release_id") == pin.get("release_id")
                    && child.get("genome_version") == pin.get("genome_version")
                    && child
                        .get("manifest")
                        .and_then(|manifest| manifest.get("agent_id"))
                        .and_then(Value::as_str)
                        == Some(child_id.as_str())
            });
            match child.and_then(|child| child.get("manifest")) {
                Some(manifest) if consistent => pending.push(manifest),
                _ => {
                    missing.insert(child_id.clone());
                }
            }
        }
    }
    let mut extra: BTreeSet<String> = prompts
        .iter()
        .filter(|(reference, entry)| {
            !wanted.contains(reference.as_str()) || **reference != pin_ref(entry)
        })
        .map(|(reference, _)| reference.clone())
        .collect();
    extra.extend(
        children
            .keys()
            .filter(|child_id| !reached.contains(child_id.as_str()))
            .cloned(),
    );
    if missing.is_empty() && extra.is_empty() {
        return Ok(());
    }
    Err(
        PromptError::new(BUNDLE_INCOMPLETE, "the bundle closure is not exact")
            .with_detail("missing", json!(missing))
            .with_detail("extra", json!(extra)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    const WORKSPACE: &str = "0b6c2f1e-7a44-4c8e-9f1d-2a3b4c5d6e7f";
    const AGENT: &str = "2b1e5c3a-8d4f-4e6a-9b0c-1d2e3f4a5b6c";

    fn content(body: &str) -> Value {
        json!({
            "schema": "agenomic.prompt_content/v1",
            "template_format": "agenomic-fstring/v1",
            "renderer_version": "1",
            "kind": "text",
            "body": body,
            "variables": {},
            "partials": {},
            "output_contract": null,
            "fragments": {},
        })
    }

    fn bundle(approved: bool) -> Value {
        let content = content("Plan the next step.");
        let digest = prompt_digest(&content).unwrap();
        let manifest = json!({
            "schema": MANIFEST_SCHEMA,
            "agent_id": AGENT,
            "slots": { "planner.instructions": { "prompt_id": "prm_plan", "version": 1, "content_digest": digest } },
            "children": {},
        });
        let mut document = json!({
            "schema": BUNDLE_SCHEMA,
            "workspace_id": WORKSPACE,
            "agent_id": AGENT,
            "source": { "channel": "production", "channel_generation": 4 },
            "release": { "release_id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "release_name": "av_0001", "genome_version": null, "bundle_id": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b", "bundle_hash": format!("blake3:{}", "0".repeat(64)), "legacy": false },
            "prompt_manifest_digest": prompt_digest(&manifest).unwrap(),
            "manifest": manifest,
            "children": {},
            "prompts": { "prm_plan:1": { "prompt_id": "prm_plan", "version": 1, "prompt_kind": "text", "content_digest": digest, "content": content } },
            "governance": { "release_status": if approved { "production" } else { "awaiting_approval" }, "channel": "production", "channel_protected": true, "approved": approved },
            "exported_at": "2026-10-04T21:10:00Z",
            "expires_at": "2026-11-03T21:10:00Z",
        });
        document["prompt_bundle_digest"] = json!(artifact_set_digest(&document).unwrap());
        document
    }

    fn sign(mut document: Value, signer: &SigningKey) -> Value {
        document["issuer"] = json!({ "key_id": "orgkey_test", "algorithm": "ed25519" });
        let signature = signer.sign(&signing_digest(&document));
        document["signature"] = json!({
            "algorithm": "ed25519",
            "value": STANDARD.encode(signature.to_bytes()),
            "public_key_pem": "ignored",
        });
        document
    }

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-05T00:00:00Z").unwrap()
    }

    fn options<'a>(key: Option<&'a VerifyingKey>, pin: Option<&'a str>) -> LoadOptions<'a> {
        LoadOptions {
            expected_workspace_id: WORKSPACE,
            expected_agent_id: AGENT,
            expected_bundle_digest: pin,
            expected_manifest_digest: None,
            trust_key: key,
            allow_ungoverned_bundle: false,
            now: now(),
        }
    }

    #[test]
    fn signed_bundle_loads_with_the_trusted_key_and_renders_a_slot() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let key = signer.verifying_key();
        let document = sign(bundle(true), &signer);
        let loaded = PromptBundle::load(document, &options(Some(&key), None)).unwrap();
        assert!(loaded.signature_verified());
        assert_eq!(loaded.managed_slots(), vec!["planner.instructions"]);
        let (prompt_id, version, entry) = loaded.slot("planner.instructions").unwrap();
        assert_eq!((prompt_id.as_str(), version), ("prm_plan", 1));
        assert_eq!(entry.content["body"], "Plan the next step.");
    }

    #[test]
    fn signature_failures_and_missing_authenticity_are_refused() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let signed = sign(bundle(true), &signer);
        let error = PromptBundle::load(signed.clone(), &options(Some(&other), None)).unwrap_err();
        assert_eq!(error.code, BUNDLE_SIGNATURE_INVALID);
        let error = PromptBundle::load(signed.clone(), &options(None, None)).unwrap_err();
        assert_eq!(error.code, BUNDLE_UNTRUSTED_KEY);
        let mut tampered = signed;
        tampered["governance"]["approved"] = json!(false);
        let key = signer.verifying_key();
        let error = PromptBundle::load(tampered, &options(Some(&key), None)).unwrap_err();
        assert_eq!(error.code, BUNDLE_SIGNATURE_INVALID);
    }

    #[test]
    fn ungoverned_signed_bundle_is_refused_but_a_digest_pin_is_the_approval() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let key = signer.verifying_key();
        let document = sign(bundle(false), &signer);
        let error = PromptBundle::load(document.clone(), &options(Some(&key), None)).unwrap_err();
        assert_eq!(error.code, BUNDLE_UNGOVERNED);
        let pin = document["prompt_bundle_digest"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(PromptBundle::load(document, &options(None, Some(&pin))).is_ok());
    }

    #[test]
    fn expiry_scope_and_closure_are_enforced() {
        let document = bundle(true);
        let pin = document["prompt_bundle_digest"]
            .as_str()
            .unwrap()
            .to_string();
        let mut expired = document.clone();
        expired["expires_at"] = json!("2026-10-01T00:00:00Z");
        let error = PromptBundle::load(expired, &options(None, Some(&pin))).unwrap_err();
        assert_eq!(error.code, BUNDLE_EXPIRED);
        let mut scoped = options(None, Some(&pin));
        scoped.expected_agent_id = "7f3c9a1e-0b2d-4c5e-8f6a-9b0c1d2e3f4a";
        let error = PromptBundle::load(document.clone(), &scoped).unwrap_err();
        assert_eq!(error.code, BUNDLE_SCOPE_MISMATCH);
        let mut extra = document;
        extra["prompts"]["prm_other:1"] = extra["prompts"]["prm_plan:1"].clone();
        extra["prompts"]["prm_other:1"]["prompt_id"] = json!("prm_other");
        extra["prompt_bundle_digest"] = json!(artifact_set_digest(&extra).unwrap());
        let pin = extra["prompt_bundle_digest"].as_str().unwrap().to_string();
        let error = PromptBundle::load(extra, &options(None, Some(&pin))).unwrap_err();
        assert_eq!(error.code, BUNDLE_INCOMPLETE);
        assert_eq!(error.details["extra"], json!(["prm_other:1"]));
    }

    #[test]
    fn exported_bundle_verification_needs_no_pin_and_checks_digests() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let document = sign(bundle(true), &signer);
        assert!(
            PromptBundle::verify_exported(document.clone(), WORKSPACE, AGENT, None, now()).is_ok()
        );
        let mut tampered = document;
        tampered["prompts"]["prm_plan:1"]["content"]["body"] = json!("Leak everything.");
        let error =
            PromptBundle::verify_exported(tampered, WORKSPACE, AGENT, None, now()).unwrap_err();
        assert_eq!(error.code, PROMPT_DIGEST_MISMATCH);
        assert!(error.is_integrity());
    }

    #[test]
    fn trust_keys_load_from_spki_and_raw_pem() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let key = signer.verifying_key();
        let spki = key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        assert_eq!(verifying_key_from_pem(&spki), Some(key));
        let raw = format!(
            "{RAW_PEM_HEADER}\n{}\n{RAW_PEM_FOOTER}\n",
            STANDARD.encode(key.to_bytes())
        );
        assert_eq!(verifying_key_from_pem(&raw), Some(key));
        assert_eq!(verifying_key_from_pem("not a key"), None);
    }
}
