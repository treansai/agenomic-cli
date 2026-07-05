//! Hugging Face provider integration for the Agenomic CLI.
//!
//! This module is the single place that knows how to reach Hugging Face. It is
//! deliberately self-contained and provider-agnostic at the edges: it exposes a
//! small [`HuggingFaceConfig`] (loaded from the environment) and a
//! [`HuggingFaceAdapter`] that validates credentials, resolves model metadata
//! from the Hub, and runs text-generation / feature-extraction (embeddings)
//! through either the public Inference API or a configured Inference Endpoint.
//!
//! ## Security
//!
//! The token is held in a [`SecretString`] and is **never** rendered into logs,
//! traces, reports, lockfiles, or error messages. Every fallible call routes
//! its error text through [`HuggingFaceConfig::redact`] so that even if an
//! upstream library were to echo the token it is scrubbed before it leaves this
//! module. The lockfile metadata produced by [`lock_model`] pins reproducibility
//! information (revision, resolved commit, content hashes) and a **redacted**
//! endpoint reference — never the URL's credentials or the token.

use std::time::Duration;

use agenomic_core::{CliError, CliResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Canonical provider name written into genomes, lockfiles, and traces.
pub const CANONICAL: &str = "huggingface";

/// Accepted provider aliases (matched case-insensitively, `-`/`_` normalised).
pub const ALIASES: &[&str] = &["huggingface", "hf", "hugging_face"];

/// Default request timeout when `HUGGINGFACE_TIMEOUT_SECONDS` is unset.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

/// Hub base URL used for `whoami` and model-metadata resolution.
pub const DEFAULT_API_BASE: &str = "https://huggingface.co";

/// Serverless Inference API base used when no Inference Endpoint is configured.
pub const DEFAULT_INFERENCE_BASE: &str = "https://api-inference.huggingface.co";

/// Normalise a provider string to the canonical Hugging Face name, or `None`
/// when it is not a Hugging Face alias.
///
/// ```
/// use agenomic_cli::huggingface::normalize;
/// assert_eq!(normalize("HF"), Some("huggingface"));
/// assert_eq!(normalize("hugging-face"), Some("huggingface"));
/// assert_eq!(normalize("Hugging_Face"), Some("huggingface"));
/// assert_eq!(normalize("openai"), None);
/// ```
pub fn normalize(provider: &str) -> Option<&'static str> {
    let p = provider.trim().to_ascii_lowercase().replace('-', "_");
    match p.as_str() {
        "huggingface" | "hugging_face" | "hf" => Some(CANONICAL),
        _ => None,
    }
}

/// True when `provider` names Hugging Face under any accepted alias.
pub fn is_huggingface(provider: &str) -> bool {
    normalize(provider).is_some()
}

/// Resolved Hugging Face configuration, sourced from the environment.
///
/// Construction never fails; a missing token is tolerated so that
/// offline/no-network flows (validate, diff, build) work without credentials.
/// Calls that genuinely need the token use [`HuggingFaceConfig::require_token`],
/// which returns a clear, secret-free error.
pub struct HuggingFaceConfig {
    token: Option<SecretString>,
    /// Optional Inference Endpoint URL (overrides the serverless Inference API).
    pub endpoint_url: Option<String>,
    /// Optional organization / user namespace.
    pub organization: Option<String>,
    /// Optional default model id used when a command omits one.
    pub default_model: Option<String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Hub API base (overridable for tests; defaults to [`DEFAULT_API_BASE`]).
    pub api_base: String,
}

impl HuggingFaceConfig {
    /// Load configuration from the environment.
    ///
    /// Token precedence: `HUGGINGFACE_API_TOKEN`, then `HF_TOKEN`. Optional
    /// settings: `HUGGINGFACE_ENDPOINT_URL`, `HUGGINGFACE_ORG`,
    /// `HUGGINGFACE_DEFAULT_MODEL`, `HUGGINGFACE_TIMEOUT_SECONDS`.
    pub fn from_env() -> Self {
        let token = std::env::var("HUGGINGFACE_API_TOKEN")
            .ok()
            .or_else(|| std::env::var("HF_TOKEN").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| SecretString::new(s.into_boxed_str()));

        let timeout_secs = std::env::var("HUGGINGFACE_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS);

        HuggingFaceConfig {
            token,
            endpoint_url: env_nonempty("HUGGINGFACE_ENDPOINT_URL"),
            organization: env_nonempty("HUGGINGFACE_ORG"),
            default_model: env_nonempty("HUGGINGFACE_DEFAULT_MODEL"),
            timeout: Duration::from_secs(timeout_secs),
            api_base: DEFAULT_API_BASE.to_string(),
        }
    }

    /// True when a non-empty token is configured.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Borrow the token, or a clear secret-free error when it is absent.
    pub fn require_token(&self) -> CliResult<&SecretString> {
        self.token.as_ref().ok_or_else(|| {
            CliError::Schema(
                "no Hugging Face token configured: set HUGGINGFACE_API_TOKEN or HF_TOKEN".into(),
            )
        })
    }

    /// The inference base for this config: a configured Inference Endpoint URL,
    /// otherwise the serverless Inference API.
    pub fn inference_base(&self) -> &str {
        self.endpoint_url
            .as_deref()
            .unwrap_or(DEFAULT_INFERENCE_BASE)
    }

    /// Scrub the configured token from arbitrary text. A no-op when no token is
    /// set. Used on every error path so a leaked token can never escape.
    pub fn redact(&self, text: impl Into<String>) -> String {
        let mut text = text.into();
        if let Some(tok) = &self.token {
            let secret = tok.expose_secret();
            if !secret.is_empty() {
                text = text.replace(secret, "***");
            }
        }
        // Defensively scrub any `hf_...`-shaped token the upstream may echo.
        redact_hf_tokens(&text)
    }

    #[cfg(test)]
    pub fn for_test(token: Option<&str>, api_base: &str) -> Self {
        HuggingFaceConfig {
            token: token.map(|t| SecretString::new(t.to_string().into_boxed_str())),
            endpoint_url: None,
            organization: None,
            default_model: None,
            timeout: Duration::from_secs(5),
            api_base: api_base.to_string(),
        }
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Replace anything that looks like a Hugging Face access token (`hf_…`) with a
/// redacted marker. Conservative: only the well-known `hf_` prefix is matched so
/// ordinary identifiers are left intact.
pub fn redact_hf_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("hf_") {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let token_len = tail
            .char_indices()
            .take_while(|(i, c)| *i == 0 || c.is_ascii_alphanumeric() || *c == '_')
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .unwrap_or(3);
        // Only treat it as a token when there is real entropy after the prefix.
        if token_len > 8 {
            out.push_str("hf_***");
        } else {
            out.push_str(&tail[..token_len]);
        }
        rest = &tail[token_len..];
    }
    out.push_str(rest);
    out
}

/// Model metadata resolved from the Hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelMetadata {
    /// Canonical model id, e.g. `mistralai/Mistral-7B-Instruct-v0.3`.
    pub model_id: String,
    /// Requested revision (branch/tag/commit), e.g. `main`.
    pub revision: String,
    /// Resolved commit SHA when the Hub reports one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_commit: Option<String>,
    /// Pipeline tag / task, e.g. `text-generation`, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Whether the model is gated/private (affects reproducibility guarantees).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
}

impl ModelMetadata {
    /// BLAKE3 hash over the canonical JSON of this metadata. Stable across runs
    /// and machines; used as the lockfile `metadata_hash`.
    pub fn metadata_hash(&self) -> String {
        let canon = serde_json::json!({
            "model_id": self.model_id,
            "revision": self.revision,
            "resolved_commit": self.resolved_commit,
            "task": self.task,
        });
        blake3_hex(canon.to_string().as_bytes())
    }
}

/// The result of a `provider test` connectivity check.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionCheck {
    pub provider: String,
    pub authenticated: bool,
    /// Hub-reported account name when authenticated (never the token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Resolved metadata for the default/selected model, when one was checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelMetadata>,
    /// True when an Inference Endpoint URL is configured (value never shown).
    pub endpoint_configured: bool,
}

/// A reproducible lockfile `model:` block for a Hugging Face model.
///
/// Mirrors `agent.lock.yaml :: model`, with the Hugging Face reproducibility
/// fields added. Never contains a token; the endpoint is reduced to a host
/// reference plus a hash so the URL itself (which may carry a query secret) is
/// not pinned verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockModel {
    pub provider: String,
    pub model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_hash: Option<String>,
}

/// Build the reproducible lockfile `model:` block from resolved metadata, the
/// optional endpoint URL, and the genome's model parameters.
///
/// `parameters` is the genome's `runtime.parameters` map (or any deterministic
/// JSON); it is hashed, not stored verbatim, so it stays compact and
/// order-independent via canonical serialization.
pub fn lock_model(
    meta: &ModelMetadata,
    endpoint_url: Option<&str>,
    parameters: Option<&serde_json::Value>,
) -> LockModel {
    let (endpoint_ref, endpoint_hash) = match endpoint_url {
        Some(url) if !url.is_empty() => (
            Some(redacted_endpoint_ref(url)),
            Some(blake3_hex(url.as_bytes())),
        ),
        _ => (None, None),
    };
    let parameter_hash = parameters
        .filter(|p| !p.is_null())
        .map(|p| blake3_hex(canonical_json(p).as_bytes()));

    LockModel {
        provider: CANONICAL.to_string(),
        model_id: meta.model_id.clone(),
        revision: Some(meta.revision.clone()),
        resolved_commit: meta.resolved_commit.clone(),
        task: meta.task.clone(),
        endpoint_ref,
        endpoint_hash,
        metadata_hash: Some(meta.metadata_hash()),
        parameter_hash,
    }
}

/// Reduce an endpoint URL to a non-secret reference: `scheme://host[/path]`,
/// dropping any userinfo, query, or fragment that could carry credentials.
pub fn redacted_endpoint_ref(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("unknown");
            let scheme = u.scheme();
            let path = u.path();
            if path.is_empty() || path == "/" {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}{path}")
            }
        }
        // Unparseable: never echo it back; just mark that one was provided.
        Err(_) => "endpoint://configured".to_string(),
    }
}

/// Adapter that performs network calls against Hugging Face.
pub struct HuggingFaceAdapter {
    config: HuggingFaceConfig,
    http: reqwest::Client,
}

impl HuggingFaceAdapter {
    /// Build an adapter from config, constructing a timeout-bounded client.
    pub fn new(config: HuggingFaceConfig) -> CliResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| CliError::Internal(config.redact(format!("http client: {e}"))))?;
        Ok(HuggingFaceAdapter { config, http })
    }

    /// Borrow the underlying config (token stays sealed).
    pub fn config(&self) -> &HuggingFaceConfig {
        &self.config
    }

    fn bearer(&self) -> CliResult<String> {
        Ok(format!(
            "Bearer {}",
            self.config.require_token()?.expose_secret()
        ))
    }

    /// Validate the configured token against the Hub `whoami` endpoint.
    pub async fn validate_credentials(&self) -> CliResult<WhoAmI> {
        let url = format!("{}/api/whoami-v2", self.config.api_base);
        let resp = self
            .http
            .get(&url)
            .header("authorization", self.bearer()?)
            .send()
            .await
            .map_err(|e| {
                CliError::Network(self.config.redact(format!("huggingface whoami: {e}")))
            })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::AuthFailed);
        }
        if !status.is_success() {
            return Err(CliError::Network(
                self.config
                    .redact(format!("huggingface whoami failed ({status}): {body}")),
            ));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| CliError::Network(self.config.redact(format!("whoami parse: {e}"))))?;
        Ok(WhoAmI {
            name: v["name"].as_str().map(str::to_string),
            organizations: v["orgs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|o| o["name"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Resolve model metadata (revision, resolved commit, task) from the Hub.
    ///
    /// Works without a token for public models; a token is sent when present so
    /// gated/private models resolve too.
    pub async fn resolve_model_metadata(
        &self,
        model_id: &str,
        revision: Option<&str>,
    ) -> CliResult<ModelMetadata> {
        let revision = revision.unwrap_or("main");
        let url = format!(
            "{}/api/models/{model_id}/revision/{revision}",
            self.config.api_base
        );
        let mut req = self.http.get(&url);
        if self.config.has_token() {
            req = req.header("authorization", self.bearer()?);
        }
        let resp = req.send().await.map_err(|e| {
            CliError::Network(
                self.config
                    .redact(format!("huggingface model metadata: {e}")),
            )
        })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::AuthFailed);
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::Schema(format!(
                "huggingface model not found: {model_id}@{revision}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Network(self.config.redact(format!(
                "huggingface model metadata failed ({status}): {body}"
            ))));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| CliError::Network(self.config.redact(format!("metadata parse: {e}"))))?;
        Ok(ModelMetadata {
            model_id: v["id"].as_str().unwrap_or(model_id).to_string(),
            revision: revision.to_string(),
            resolved_commit: v["sha"].as_str().map(str::to_string),
            task: v["pipeline_tag"].as_str().map(str::to_string),
            private: v["private"].as_bool(),
        })
    }

    /// Run text generation for `model` and return the generated text.
    pub async fn generate_text(
        &self,
        model: &str,
        prompt: &str,
        parameters: Option<&serde_json::Value>,
    ) -> CliResult<String> {
        let url = format!("{}/models/{model}", self.config.inference_base());
        let mut body = serde_json::json!({ "inputs": prompt });
        if let Some(params) = parameters {
            if !params.is_null() {
                body["parameters"] = params.clone();
            }
        }
        let v = self.post_inference(&url, &body).await?;
        // The Inference API returns either an array of {generated_text} or a
        // single object; tolerate both shapes.
        let text = v
            .get(0)
            .and_then(|x| x.get("generated_text"))
            .or_else(|| v.get("generated_text"))
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(text)
    }

    /// Compute embeddings (feature extraction) for `inputs`.
    pub async fn embeddings(&self, model: &str, inputs: &[String]) -> CliResult<Vec<Vec<f64>>> {
        let url = format!("{}/models/{model}", self.config.inference_base());
        let body = serde_json::json!({ "inputs": inputs });
        let v = self.post_inference(&url, &body).await?;
        let arr = v.as_array().ok_or_else(|| {
            CliError::Network("huggingface embeddings: unexpected response shape".into())
        })?;
        let mut out = Vec::with_capacity(arr.len());
        for row in arr {
            let vals = row
                .as_array()
                .ok_or_else(|| {
                    CliError::Network("huggingface embeddings: row was not an array".into())
                })?
                .iter()
                .filter_map(|n| n.as_f64())
                .collect();
            out.push(vals);
        }
        Ok(out)
    }

    async fn post_inference(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> CliResult<serde_json::Value> {
        let resp = self
            .http
            .post(url)
            .header("authorization", self.bearer()?)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                CliError::Network(self.config.redact(format!("huggingface inference: {e}")))
            })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::AuthFailed);
        }
        if !status.is_success() {
            return Err(CliError::Network(self.config.redact(format!(
                "huggingface inference failed ({status}): {text}"
            ))));
        }
        serde_json::from_str(&text)
            .map_err(|e| CliError::Network(self.config.redact(format!("inference parse: {e}"))))
    }
}

/// Hub account identity, returned by `whoami`. Never carries the token.
#[derive(Debug, Clone, Serialize)]
pub struct WhoAmI {
    pub name: Option<String>,
    pub organizations: Vec<String>,
}

fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

/// Deterministic JSON serialization (object keys sorted) for stable hashing.
fn canonical_json(v: &serde_json::Value) -> String {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    sort(v).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_all_aliases() {
        for alias in [
            "huggingface",
            "HF",
            "hf",
            "Hugging_Face",
            "hugging-face",
            " HuggingFace ",
        ] {
            assert_eq!(normalize(alias), Some(CANONICAL), "alias: {alias}");
            assert!(is_huggingface(alias));
        }
        assert_eq!(normalize("openai"), None);
        assert_eq!(normalize("anthropic"), None);
        assert!(!is_huggingface("openai"));
    }

    #[test]
    fn redacts_configured_token() {
        let cfg = HuggingFaceConfig::for_test(Some("hf_abcdef1234567890"), DEFAULT_API_BASE);
        let msg = cfg.redact("request to api with token hf_abcdef1234567890 failed");
        assert!(!msg.contains("hf_abcdef1234567890"));
        assert!(msg.contains("***"));
    }

    #[test]
    fn redacts_hf_shaped_tokens_without_config() {
        let scrubbed = redact_hf_tokens("auth: hf_QWERTYuiop1234567890 done");
        assert!(!scrubbed.contains("QWERTYuiop1234567890"));
        assert!(scrubbed.contains("hf_***"));
        // Short non-token strings are left alone.
        assert_eq!(redact_hf_tokens("hf_x is fine"), "hf_x is fine");
    }

    #[test]
    fn endpoint_ref_strips_credentials_and_query() {
        let r = redacted_endpoint_ref("https://user:pass@my-endpoint.hf.space/v1/x?token=secret");
        assert!(r.starts_with("https://my-endpoint.hf.space"));
        assert!(!r.contains("secret"));
        assert!(!r.contains("pass"));
    }

    #[test]
    fn lock_model_pins_reproducibility_fields_and_hashes_params() {
        let meta = ModelMetadata {
            model_id: "mistralai/Mistral-7B-Instruct-v0.3".into(),
            revision: "main".into(),
            resolved_commit: Some("e0bc86c23ce5aae1db576c8cca6f06f1f73af2db".into()),
            task: Some("text-generation".into()),
            private: Some(false),
        };
        let params = serde_json::json!({ "temperature": 0.2, "max_tokens": 1024 });
        let lock = lock_model(
            &meta,
            Some("https://my-endpoint.hf.space/v1"),
            Some(&params),
        );
        assert_eq!(lock.provider, "huggingface");
        assert_eq!(
            lock.resolved_commit.as_deref(),
            Some(meta.resolved_commit.as_deref().unwrap())
        );
        assert_eq!(lock.task.as_deref(), Some("text-generation"));
        assert!(lock
            .endpoint_ref
            .as_deref()
            .unwrap()
            .starts_with("https://my-endpoint.hf.space"));
        assert!(lock.endpoint_hash.is_some());
        assert!(lock.metadata_hash.is_some());
        assert!(lock.parameter_hash.is_some());
    }

    #[test]
    fn parameter_hash_is_order_independent() {
        let meta = ModelMetadata {
            model_id: "m".into(),
            revision: "main".into(),
            resolved_commit: None,
            task: None,
            private: None,
        };
        let a = serde_json::json!({ "a": 1, "b": 2 });
        let b = serde_json::json!({ "b": 2, "a": 1 });
        let la = lock_model(&meta, None, Some(&a));
        let lb = lock_model(&meta, None, Some(&b));
        assert_eq!(la.parameter_hash, lb.parameter_hash);
    }

    #[tokio::test]
    async fn validate_credentials_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/whoami-v2"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer hf_test",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "name": "alice", "orgs": [{"name": "acme"}] }),
                ),
            )
            .mount(&server)
            .await;

        let cfg = HuggingFaceConfig::for_test(Some("hf_test"), &server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let who = adapter.validate_credentials().await.unwrap();
        assert_eq!(who.name.as_deref(), Some("alice"));
        assert_eq!(who.organizations, vec!["acme".to_string()]);
    }

    #[tokio::test]
    async fn validate_credentials_unauthorized_maps_to_auth_failed() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/whoami-v2"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let cfg = HuggingFaceConfig::for_test(Some("hf_bad"), &server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let err = adapter.validate_credentials().await.unwrap_err();
        assert!(matches!(err, CliError::AuthFailed));
    }

    #[tokio::test]
    async fn resolve_metadata_extracts_commit_and_task() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/models/mistralai/Mistral-7B-Instruct-v0.3/revision/main",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "mistralai/Mistral-7B-Instruct-v0.3",
                    "sha": "e0bc86c23ce5aae1db576c8cca6f06f1f73af2db",
                    "pipeline_tag": "text-generation",
                    "private": false
                })),
            )
            .mount(&server)
            .await;
        let cfg = HuggingFaceConfig::for_test(None, &server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let meta = adapter
            .resolve_model_metadata("mistralai/Mistral-7B-Instruct-v0.3", Some("main"))
            .await
            .unwrap();
        assert_eq!(
            meta.resolved_commit.as_deref(),
            Some("e0bc86c23ce5aae1db576c8cca6f06f1f73af2db")
        );
        assert_eq!(meta.task.as_deref(), Some("text-generation"));
    }

    #[tokio::test]
    async fn resolve_metadata_not_found_is_schema_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let cfg = HuggingFaceConfig::for_test(None, &server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let err = adapter
            .resolve_model_metadata("nope/nope", Some("main"))
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Schema(_)));
    }

    #[tokio::test]
    async fn generate_text_returns_completion() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/models/gpt2"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    { "generated_text": "hello world" }
                ])),
            )
            .mount(&server)
            .await;
        let mut cfg = HuggingFaceConfig::for_test(Some("hf_test"), &server.uri());
        cfg.endpoint_url = Some(server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let out = adapter.generate_text("gpt2", "hi", None).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test]
    async fn inference_error_does_not_leak_token() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(500)
                    .set_body_string("upstream error referencing hf_secrettoken123456 oops"),
            )
            .mount(&server)
            .await;
        let mut cfg = HuggingFaceConfig::for_test(Some("hf_secrettoken123456"), &server.uri());
        cfg.endpoint_url = Some(server.uri());
        let adapter = HuggingFaceAdapter::new(cfg).unwrap();
        let err = adapter.generate_text("gpt2", "hi", None).await.unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("hf_secrettoken123456"), "token leaked: {msg}");
    }
}
