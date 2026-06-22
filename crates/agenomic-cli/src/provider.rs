//! LLM provider adapter for `agm enrich`. The enrichment domain
//! (`gather` / `build_prompt` / `parse_enrichment` / `apply` in
//! [`crate::enrich`]) is provider-agnostic; this module is the only place that
//! knows how to reach a model. `direct` keeps the pre-existing Anthropic /
//! OpenAI behaviour unchanged; `cloud` targets an internal OpenAI-compatible
//! deployment (Scaleway), configured entirely through the environment.

use agenomic_core::{CliError, CliResult};

const CLOUD_DEFAULT_BASE_URL: &str = "https://api.scaleway.ai/v1";
const CLOUD_DEFAULT_MODEL: &str = "llama-3.3-70b-instruct";

/// Which transport a run uses. `direct` calls the model vendor's public API;
/// `cloud` calls our internal OpenAI-compatible endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Direct,
    Cloud,
}

/// Resolve the kind from the CLI selection. The `--cloud` shortcut and an
/// explicit `cloud` value both pick cloud; everything else stays direct.
pub fn resolve_kind(provider_flag: Option<&str>, cloud_flag: bool) -> ProviderKind {
    let asked_cloud = provider_flag.is_some_and(|p| p.eq_ignore_ascii_case("cloud"));
    if cloud_flag || asked_cloud {
        ProviderKind::Cloud
    } else {
        ProviderKind::Direct
    }
}

/// The vendor a direct run calls: an explicit vendor `--provider` value
/// (back-compat override) wins, otherwise the genome's declared provider.
fn direct_vendor(provider_flag: Option<&str>, genome_provider: &str) -> String {
    match provider_flag {
        Some(p) if !p.eq_ignore_ascii_case("direct") && !p.eq_ignore_ascii_case("cloud") => {
            p.to_string()
        }
        _ => genome_provider.to_string(),
    }
}

/// Endpoint, key, and model for the cloud provider.
pub struct CloudConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// Apply cloud defaults over the (optional) raw values. The API key is
/// mandatory; base URL and model fall back to the Scaleway defaults.
fn cloud_config(
    api_key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
) -> CliResult<CloudConfig> {
    let api_key = api_key.filter(|k| !k.is_empty()).ok_or_else(|| {
        CliError::Schema(
            "AGENOMIC_CLOUD_API_KEY is not set (required by `agm enrich --cloud`); the cloud \
             provider never falls back to ANTHROPIC_API_KEY/OPENAI_API_KEY"
                .into(),
        )
    })?;
    Ok(CloudConfig {
        base_url: present(base_url).unwrap_or_else(|| CLOUD_DEFAULT_BASE_URL.to_string()),
        api_key,
        model: present(model).unwrap_or_else(|| CLOUD_DEFAULT_MODEL.to_string()),
    })
}

fn present(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Read the cloud provider config from `AGENOMIC_CLOUD_*` (base URL and model
/// default; the API key is required).
pub fn cloud_config_from_env() -> CliResult<CloudConfig> {
    cloud_config(
        env_opt("AGENOMIC_CLOUD_API_KEY"),
        env_opt("AGENOMIC_CLOUD_BASE_URL"),
        env_opt("AGENOMIC_CLOUD_MODEL"),
    )
}

/// A ready-to-call enrichment provider.
pub enum Provider {
    Direct { vendor: String, model: String },
    Cloud(CloudConfig),
}

/// Build the provider for this run. `--cloud` / an explicit `cloud` value pick
/// the cloud adapter; otherwise direct, with vendor/model from the flags
/// (back-compat) or the genome.
pub fn select(
    provider_flag: Option<&str>,
    cloud_flag: bool,
    model_flag: Option<&str>,
    genome_provider: &str,
    genome_model: &str,
) -> CliResult<Provider> {
    match resolve_kind(provider_flag, cloud_flag) {
        ProviderKind::Cloud => Ok(Provider::Cloud(cloud_config_from_env()?)),
        ProviderKind::Direct => Ok(Provider::Direct {
            vendor: direct_vendor(provider_flag, genome_provider),
            model: model_flag
                .map(str::to_string)
                .unwrap_or_else(|| genome_model.to_string()),
        }),
    }
}

impl Provider {
    /// The label shown in JSON output (the vendor, or `cloud`).
    pub fn label(&self) -> &str {
        match self {
            Provider::Direct { vendor, .. } => vendor,
            Provider::Cloud(_) => "cloud",
        }
    }

    /// The model the run will call.
    pub fn model(&self) -> &str {
        match self {
            Provider::Direct { model, .. } => model,
            Provider::Cloud(c) => &c.model,
        }
    }

    /// Call the provider's chat API and return the raw text reply.
    pub fn complete(&self, prompt: &str) -> CliResult<String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
        rt.block_on(self.complete_async(prompt))
    }

    async fn complete_async(&self, prompt: &str) -> CliResult<String> {
        let client = http_client()?;
        match self {
            Provider::Direct { vendor, model } => direct_complete(&client, vendor, model, prompt).await,
            Provider::Cloud(c) => {
                openai_chat(&client, &c.base_url, &c.api_key, &c.model, "cloud", prompt).await
            }
        }
    }
}

fn http_client() -> CliResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| CliError::Internal(format!("http client: {e}")))
}

async fn direct_complete(
    client: &reqwest::Client,
    vendor: &str,
    model: &str,
    prompt: &str,
) -> CliResult<String> {
    match vendor {
        "anthropic" => anthropic_chat(client, model, prompt).await,
        "openai" => {
            let key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                CliError::Schema(
                    "OPENAI_API_KEY is not set (required by `agm enrich` for provider openai)"
                        .into(),
                )
            })?;
            openai_chat(client, "https://api.openai.com/v1", &key, model, "openai", prompt).await
        }
        other => Err(CliError::Schema(format!(
            "provider '{other}' is not supported by `agm enrich` (anthropic, openai, cloud); \
             pass --provider/--cloud explicitly"
        ))),
    }
}

async fn anthropic_chat(client: &reqwest::Client, model: &str, prompt: &str) -> CliResult<String> {
    let key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        CliError::Schema(
            "ANTHROPIC_API_KEY is not set (required by `agm enrich` for provider anthropic)".into(),
        )
    })?;
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 4000,
        "messages": [{"role": "user", "content": prompt}],
    });
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await
        .map_err(|e| CliError::Internal(format!("anthropic request: {e}")))?;
    let status = resp.status();
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CliError::Internal(format!("anthropic response: {e}")))?;
    if !status.is_success() {
        return Err(CliError::Internal(format!(
            "anthropic API error ({status}): {}",
            v["error"]["message"].as_str().unwrap_or("unknown")
        )));
    }
    Ok(v["content"][0]["text"].as_str().unwrap_or_default().to_string())
}

async fn openai_chat(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
    label: &str,
    prompt: &str,
) -> CliResult<String> {
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": model,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": prompt}],
    });
    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| CliError::Internal(format!("{label} request: {e}")))?;
    let status = resp.status();
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CliError::Internal(format!("{label} response: {e}")))?;
    if !status.is_success() {
        return Err(CliError::Internal(format!(
            "{label} API error ({status}): {}",
            v["error"]["message"].as_str().unwrap_or("unknown")
        )));
    }
    Ok(v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_direct() {
        assert_eq!(resolve_kind(None, false), ProviderKind::Direct);
    }

    #[test]
    fn cloud_shortcut_selects_cloud() {
        assert_eq!(resolve_kind(None, true), ProviderKind::Cloud);
    }

    #[test]
    fn explicit_cloud_value_selects_cloud() {
        assert_eq!(resolve_kind(Some("cloud"), false), ProviderKind::Cloud);
        assert_eq!(resolve_kind(Some("Cloud"), false), ProviderKind::Cloud);
    }

    #[test]
    fn vendor_value_stays_direct() {
        assert_eq!(resolve_kind(Some("openai"), false), ProviderKind::Direct);
        assert_eq!(resolve_kind(Some("direct"), false), ProviderKind::Direct);
    }

    #[test]
    fn direct_default_uses_genome() {
        let p = select(None, false, None, "anthropic", "claude-sonnet-4-6").unwrap();
        assert_eq!(p.label(), "anthropic");
        assert_eq!(p.model(), "claude-sonnet-4-6");
    }

    #[test]
    fn direct_flags_override_genome() {
        let p = select(Some("openai"), false, Some("gpt-4o"), "anthropic", "claude").unwrap();
        assert_eq!(p.label(), "openai");
        assert_eq!(p.model(), "gpt-4o");
    }

    #[test]
    fn cloud_config_requires_api_key() {
        match cloud_config(None, None, None) {
            Err(e) => assert!(format!("{e}").contains("AGENOMIC_CLOUD_API_KEY")),
            Ok(_) => panic!("expected a missing-key error"),
        }
    }

    #[test]
    fn cloud_config_applies_defaults() {
        let c = cloud_config(Some("scw-secret".into()), None, None).unwrap();
        assert_eq!(c.base_url, CLOUD_DEFAULT_BASE_URL);
        assert_eq!(c.model, CLOUD_DEFAULT_MODEL);
    }

    #[test]
    fn cloud_config_honours_overrides() {
        let c = cloud_config(
            Some("scw-secret".into()),
            Some("https://abc.ifr.fr-par.scaleway.com/v1".into()),
            Some("mistral-nemo-instruct-2407".into()),
        )
        .unwrap();
        assert_eq!(c.base_url, "https://abc.ifr.fr-par.scaleway.com/v1");
        assert_eq!(c.model, "mistral-nemo-instruct-2407");
    }

    #[tokio::test]
    #[ignore = "requires binding a local TCP port for the mock LLM endpoint"]
    async fn cloud_provider_posts_openai_chat_completions() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer scw-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "{\"domain\": \"claims\"}"}}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = CloudConfig {
            base_url: format!("{}/v1", server.uri()),
            api_key: "scw-secret".into(),
            model: "llama-3.3-70b-instruct".into(),
        };
        let reply = Provider::Cloud(cfg).complete_async("prompt").await.unwrap();
        assert_eq!(reply, "{\"domain\": \"claims\"}");
    }
}
