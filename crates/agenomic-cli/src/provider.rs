//! LLM provider adapter for `agm enrich`. The enrichment domain
//! (`gather` / `build_prompt` / `parse_enrichment` / `apply` in
//! [`crate::enrich`]) is provider-agnostic; this module is the only place that
//! knows how to reach a model. `direct` keeps the pre-existing Anthropic /
//! OpenAI behaviour unchanged; `cloud` routes through Agenomic Cloud, which
//! authenticates the caller with their Agenomic API key and proxies to the
//! internal model server-side — the CLI never holds the model credentials.

use agenomic_core::{CliError, CliResult};

/// Which transport a run uses. `direct` calls the model vendor's public API;
/// `cloud` calls Agenomic Cloud (which gates access and proxies internally).
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

/// A ready-to-call enrichment provider.
pub enum Provider {
    Direct {
        vendor: String,
        model: String,
    },
    Cloud {
        client: agenomic_cloud_client::CloudClient,
        model: Option<String>,
    },
}

/// Build the provider for this run. `--cloud` / an explicit `cloud` value pick
/// the cloud adapter (building the client lazily, so direct never needs a
/// login); otherwise direct, with vendor/model from the flags (back-compat) or
/// the genome.
pub fn select<F>(
    provider_flag: Option<&str>,
    cloud_flag: bool,
    model_flag: Option<&str>,
    genome_provider: &str,
    genome_model: &str,
    cloud_client: F,
) -> CliResult<Provider>
where
    F: FnOnce() -> CliResult<agenomic_cloud_client::CloudClient>,
{
    match resolve_kind(provider_flag, cloud_flag) {
        ProviderKind::Cloud => Ok(Provider::Cloud {
            client: cloud_client()?,
            model: model_flag.map(str::to_string),
        }),
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
            Provider::Cloud { .. } => "cloud",
        }
    }

    /// The model the run will call (the requested hint for cloud, where the
    /// server makes the final choice).
    pub fn model(&self) -> &str {
        match self {
            Provider::Direct { model, .. } => model,
            Provider::Cloud { model, .. } => model.as_deref().unwrap_or("cloud"),
        }
    }

    /// Call the provider and return the raw text reply.
    pub fn complete(&self, prompt: &str) -> CliResult<String> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
        rt.block_on(self.complete_async(prompt))
    }

    async fn complete_async(&self, prompt: &str) -> CliResult<String> {
        match self {
            Provider::Direct { vendor, model } => {
                direct_complete(&http_client()?, vendor, model, prompt).await
            }
            Provider::Cloud { client, model } => {
                cloud_complete(client, model.clone(), prompt).await
            }
        }
    }
}

async fn cloud_complete(
    client: &agenomic_cloud_client::CloudClient,
    model: Option<String>,
    prompt: &str,
) -> CliResult<String> {
    let resp = client
        .enrich(agenomic_cloud_client::EnrichRequest {
            prompt: prompt.to_string(),
            model,
        })
        .await?;
    Ok(resp.content)
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
        "openai" => openai_chat(client, model, prompt).await,
        other if crate::huggingface::is_huggingface(other) => {
            huggingface_chat(model, prompt).await
        }
        other => Err(CliError::Schema(format!(
            "provider '{other}' is not supported by `agm enrich` (anthropic, openai, huggingface, cloud); \
             pass --provider/--cloud explicitly"
        ))),
    }
}

/// Enrich via Hugging Face text generation. Reuses the shared adapter so token
/// resolution (`HUGGINGFACE_API_TOKEN` / `HF_TOKEN`), endpoint selection,
/// timeouts, and redaction all stay in one place.
async fn huggingface_chat(model: &str, prompt: &str) -> CliResult<String> {
    let cfg = crate::huggingface::HuggingFaceConfig::from_env();
    let model = if model.is_empty() {
        cfg.default_model.clone().ok_or_else(|| {
            CliError::Schema(
                "no Hugging Face model selected: set runtime.model_id, pass --model, or \
                 HUGGINGFACE_DEFAULT_MODEL"
                    .into(),
            )
        })?
    } else {
        model.to_string()
    };
    // JSON enrichment prompts benefit from bounded, non-echoed output.
    let params = serde_json::json!({
        "return_full_text": false,
        "max_new_tokens": 1024,
    });
    let adapter = crate::huggingface::HuggingFaceAdapter::new(cfg)?;
    adapter.generate_text(&model, prompt, Some(&params)).await
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
    Ok(v["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string())
}

async fn openai_chat(client: &reqwest::Client, model: &str, prompt: &str) -> CliResult<String> {
    let key = std::env::var("OPENAI_API_KEY").map_err(|_| {
        CliError::Schema(
            "OPENAI_API_KEY is not set (required by `agm enrich` for provider openai)".into(),
        )
    })?;
    let body = serde_json::json!({
        "model": model,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": prompt}],
    });
    let resp = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(|e| CliError::Internal(format!("openai request: {e}")))?;
    let status = resp.status();
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CliError::Internal(format!("openai response: {e}")))?;
    if !status.is_success() {
        return Err(CliError::Internal(format!(
            "openai API error ({status}): {}",
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

    fn no_cloud() -> CliResult<agenomic_cloud_client::CloudClient> {
        Err(CliError::AuthFailed)
    }

    fn dummy_cloud() -> CliResult<agenomic_cloud_client::CloudClient> {
        Ok(agenomic_cloud_client::CloudClient::new(
            "http://localhost".into(),
            secrecy::SecretString::new("k".into()),
        ))
    }

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
        let p = select(
            None,
            false,
            None,
            "anthropic",
            "claude-sonnet-4-6",
            no_cloud,
        )
        .unwrap();
        assert_eq!(p.label(), "anthropic");
        assert_eq!(p.model(), "claude-sonnet-4-6");
    }

    #[test]
    fn direct_flags_override_genome() {
        let p = select(
            Some("openai"),
            false,
            Some("gpt-4o"),
            "anthropic",
            "claude",
            no_cloud,
        )
        .unwrap();
        assert_eq!(p.label(), "openai");
        assert_eq!(p.model(), "gpt-4o");
    }

    #[test]
    fn cloud_selection_builds_cloud_provider() {
        let p = select(None, true, None, "anthropic", "claude", dummy_cloud).unwrap();
        assert_eq!(p.label(), "cloud");
    }

    #[test]
    fn cloud_selection_propagates_login_error() {
        let result = select(None, true, None, "anthropic", "claude", no_cloud);
        assert!(matches!(result, Err(CliError::AuthFailed)));
    }
}
