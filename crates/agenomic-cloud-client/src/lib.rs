//! Optional HTTP client for Agenomic Cloud.
//!
//! No CLI command requires this client; if a user has not configured a Cloud
//! profile, the binary still does everything locally.

use std::path::Path;
use std::time::Duration;

use agenomic_core::{CliError, CliResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// HTTP client for Agenomic Cloud.
pub struct CloudClient {
    http: reqwest::Client,
    endpoint: String,
    api_key: SecretString,
}

/// `POST /v1/orgs/:org_id/billing/reconcile` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingReconcileReport {
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub subscriptions_checked: u64,
    #[serde(default)]
    pub corrections: Vec<String>,
    #[serde(default)]
    pub events_reprocessed: u64,
}

/// Redacted billing webhook event journal entry (no raw Stripe payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingEventRecord {
    pub stripe_event_id: String,
    pub event_type: String,
    #[serde(default)]
    pub stripe_created_at: Option<String>,
    pub processing_status: String,
    #[serde(default)]
    pub processing_attempts: i64,
    #[serde(default)]
    pub processed_at: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub received_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhoAmIResponse {
    /// Cloud's response shape: `{ org_id, user_id?, api_key_id?, api_key_name,
    /// role?, auth_method? }`. `api_key_id` is `None` for session-auth callers;
    /// `role` and `auth_method` were added in the cloud's PR 1 refactor and are
    /// accepted-but-ignored for forward compatibility.
    pub org_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
    pub api_key_name: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAgentRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentResponse {
    pub agent: AgentRecord,
}

/// Agent as returned by the cloud — mirrors agenomic-core::models::Agent.
/// The PR 1 cloud refactor added slug, domain, and criticality on top of
/// the legacy id/name/description triple.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub bucket_id: Option<String>,
    pub domain: Option<String>,
    pub description: Option<String>,
    /// One of "standard", "sensitive", "regulated_customer_facing",
    /// "life_critical".
    pub criticality: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBundleRequest {
    pub agent_id: String,
    pub version: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_base64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleResponseEnvelope {
    pub bundle: BundleRecord,
}

/// Bundle as returned by the cloud — mirrors agenomic-core::models::Bundle.
/// The PR 1 cloud refactor renamed `hash` to `bundle_hash` and split the
/// legacy free-form `metadata` into structured fields.
#[derive(Debug, Clone, Deserialize)]
pub struct BundleRecord {
    pub id: String,
    pub org_id: String,
    pub agent_id: String,
    pub version: String,
    pub bundle_hash: String,
    pub hash_algorithm: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub genome_summary: serde_json::Value,
    pub lockfile_summary: serde_json::Value,
    /// One of "pending", "valid", "invalid".
    pub validation_status: String,
    pub validation_errors: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadBundleResponse {
    pub bundle_id: String,
    pub logical_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadAtepResponse {
    pub segment_id: String,
    pub events_ingested: u32,
}

// Cloud's POST /v1/releases body. Note: the wire shape carries `version`
// (release version label, free string) and optional `notes`. The legacy
// shape (which embedded an `attestation` jsonb) was never matched by the
// cloud and is removed.
#[derive(Debug, Clone, Serialize)]
pub struct CreateReleaseRequest {
    pub agent_id: String,
    pub bundle_id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseResponseEnvelope {
    pub release: ReleaseRecord,
}

/// Release as returned by the cloud — mirrors agenomic-core::models::AgentRelease.
/// The PR 1 cloud refactor extended ReleaseStatus to 11 variants (draft,
/// candidate, replay_required, replay_passed, replay_failed,
/// awaiting_approval, approved, canary, production, rolled_back,
/// deprecated) and added environment + lineage fields.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseRecord {
    pub id: String,
    pub org_id: String,
    pub agent_id: String,
    pub bundle_id: String,
    pub version: String,
    pub notes: Option<String>,
    pub status: String,
    /// One of "dev", "staging", "canary", "production".
    pub environment: String,
    pub previous_release_id: Option<String>,
    pub created_by_user_id: Option<String>,
    pub approved_at: Option<String>,
    pub promoted_at: Option<String>,
    pub rolled_back_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// Cloud's POST /v1/replay-jobs body. The legacy shape (bundle_id,
// contract_id) didn't match the cloud — the real fields are the agent
// id, an optional release id (so replays can be pinned to a release),
// the trace ids to feed in, and the run mode.
#[derive(Debug, Clone, Serialize)]
pub struct CreateReplayJobRequest {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub trace_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayJobResponseEnvelope {
    pub replay_job: ReplayJobRecord,
}

/// ReplayJob as returned by the cloud — mirrors agenomic-core::models::ReplayJob.
/// PR 1 added baseline/candidate ids, runs_per_trace, budget tracking,
/// and a report_storage_key. Status is one of pending/running/succeeded/
/// failed/cancelled (was completed → succeeded).
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayJobRecord {
    pub id: String,
    pub org_id: String,
    pub agent_id: String,
    pub release_id: Option<String>,
    pub baseline_release_id: Option<String>,
    pub candidate_bundle_id: Option<String>,
    pub status: String,
    pub runs_per_trace: i32,
    #[serde(default)]
    pub trace_ids: Vec<String>,
    /// One of "deterministic", "statistical".
    pub mode: String,
    pub budget_limit_cents: Option<i64>,
    pub cost_accrued_cents: i64,
    pub requested_by_user_id: Option<String>,
    pub requested_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
    pub report_storage_key: Option<String>,
}

/// Per-trace ReplayResult roll-up — what the cloud computes from the
/// per-(trace, run_index) rows the worker records. Mirrors
/// agenomic-core::models::ReplayResultSummary.
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayResultSummary {
    pub replay_job_id: String,
    pub total_runs: i64,
    pub passed_runs: i64,
    pub failed_runs: i64,
    pub errored_runs: i64,
    pub all_passed: bool,
    pub first_recorded_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayReportResponse {
    pub replay_job: ReplayJobRecord,
    /// Aggregate roll-up across the per-trace replay_results rows.
    /// `None` while the worker hasn't recorded any pass yet.
    pub replay_summary: Option<ReplayResultSummary>,
    pub contract_result: Option<serde_json::Value>,
}

// Cloud's POST /v1/attestations body. release_id + replay_job_id are
// the only inputs; everything else is computed server-side.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAttestationRequest {
    pub release_id: String,
    pub replay_job_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationResponseEnvelope {
    pub attestation: AttestationRecord,
}

/// Attestation as returned by the cloud — mirrors
/// agenomic-core::models::Attestation. PR 1 added attestation_type,
/// schema_version, storage_key, content_hash (base64 on the wire),
/// signing_key_id, signature, and made replay_job_id Optional.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationRecord {
    pub id: String,
    pub org_id: String,
    pub release_id: String,
    pub replay_job_id: Option<String>,
    /// Currently always "release"; v1.0 schema reserves room for
    /// other kinds.
    pub attestation_type: String,
    pub schema_version: i32,
    pub storage_key: String,
    /// blake3 of the canonical payload bytes; base64 on the wire.
    pub content_hash: String,
    pub payload: serde_json::Value,
    pub signing_key_id: Option<String>,
    /// Detached signature bytes; `None` while the attestation is
    /// unsigned. Base64 on the wire when present.
    pub signature: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromoteRequest {
    pub environment: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BucketResponseEnvelope {
    pub bucket: BucketRecord,
}

/// Bucket as returned by the cloud — mirrors agenomic-core::models::Bucket.
#[derive(Debug, Clone, Deserialize)]
pub struct BucketRecord {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
    pub content_version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListBucketsResponse {
    pub buckets: Vec<BucketRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBucketRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MoveAgentToBucketRequest<'a> {
    pub bucket_id: Option<&'a str>,
}

/// `POST /v1/enrich` request: the enrichment prompt and an optional model hint
/// (the cloud picks the model otherwise).
#[derive(Debug, Clone, Serialize)]
pub struct EnrichRequest {
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// `POST /v1/enrich` response: the model's raw text reply and the model used.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrichResponse {
    pub content: String,
    #[serde(default)]
    pub model: String,
}

impl CloudClient {
    /// Construct a new client.
    ///
    /// ```no_run
    /// use agenomic_cloud_client::CloudClient;
    /// use secrecy::SecretString;
    /// let _c = CloudClient::new("https://api.agenomic.io".into(),
    ///                           SecretString::new("k".into()));
    /// ```
    pub fn new(endpoint: String, api_key: SecretString) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(format!("agenomic-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client should build");
        Self {
            http,
            endpoint,
            api_key,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.endpoint.trim_end_matches('/'), path)
    }

    fn api_key_header(&self) -> String {
        // Cloud's auth middleware reads the `x-api-key` header; the older
        // `authorization: Bearer …` scheme this client used previously was
        // never wired on the server.
        self.api_key.expose_secret().to_string()
    }

    fn idempotency_key() -> String {
        ulid::Ulid::new().to_string()
    }

    async fn send_with_retry<F, Fut>(&self, mut build: F) -> CliResult<reqwest::Response>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = reqwest::RequestBuilder>,
    {
        let backoffs = [200u64, 800, 3200];
        let mut attempt = 0usize;
        loop {
            let req = build().await;
            let result = req.send().await;
            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status == reqwest::StatusCode::UNAUTHORIZED {
                        return Err(CliError::AuthFailed);
                    }
                    if (status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error())
                        && attempt < backoffs.len()
                    {
                        let retry_after = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .map(|s| s * 1000)
                            .unwrap_or(backoffs[attempt]);
                        tokio::time::sleep(Duration::from_millis(retry_after)).await;
                        attempt += 1;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if attempt < backoffs.len() {
                        tokio::time::sleep(Duration::from_millis(backoffs[attempt])).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(CliError::Network(format!("{e}")));
                }
            }
        }
    }

    /// `GET /v1/whoami`
    pub async fn whoami(&self) -> CliResult<WhoAmIResponse> {
        let url = self.url("/v1/whoami");
        let resp = self
            .send_with_retry(|| async {
                self.http
                    .get(&url)
                    .header("x-api-key", self.api_key_header())
                    .header("accept", "application/json")
            })
            .await?;
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "whoami: HTTP {status} — {body}{hint}",
                body = truncate_for_error(&body)
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CliError::Network(format!("whoami read: {e}")))?;
        serde_json::from_slice::<WhoAmIResponse>(&bytes).map_err(|e| {
            CliError::Network(format!(
                "whoami parse: {e} (content-type: {ct}, body: {body}). \
                 Hint: this usually means the configured endpoint is not the \
                 Agenomic Cloud API gateway — check that `--endpoint` points to \
                 the API service (e.g. https://api.agenomic.io), not the web UI.",
                ct = if content_type.is_empty() {
                    "<none>"
                } else {
                    &content_type
                },
                body = truncate_for_error(&String::from_utf8_lossy(&bytes)),
            ))
        })
    }

    /// `POST /v1/orgs/:org_id/billing/reconcile` — compare the workspace's
    /// local billing projection against live Stripe state and repair
    /// discrepancies. Owner-only server-side.
    pub async fn billing_reconcile(&self, org_id: &str) -> CliResult<BillingReconcileReport> {
        let url = self.url(&format!("/v1/orgs/{org_id}/billing/reconcile"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let url = url.clone();
                let idemp = idemp.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .header("accept", "application/json")
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "billing_reconcile: HTTP {status} — {body}{hint}",
                body = truncate_for_error(&body)
            )));
        }
        resp.json()
            .await
            .map_err(|e| CliError::Network(format!("billing_reconcile parse: {e}")))
    }

    /// `GET /v1/orgs/:org_id/billing/events/:event_id` — inspect one
    /// journaled Stripe webhook event (redacted: no raw payload).
    pub async fn billing_event(
        &self,
        org_id: &str,
        stripe_event_id: &str,
    ) -> CliResult<BillingEventRecord> {
        let url = self.url(&format!(
            "/v1/orgs/{org_id}/billing/events/{stripe_event_id}"
        ));
        let resp = self
            .send_with_retry(|| async {
                self.http
                    .get(&url)
                    .header("x-api-key", self.api_key_header())
                    .header("accept", "application/json")
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "billing_event: HTTP {status} — {body}{hint}",
                body = truncate_for_error(&body)
            )));
        }
        resp.json()
            .await
            .map_err(|e| CliError::Network(format!("billing_event parse: {e}")))
    }

    /// `POST /v1/orgs/:org_id/billing/events/:event_id/retry` — replay one
    /// journaled Stripe webhook event through the idempotent processor.
    pub async fn billing_event_retry(&self, org_id: &str, stripe_event_id: &str) -> CliResult<()> {
        let url = self.url(&format!(
            "/v1/orgs/{org_id}/billing/events/{stripe_event_id}/retry"
        ));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let url = url.clone();
                let idemp = idemp.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .header("accept", "application/json")
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "billing_event_retry: HTTP {status} — {body}{hint}",
                body = truncate_for_error(&body)
            )));
        }
        Ok(())
    }

    /// `GET /v1/buckets`
    ///
    /// ```no_run
    /// # use agenomic_cloud_client::CloudClient;
    /// # use secrecy::SecretString;
    /// # async fn demo() -> agenomic_core::CliResult<()> {
    /// let client = CloudClient::new(
    ///     "https://api.agenomic.io".into(),
    ///     SecretString::new("k".into()),
    /// );
    /// let _ = client.list_buckets().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_buckets(&self) -> CliResult<Vec<BucketRecord>> {
        let url = self.url("/v1/buckets");
        let resp = self
            .send_with_retry(|| async {
                self.http
                    .get(&url)
                    .header("x-api-key", self.api_key_header())
                    .header("accept", "application/json")
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "list_buckets: HTTP {status} — {body}"
            )));
        }
        let env = resp
            .json::<ListBucketsResponse>()
            .await
            .map_err(|e| CliError::Network(format!("list_buckets parse: {e}")))?;
        Ok(env.buckets)
    }

    /// Resolve a bucket by slug via `GET /v1/buckets`.
    ///
    /// ```no_run
    /// # use agenomic_cloud_client::CloudClient;
    /// # use secrecy::SecretString;
    /// # async fn demo() -> agenomic_core::CliResult<()> {
    /// let client = CloudClient::new(
    ///     "https://api.agenomic.io".into(),
    ///     SecretString::new("k".into()),
    /// );
    /// let _ = client.get_bucket_by_slug("default").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_bucket_by_slug(&self, slug: &str) -> CliResult<Option<BucketRecord>> {
        let buckets = self.list_buckets().await?;
        Ok(buckets.into_iter().find(|bucket| bucket.slug == slug))
    }

    /// `POST /v1/buckets`
    ///
    /// ```no_run
    /// # use agenomic_cloud_client::{CloudClient, CreateBucketRequest};
    /// # use secrecy::SecretString;
    /// # async fn demo() -> agenomic_core::CliResult<()> {
    /// let client = CloudClient::new(
    ///     "https://api.agenomic.io".into(),
    ///     SecretString::new("k".into()),
    /// );
    /// let _ = client.create_bucket(CreateBucketRequest {
    ///     name: "default".into(),
    ///     slug: Some("default".into()),
    ///     description: None,
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_bucket(&self, request: CreateBucketRequest) -> CliResult<BucketRecord> {
        let url = self.url("/v1/buckets");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "create_bucket: HTTP {status} — {body}"
            )));
        }
        let env = resp
            .json::<BucketResponseEnvelope>()
            .await
            .map_err(|e| CliError::Network(format!("create_bucket parse: {e}")))?;
        Ok(env.bucket)
    }

    /// Upload a bundle archive (`.tar.zst`).
    pub async fn upload_bundle(
        &self,
        agent_id: &str,
        archive: &Path,
    ) -> CliResult<UploadBundleResponse> {
        let url = self.url(&format!("/v1/agents/{agent_id}/bundles"));
        let bytes = std::fs::read(archive).map_err(|e| agenomic_core::io_at(archive, e))?;
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let bytes = bytes.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .header("content-type", "application/octet-stream")
                        .body(bytes)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("upload_bundle: HTTP {status}")));
        }
        resp.json::<UploadBundleResponse>()
            .await
            .map_err(|e| CliError::Network(format!("upload_bundle parse: {e}")))
    }

    /// Upload an ATEP segment file.
    pub async fn upload_atep_segment(
        &self,
        agent_id: &str,
        segment: &Path,
    ) -> CliResult<UploadAtepResponse> {
        let url = self.url(&format!("/v1/agents/{agent_id}/atep"));
        let bytes = std::fs::read(segment).map_err(|e| agenomic_core::io_at(segment, e))?;
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let bytes = bytes.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .header("content-type", "application/x-atep-segment")
                        .body(bytes)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("upload_atep: HTTP {status}")));
        }
        resp.json::<UploadAtepResponse>()
            .await
            .map_err(|e| CliError::Network(format!("upload_atep parse: {e}")))
    }

    /// `POST /v1/releases` — create a release pinning bundle to agent at version.
    pub async fn create_release(&self, request: CreateReleaseRequest) -> CliResult<ReleaseRecord> {
        let url = self.url("/v1/releases");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "create_release: HTTP {status} — {body}"
            )));
        }
        let env: ReleaseResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_release parse: {e}")))?;
        Ok(env.release)
    }

    /// `POST /v1/replay-jobs` — enqueue a replay job for an agent.
    pub async fn create_replay_job(
        &self,
        request: CreateReplayJobRequest,
    ) -> CliResult<ReplayJobRecord> {
        let url = self.url("/v1/replay-jobs");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "create_replay_job: HTTP {status} — {body}"
            )));
        }
        let env: ReplayJobResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_replay_job parse: {e}")))?;
        Ok(env.replay_job)
    }

    /// `GET /v1/replay-jobs/:id/report` — fetch the report for a replay job.
    pub async fn get_replay_report(&self, job_id: &str) -> CliResult<ReplayReportResponse> {
        let url = self.url(&format!("/v1/replay-jobs/{job_id}/report"));
        let resp = self
            .send_with_retry(|| async {
                self.http
                    .get(&url)
                    .header("x-api-key", self.api_key_header())
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "get_replay_report: HTTP {status} — {body}"
            )));
        }
        resp.json::<ReplayReportResponse>()
            .await
            .map_err(|e| CliError::Network(format!("get_replay_report parse: {e}")))
    }

    /// `POST /v1/releases/:id/promote` — promote an approved release.
    pub async fn promote_release(&self, release_id: &str) -> CliResult<ReleaseRecord> {
        let url = self.url(&format!("/v1/releases/{release_id}/promote"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&serde_json::json!({}))
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "promote: HTTP {status} — {body}"
            )));
        }
        let env: ReleaseResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("promote parse: {e}")))?;
        Ok(env.release)
    }

    /// `POST /v1/attestations` — sign a release with a replay job's evidence.
    pub async fn create_attestation(
        &self,
        request: CreateAttestationRequest,
    ) -> CliResult<AttestationRecord> {
        let url = self.url("/v1/attestations");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "create_attestation: HTTP {status} — {body}"
            )));
        }
        let env: AttestationResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_attestation parse: {e}")))?;
        Ok(env.attestation)
    }

    /// `POST /v1/agents` — create a new agent in the caller's org.
    pub async fn create_agent(&self, request: CreateAgentRequest) -> CliResult<AgentRecord> {
        let url = self.url("/v1/agents");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .header("accept", "application/json")
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "create_agent: HTTP {status} — {body}{hint}",
                body = truncate_for_error(&body)
            )));
        }
        let env: AgentResponse = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_agent parse: {e}")))?;
        Ok(env.agent)
    }

    /// `POST /v1/agents/:id/move-to-bucket`
    ///
    /// ```no_run
    /// # use agenomic_cloud_client::CloudClient;
    /// # use secrecy::SecretString;
    /// # async fn demo() -> agenomic_core::CliResult<()> {
    /// let client = CloudClient::new(
    ///     "https://api.agenomic.io".into(),
    ///     SecretString::new("k".into()),
    /// );
    /// let _ = client
    ///     .move_agent_to_bucket("agent-id", Some("bucket-id"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn move_agent_to_bucket(
        &self,
        agent_id: &str,
        bucket_id: Option<&str>,
    ) -> CliResult<AgentRecord> {
        let url = self.url(&format!("/v1/agents/{agent_id}/move-to-bucket"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = MoveAgentToBucketRequest { bucket_id };
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "move_agent_to_bucket: HTTP {status} — {body}"
            )));
        }
        let env: AgentResponse = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("move_agent_to_bucket parse: {e}")))?;
        Ok(env.agent)
    }

    /// `POST /v1/bundles` — upload a bundle as JSON with the archive
    /// base64-encoded. Replaces the older `upload_bundle` octet-stream
    /// endpoint, which never existed on the cloud.
    pub async fn create_bundle(&self, request: CreateBundleRequest) -> CliResult<BundleRecord> {
        let url = self.url("/v1/bundles");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "create_bundle: HTTP {status} — {body}"
            )));
        }
        let env: BundleResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_bundle parse: {e}")))?;
        Ok(env.bundle)
    }

    /// `POST /v1/releases/:id/rollback` — request rollback of a release.
    pub async fn rollback_release(&self, release_id: &str) -> CliResult<ReleaseRecord> {
        let url = self.url(&format!("/v1/releases/{release_id}/rollback"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&serde_json::json!({}))
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!(
                "rollback: HTTP {status} — {body}"
            )));
        }
        let env: ReleaseResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("rollback parse: {e}")))?;
        Ok(env.release)
    }

    /// `POST /v1/enrich` — run the enrichment LLM pass against the cloud's
    /// internal model. The cloud authenticates the caller with their Agenomic
    /// API key and gates access server-side; the model credentials never reach
    /// the CLI.
    pub async fn enrich(&self, request: EnrichRequest) -> CliResult<EnrichResponse> {
        let url = self.url("/v1/enrich");
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let idemp = idemp.clone();
                let url = url.clone();
                let request = request.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("x-api-key", self.api_key_header())
                        .header("idempotency-key", idemp)
                        .json(&request)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let hint = endpoint_hint(status, &body);
            return Err(CliError::Network(format!(
                "enrich: HTTP {status} — {}{hint}",
                truncate_for_error(&body)
            )));
        }
        resp.json::<EnrichResponse>()
            .await
            .map_err(|e| CliError::Network(format!("enrich parse: {e}")))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptListQuery {
    pub query: Option<String>,
    pub tags: Vec<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSelector {
    Channel(String),
    Release(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MovePreview {
    Promote { release_id: String },
    Rollback { to_release_id: Option<String> },
}

#[derive(Debug, Clone)]
pub struct CloudResponse {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub bytes: Vec<u8>,
}

pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn path_with_query(path: &str, pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return path.to_string();
    }
    let query: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect();
    format!("{path}?{}", query.join("&"))
}

fn refused(status: reqwest::StatusCode, body: &[u8]) -> CliError {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let envelope = parsed.as_ref().and_then(|value| value.get("error"));
    match envelope
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_str())
    {
        Some(code) => {
            let mut message = envelope
                .and_then(|error| error.get("message"))
                .and_then(|message| message.as_str())
                .unwrap_or_default()
                .to_string();
            if let Some(reason) = envelope
                .and_then(|error| error.get("details"))
                .and_then(|details| details.get("reason"))
                .and_then(|reason| reason.as_str())
            {
                message.push_str(&format!(" [reason: {reason}]"));
            }
            CliError::CloudRefused {
                code: code.to_string(),
                status: status.as_u16(),
                message,
            }
        }
        None => {
            let text = String::from_utf8_lossy(body);
            CliError::CloudRefused {
                code: "http_error".to_string(),
                status: status.as_u16(),
                message: format!("{}{}", excerpt(&text), endpoint_hint(status, &text)),
            }
        }
    }
}

fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "<empty body>".to_string();
    }
    let mut out: String = trimmed.chars().take(240).collect();
    if out.len() < trimmed.len() {
        out.push_str("...");
    }
    out
}

impl CloudClient {
    pub async fn send_bytes(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
        if_match: Option<u64>,
        idempotency_key: Option<String>,
    ) -> CliResult<CloudResponse> {
        let url = self.url(path);
        let resp = self
            .send_with_retry(|| {
                let mut request = self
                    .http
                    .request(method.clone(), &url)
                    .header("x-api-key", self.api_key_header())
                    .header("accept", "application/json");
                if let Some(revision) = if_match {
                    request = request.header("if-match", format!("\"{revision}\""));
                }
                if let Some(key) = &idempotency_key {
                    request = request.header("idempotency-key", key.clone());
                }
                if let Some(body) = body {
                    request = request.json(body);
                }
                async move { request }
            })
            .await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CliError::Network(format!("{method} {path} read: {e}")))?
            .to_vec();
        if !status.is_success() {
            return Err(refused(status, &bytes));
        }
        Ok(CloudResponse {
            status,
            headers,
            bytes,
        })
    }

    pub async fn send_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
        if_match: Option<u64>,
        idempotency_key: Option<String>,
    ) -> CliResult<(
        reqwest::StatusCode,
        reqwest::header::HeaderMap,
        serde_json::Value,
    )> {
        let response = self
            .send_bytes(method.clone(), path, body, if_match, idempotency_key)
            .await?;
        let value = if response.bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&response.bytes).map_err(|e| {
                let text = String::from_utf8_lossy(&response.bytes);
                CliError::Network(format!(
                    "{method} {path} parse: {e} (body: {}){}",
                    excerpt(&text),
                    endpoint_hint(response.status, &text)
                ))
            })?
        };
        Ok((response.status, response.headers, value))
    }

    async fn get_json(&self, path: &str) -> CliResult<serde_json::Value> {
        Ok(self
            .send_json(reqwest::Method::GET, path, None, None, None)
            .await?
            .2)
    }

    async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> CliResult<(reqwest::StatusCode, serde_json::Value)> {
        let (status, _, value) = self
            .send_json(reqwest::Method::POST, path, Some(body), None, None)
            .await?;
        Ok((status, value))
    }

    pub async fn list_prompts(&self, query: &PromptListQuery) -> CliResult<serde_json::Value> {
        let mut pairs = Vec::new();
        if let Some(text) = &query.query {
            pairs.push(("q", text.clone()));
        }
        if !query.tags.is_empty() {
            pairs.push(("tags", query.tags.join(",")));
        }
        if let Some(limit) = query.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(cursor) = &query.cursor {
            pairs.push(("cursor", cursor.clone()));
        }
        self.get_json(&path_with_query("/v1/prompts", &pairs)).await
    }

    pub async fn get_prompt(&self, prompt_id: &str) -> CliResult<serde_json::Value> {
        self.get_json(&format!("/v1/prompts/{}", encode_component(prompt_id)))
            .await
    }

    pub async fn get_prompt_version(
        &self,
        prompt_id: &str,
        version: u32,
        include_fragments: bool,
    ) -> CliResult<serde_json::Value> {
        let path = format!(
            "/v1/prompts/{}/versions/{version}",
            encode_component(prompt_id)
        );
        let pairs: Vec<(&str, String)> = if include_fragments {
            vec![("include", "fragments".to_string())]
        } else {
            Vec::new()
        };
        self.get_json(&path_with_query(&path, &pairs)).await
    }

    pub async fn list_prompt_versions(
        &self,
        prompt_id: &str,
        include_content: bool,
        cursor: Option<&str>,
    ) -> CliResult<serde_json::Value> {
        let path = format!("/v1/prompts/{}/versions", encode_component(prompt_id));
        let mut pairs = Vec::new();
        if include_content {
            pairs.push(("include", "content".to_string()));
        }
        if let Some(cursor) = cursor {
            pairs.push(("cursor", cursor.to_string()));
        }
        self.get_json(&path_with_query(&path, &pairs)).await
    }

    pub async fn resolve_prompt_ref(&self, reference: &str) -> CliResult<serde_json::Value> {
        Ok(self
            .post_json(
                "/v1/prompts/resolve",
                &serde_json::json!({ "ref": reference }),
            )
            .await?
            .1)
    }

    pub async fn create_prompt(&self, body: &serde_json::Value) -> CliResult<serde_json::Value> {
        Ok(self.post_json("/v1/prompts", body).await?.1)
    }

    pub async fn publish_prompt_version(
        &self,
        prompt_id: &str,
        body: &serde_json::Value,
    ) -> CliResult<(reqwest::StatusCode, serde_json::Value)> {
        self.post_json(
            &format!("/v1/prompts/{}/versions", encode_component(prompt_id)),
            body,
        )
        .await
    }

    pub async fn render_prompt(&self, body: &serde_json::Value) -> CliResult<serde_json::Value> {
        Ok(self.post_json("/v1/prompts/render", body).await?.1)
    }

    pub async fn export_prompt_bundle(
        &self,
        agent_id: &str,
        selector: &AgentSelector,
        expires_in_days: Option<u32>,
    ) -> CliResult<(serde_json::Value, Vec<u8>)> {
        let mut pairs = vec![match selector {
            AgentSelector::Channel(name) => ("channel", name.clone()),
            AgentSelector::Release(release_id) => ("release_id", release_id.clone()),
        }];
        if let Some(days) = expires_in_days {
            pairs.push(("expires_in_days", days.to_string()));
        }
        let path = path_with_query(
            &format!("/v1/agents/{}/prompt-bundle", encode_component(agent_id)),
            &pairs,
        );
        let response = self
            .send_bytes(reqwest::Method::GET, &path, None, None, None)
            .await?;
        let value = serde_json::from_slice(&response.bytes)
            .map_err(|e| CliError::Network(format!("export_prompt_bundle parse: {e}")))?;
        Ok((value, response.bytes))
    }

    pub async fn list_channels(&self, agent_id: &str) -> CliResult<serde_json::Value> {
        self.get_json(&format!(
            "/v1/agents/{}/channels",
            encode_component(agent_id)
        ))
        .await
    }

    pub async fn channel_history(
        &self,
        agent_id: &str,
        channel: &str,
        after: Option<i64>,
        limit: Option<u32>,
    ) -> CliResult<serde_json::Value> {
        let mut pairs = Vec::new();
        if let Some(after) = after {
            pairs.push(("after", after.to_string()));
        }
        if let Some(limit) = limit {
            pairs.push(("limit", limit.to_string()));
        }
        let path = format!(
            "/v1/agents/{}/channels/{}/history",
            encode_component(agent_id),
            encode_component(channel)
        );
        self.get_json(&path_with_query(&path, &pairs)).await
    }

    pub async fn channel_move_preview(
        &self,
        agent_id: &str,
        channel: &str,
        preview: &MovePreview,
    ) -> CliResult<serde_json::Value> {
        let pairs = match preview {
            MovePreview::Promote { release_id } => vec![
                ("action", "promote".to_string()),
                ("release_id", release_id.clone()),
            ],
            MovePreview::Rollback { to_release_id } => {
                let mut pairs = vec![("action", "rollback".to_string())];
                if let Some(release_id) = to_release_id {
                    pairs.push(("to_release_id", release_id.clone()));
                }
                pairs
            }
        };
        let path = format!(
            "/v1/agents/{}/channels/{}/move-preview",
            encode_component(agent_id),
            encode_component(channel)
        );
        self.get_json(&path_with_query(&path, &pairs)).await
    }
}

/// Trim long bodies for inclusion in error strings. We keep enough to
/// identify the response shape (HTML doctype, JSON error envelope, plain
/// text), but not so much that a streamed HTML login page floods the
/// terminal.
fn truncate_for_error(body: &str) -> String {
    const MAX: usize = 240;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "<empty body>".to_string();
    }
    if trimmed.len() <= MAX {
        return trimmed.to_string();
    }
    format!("{}… (+{} bytes)", &trimmed[..MAX], trimmed.len() - MAX)
}

/// Build the "is your endpoint right?" hint for non-success responses
/// whose shape strongly suggests the request landed on the web UI
/// rather than the API gateway. Common symptoms:
///   * HTML body (Next.js 404 / login page rendered by the dashboard)
///   * 405 from a redirect that turned POST into POST /login
///   * 404 with an HTML body
fn endpoint_hint(status: reqwest::StatusCode, body: &str) -> String {
    let looks_like_html = body.trim_start().starts_with("<!DOCTYPE")
        || body.trim_start().starts_with("<html")
        || body.contains("_next/static");
    if looks_like_html || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        "\nHint: this response looks like it came from the web UI, not the \
         API gateway. Verify that `--endpoint` points to the cloud API \
         service (typically https://api.<your-domain>), not the dashboard. \
         The cloud's web origin needs a `/v1/*` rewrite to the API gateway \
         if you want a single hostname to serve both."
            .to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn enrich_posts_prompt_and_returns_content() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/enrich"))
            .and(header("x-api-key", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": "{\"domain\": \"claims\"}",
                "model": "llama-3.3-70b-instruct"
            })))
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("secret".into()));
        let r = c
            .enrich(EnrichRequest {
                prompt: "p".into(),
                model: None,
            })
            .await
            .unwrap();
        assert_eq!(r.content, "{\"domain\": \"claims\"}");
        assert_eq!(r.model, "llama-3.3-70b-instruct");
    }

    #[tokio::test]
    async fn whoami_returns_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/whoami"))
            .and(header("x-api-key", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "org_id": "00000000-0000-0000-0000-000000000001",
                "user_id": "00000000-0000-0000-0000-000000000002",
                "api_key_id": "00000000-0000-0000-0000-000000000003",
                "api_key_name": "dev"
            })))
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("secret".into()));
        let r = c.whoami().await.unwrap();
        assert_eq!(r.api_key_name, "dev");
        assert_eq!(
            r.api_key_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000003")
        );
    }

    /// Cloud returns `api_key_id: null` for session-auth callers and
    /// includes additional `role` / `auth_method` fields. The CLI must
    /// accept the full forward-compatible shape — historically it required
    /// `api_key_id` to be a string and choked on null.
    #[tokio::test]
    async fn whoami_accepts_session_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "org_id": "00000000-0000-0000-0000-000000000001",
                "user_id": "00000000-0000-0000-0000-000000000002",
                "api_key_id": null,
                "api_key_name": "session",
                "role": "owner",
                "auth_method": "session"
            })))
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let r = c.whoami().await.unwrap();
        assert!(r.api_key_id.is_none());
        assert_eq!(r.api_key_name, "session");
        assert_eq!(r.role.as_deref(), Some("owner"));
        assert_eq!(r.auth_method.as_deref(), Some("session"));
    }

    /// HTML responses (a misrouted endpoint hitting the web UI) produce a
    /// useful diagnostic instead of "error decoding response body".
    #[tokio::test]
    async fn whoami_parse_failure_surfaces_body_and_hint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "<!DOCTYPE html><html><body>login</body></html>".as_bytes(),
                "text/html; charset=utf-8",
            ))
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let err = c.whoami().await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("whoami parse"),
            "expected parse error, got: {msg}"
        );
        assert!(
            msg.contains("text/html"),
            "expected content-type in error, got: {msg}"
        );
        assert!(
            msg.contains("Hint"),
            "expected endpoint hint in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn unauthorized_no_retry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("bad".into()));
        let r = c.whoami().await;
        assert!(matches!(r, Err(CliError::AuthFailed)));
    }

    #[tokio::test]
    async fn create_release_unwraps_envelope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/releases"))
            .and(header("x-api-key", "s"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "release": {
                    "id": "00000000-0000-0000-0000-000000000010",
                    "org_id": "00000000-0000-0000-0000-000000000001",
                    "agent_id": "a",
                    "bundle_id": "b",
                    "version": "v1",
                    "status": "pending_approval",
                    "environment": "dev",
                    "notes": null,
                    "approved_at": null,
                    "promoted_at": null,
                    "created_at": "2026-05-04T00:00:00Z",
                    "updated_at": "2026-05-04T00:00:00Z"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let r = c
            .create_release(CreateReleaseRequest {
                agent_id: "a".into(),
                bundle_id: "b".into(),
                version: "v1".into(),
                notes: None,
            })
            .await
            .unwrap();
        assert_eq!(r.version, "v1");
        assert_eq!(r.status, "pending_approval");
    }

    #[tokio::test]
    async fn send_json_sends_the_key_and_a_quoted_if_match() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/things/1"))
            .and(header("x-api-key", "s"))
            .and(header("if-match", "\"7\""))
            .and(header("idempotency-key", "k1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"8\"")
                    .set_body_json(serde_json::json!({ "revision": 8 })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let (status, headers, body) = c
            .send_json(
                reqwest::Method::PUT,
                "/v1/things/1",
                Some(&serde_json::json!({})),
                Some(7),
                Some("k1".into()),
            )
            .await
            .unwrap();
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(headers.get("etag").unwrap(), "\"8\"");
        assert_eq!(body["revision"], 8);
    }

    #[tokio::test]
    async fn coded_error_envelope_becomes_cloud_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prompts/prm_x/versions"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": {
                    "code": "prompt_version_conflict",
                    "message": "parent_version is stale",
                    "details": { "reason": "stale_parent", "latest_version": 4 }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let error = c
            .publish_prompt_version("prm_x", &serde_json::json!({}))
            .await
            .unwrap_err();
        match &error {
            CliError::CloudRefused {
                code,
                status,
                message,
            } => {
                assert_eq!(code, "prompt_version_conflict");
                assert_eq!(*status, 409);
                assert!(message.contains("stale_parent"), "{message}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(error.exit_code().as_i32(), 21);
    }

    #[tokio::test]
    async fn move_preview_is_a_get_with_the_action_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/agents/a1/channels/production/move-preview"))
            .and(wiremock::matchers::query_param("action", "rollback"))
            .and(wiremock::matchers::query_param("to_release_id", "r0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "action": "rollback" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let preview = c
            .channel_move_preview(
                "a1",
                "production",
                &MovePreview::Rollback {
                    to_release_id: Some("r0".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(preview["action"], "rollback");
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(
            path_with_query(
                "/v1/prompts",
                &[("q", "a b&c".into()), ("tags", "x,y".into())]
            ),
            "/v1/prompts?q=a%20b%26c&tags=x%2Cy"
        );
        assert_eq!(path_with_query("/v1/prompts", &[]), "/v1/prompts");
    }
}
