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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhoAmIResponse {
    /// Cloud's response shape: `{ org_id, user_id?, api_key_id, api_key_name }`.
    pub org_id: String,
    pub user_id: Option<String>,
    pub api_key_id: String,
    pub api_key_name: String,
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

impl CloudClient {
    /// Construct a new client.
    ///
    /// ```no_run
    /// use agenomic_cloud_client::CloudClient;
    /// use secrecy::SecretString;
    /// let _c = CloudClient::new("https://api.agenomic.dev".into(),
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
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
                    {
                        if attempt < backoffs.len() {
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
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("whoami: HTTP {status}")));
        }
        resp.json::<WhoAmIResponse>()
            .await
            .map_err(|e| CliError::Network(format!("whoami parse: {e}")))
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
    pub async fn create_release(
        &self,
        request: CreateReleaseRequest,
    ) -> CliResult<ReleaseRecord> {
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
            return Err(CliError::Network(format!("create_release: HTTP {status} — {body}")));
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
            return Err(CliError::Network(format!("promote: HTTP {status} — {body}")));
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
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::Network(format!("create_agent: HTTP {status} — {body}")));
        }
        let env: AgentResponse = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("create_agent parse: {e}")))?;
        Ok(env.agent)
    }

    /// `POST /v1/bundles` — upload a bundle as JSON with the archive
    /// base64-encoded. Replaces the older `upload_bundle` octet-stream
    /// endpoint, which never existed on the cloud.
    pub async fn create_bundle(
        &self,
        request: CreateBundleRequest,
    ) -> CliResult<BundleRecord> {
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
            return Err(CliError::Network(format!("create_bundle: HTTP {status} — {body}")));
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
            return Err(CliError::Network(format!("rollback: HTTP {status} — {body}")));
        }
        let env: ReleaseResponseEnvelope = resp
            .json()
            .await
            .map_err(|e| CliError::Network(format!("rollback parse: {e}")))?;
        Ok(env.release)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
                    "agent_id": "a",
                    "bundle_id": "b",
                    "version": "v1",
                    "status": "pending_approval",
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
}
