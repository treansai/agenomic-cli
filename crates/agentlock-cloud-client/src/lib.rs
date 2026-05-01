//! Optional HTTP client for AgentLock Cloud.
//!
//! No CLI command requires this client; if a user has not configured a Cloud
//! profile, the binary still does everything locally.

use std::path::Path;
use std::time::Duration;

use agentlock_core::{CliError, CliResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// HTTP client for AgentLock Cloud.
pub struct CloudClient {
    http: reqwest::Client,
    endpoint: String,
    api_key: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhoAmIResponse {
    pub user_id: String,
    pub email: Option<String>,
    pub org: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReleaseRequest {
    pub agent_id: String,
    pub bundle_id: String,
    #[serde(default)]
    pub attestation: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResponse {
    pub release_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReplayJobRequest {
    pub agent_id: String,
    pub bundle_id: String,
    #[serde(default)]
    pub contract_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayJobResponse {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReportResponse {
    pub job_id: String,
    pub report: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteRequest {
    pub environment: String,
}

impl CloudClient {
    /// Construct a new client.
    ///
    /// ```no_run
    /// use agentlock_cloud_client::CloudClient;
    /// use secrecy::SecretString;
    /// let _c = CloudClient::new("https://api.agentlock.dev".into(),
    ///                           SecretString::new("k".into()));
    /// ```
    pub fn new(endpoint: String, api_key: SecretString) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(format!("agentlock-cli/{}", env!("CARGO_PKG_VERSION")))
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

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key.expose_secret())
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
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error()
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
                    .header("authorization", self.auth_header())
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
        let bytes = std::fs::read(archive)
            .map_err(|e| agentlock_core::io_at(archive, e))?;
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let bytes = bytes.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("authorization", self.auth_header())
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
        let bytes = std::fs::read(segment)
            .map_err(|e| agentlock_core::io_at(segment, e))?;
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let bytes = bytes.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("authorization", self.auth_header())
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

    pub async fn create_release(
        &self,
        request: CreateReleaseRequest,
    ) -> CliResult<ReleaseResponse> {
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
                        .header("authorization", self.auth_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("create_release: HTTP {status}")));
        }
        resp.json::<ReleaseResponse>()
            .await
            .map_err(|e| CliError::Network(format!("create_release parse: {e}")))
    }

    pub async fn create_replay_job(
        &self,
        request: CreateReplayJobRequest,
    ) -> CliResult<ReplayJobResponse> {
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
                        .header("authorization", self.auth_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!(
                "create_replay_job: HTTP {status}"
            )));
        }
        resp.json::<ReplayJobResponse>()
            .await
            .map_err(|e| CliError::Network(format!("create_replay_job parse: {e}")))
    }

    pub async fn get_replay_report(&self, job_id: &str) -> CliResult<ReplayReportResponse> {
        let url = self.url(&format!("/v1/replay-jobs/{job_id}/report"));
        let resp = self
            .send_with_retry(|| async {
                self.http
                    .get(&url)
                    .header("authorization", self.auth_header())
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!(
                "get_replay_report: HTTP {status}"
            )));
        }
        resp.json::<ReplayReportResponse>()
            .await
            .map_err(|e| CliError::Network(format!("get_replay_report parse: {e}")))
    }

    pub async fn promote_release(
        &self,
        release_id: &str,
        request: PromoteRequest,
    ) -> CliResult<ReleaseResponse> {
        let url = self.url(&format!("/v1/releases/{release_id}/promote"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let req = request.clone();
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("authorization", self.auth_header())
                        .header("idempotency-key", idemp)
                        .json(&req)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("promote: HTTP {status}")));
        }
        resp.json::<ReleaseResponse>()
            .await
            .map_err(|e| CliError::Network(format!("promote parse: {e}")))
    }

    pub async fn rollback_release(&self, release_id: &str) -> CliResult<ReleaseResponse> {
        let url = self.url(&format!("/v1/releases/{release_id}/rollback"));
        let idemp = Self::idempotency_key();
        let resp = self
            .send_with_retry(|| {
                let idemp = idemp.clone();
                let url = url.clone();
                async move {
                    self.http
                        .post(&url)
                        .header("authorization", self.auth_header())
                        .header("idempotency-key", idemp)
                }
            })
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(CliError::Network(format!("rollback: HTTP {status}")));
        }
        resp.json::<ReleaseResponse>()
            .await
            .map_err(|e| CliError::Network(format!("rollback parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn whoami_returns_user() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/whoami"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_id": "u1",
                "email": "a@b.com",
                "org": "acme"
            })))
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("secret".into()));
        let r = c.whoami().await.unwrap();
        assert_eq!(r.user_id, "u1");
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
    async fn idempotency_key_present_on_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/releases"))
            .and(header("authorization", "Bearer s"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "release_id": "r1",
                    "status": "created"
                })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let c = CloudClient::new(server.uri(), SecretString::new("s".into()));
        let r = c
            .create_release(CreateReleaseRequest {
                agent_id: "a".into(),
                bundle_id: "b".into(),
                attestation: None,
            })
            .await
            .unwrap();
        assert_eq!(r.release_id, "r1");
    }
}
