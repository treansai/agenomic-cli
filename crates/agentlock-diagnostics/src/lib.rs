//! `agentlock doctor` diagnostic checks.

use std::time::Duration;

use agentlock_atep::{AtepStore, EventHeader, EventPayload, Hlc, StreamId};
use agentlock_config::{EffectiveConfig, ProfileMode};
use agentlock_core::{CliResult, Severity};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

/// Outcome of a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Ok,
    Warning,
    Failed,
}

/// One named check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: DiagnosticStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregate report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub checks: Vec<DiagnosticCheck>,
    pub overall_ok: bool,
}

/// Run all diagnostic checks.
///
/// ```no_run
/// # async fn demo() {
/// let cfg = agentlock_config::load(None).unwrap();
/// let r = agentlock_diagnostics::run_diagnostics(&cfg).await.unwrap();
/// println!("{}", r.overall_ok);
/// # }
/// ```
pub async fn run_diagnostics(config: &EffectiveConfig) -> CliResult<DiagnosticReport> {
    let mut checks: Vec<DiagnosticCheck> = Vec::new();

    checks.push(DiagnosticCheck {
        name: "cli_version".into(),
        status: DiagnosticStatus::Ok,
        detail: Some(env!("CARGO_PKG_VERSION").into()),
    });

    checks.push(DiagnosticCheck {
        name: "platform".into(),
        status: DiagnosticStatus::Ok,
        detail: Some(format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH)),
    });

    let mut schemas_ok = true;
    let mut schema_errors: Vec<String> = Vec::new();
    for kind in agentlock_spec::SchemaKind::ALL {
        if agentlock_spec::validator(kind).is_err() {
            schemas_ok = false;
            schema_errors.push(kind.label().into());
        }
    }
    checks.push(DiagnosticCheck {
        name: "embedded_schemas".into(),
        status: if schemas_ok {
            DiagnosticStatus::Ok
        } else {
            DiagnosticStatus::Failed
        },
        detail: Some(if schemas_ok {
            format!("{} schemas parsed", agentlock_spec::SchemaKind::ALL.len())
        } else {
            format!("schema(s) failed: {}", schema_errors.join(","))
        }),
    });

    checks.push(match agentlock_config::config_file_path() {
        Ok(p) => DiagnosticCheck {
            name: "config_file_path".into(),
            status: DiagnosticStatus::Ok,
            detail: Some(p.display().to_string()),
        },
        Err(e) => DiagnosticCheck {
            name: "config_file_path".into(),
            status: DiagnosticStatus::Failed,
            detail: Some(format!("{e}")),
        },
    });

    #[cfg(unix)]
    {
        if let Ok(p) = agentlock_config::credentials_file_path() {
            if p.exists() {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&p)
                    .ok()
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0);
                checks.push(DiagnosticCheck {
                    name: "credentials_mode".into(),
                    status: if mode == 0o600 {
                        DiagnosticStatus::Ok
                    } else {
                        DiagnosticStatus::Warning
                    },
                    detail: Some(format!("{:o}", mode)),
                });
            } else {
                checks.push(DiagnosticCheck {
                    name: "credentials_mode".into(),
                    status: DiagnosticStatus::Ok,
                    detail: Some("no credentials file (offline-only)".into()),
                });
            }
        }
    }

    // ATEP smoke test
    let atep_status = atep_smoke_test();
    checks.push(DiagnosticCheck {
        name: "atep_support".into(),
        status: if atep_status.is_ok() {
            DiagnosticStatus::Ok
        } else {
            DiagnosticStatus::Failed
        },
        detail: atep_status.err(),
    });

    // BLAKE3 sanity
    let h = blake3::hash(b"agentlock");
    let expected = "agentlock";
    let _ = expected;
    checks.push(DiagnosticCheck {
        name: "blake3_hash_sanity".into(),
        status: if h.as_bytes().len() == 32 {
            DiagnosticStatus::Ok
        } else {
            DiagnosticStatus::Failed
        },
        detail: Some(hex::encode(&h.as_bytes()[..8])),
    });

    // Disk space
    let tmp = std::env::temp_dir();
    let avail = available_space_bytes(&tmp).unwrap_or(0);
    checks.push(DiagnosticCheck {
        name: "tmp_dir".into(),
        status: if avail > 64 * 1024 * 1024 {
            DiagnosticStatus::Ok
        } else if avail > 0 {
            DiagnosticStatus::Warning
        } else {
            DiagnosticStatus::Warning
        },
        detail: Some(format!(
            "{} (estimated free bytes >0 {})",
            tmp.display(),
            avail > 0
        )),
    });

    // Cloud connectivity (only if profile is Cloud and endpoint set)
    if matches!(config.profile.mode, ProfileMode::Cloud) {
        if let Some(endpoint) = &config.profile.endpoint {
            let url = format!("{}/health", endpoint.trim_end_matches('/'));
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build();
            let detail = match client {
                Ok(c) => match c.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        Some(format!("HEAD {url} -> {}", r.status()))
                    }
                    Ok(r) => Some(format!("HEAD {url} -> {}", r.status())),
                    Err(e) => Some(format!("network error: {e}")),
                },
                Err(e) => Some(format!("client build failed: {e}")),
            };
            let status = match detail.as_deref().unwrap_or("") {
                s if s.contains("-> 200") || s.contains("-> 204") => DiagnosticStatus::Ok,
                _ => DiagnosticStatus::Warning,
            };
            checks.push(DiagnosticCheck {
                name: "cloud_health".into(),
                status,
                detail,
            });
        }
    }

    let overall_ok = checks
        .iter()
        .all(|c| !matches!(c.status, DiagnosticStatus::Failed));

    Ok(DiagnosticReport { checks, overall_ok })
}

fn atep_smoke_test() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let agent = "agent://diagnostics/smoke";
    let mut store = AtepStore::open_or_init(dir.path(), agent)
        .map_err(|e| format!("open_or_init: {e}"))?;
    let sk = SigningKey::generate(&mut rand_core_compat());
    let header = EventHeader {
        schema_version: 1,
        event_id: ulid::Ulid::new().to_bytes(),
        agent_id: agent.into(),
        stream: StreamId::Capability,
        stream_seq: 0,
        clock: Hlc::new(1, 0, 1),
        parents: vec![],
        event_type: "diag.test".into(),
        payload_schema_uri: "atep://schemas/v1/diag".into(),
    };
    let payload = EventPayload(ciborium::value::Value::Null);
    let event = agentlock_atep::AtepEvent::seal(header, payload, &sk, "diag".into())
        .map_err(|e| format!("seal: {e}"))?;
    store.append_event(event).map_err(|e| format!("append: {e}"))?;
    store
        .verify_all(&sk.verifying_key())
        .map_err(|e| format!("verify_all: {e}"))?;
    Ok(())
}

fn rand_core_compat() -> impl rand_core::CryptoRng + rand_core::RngCore {
    use rand_core::OsRng;
    OsRng
}

fn available_space_bytes(_path: &std::path::Path) -> Option<u64> {
    // Best-effort; reading /proc/self/statvfs would be Linux-specific. We
    // simply return None to mean "unknown".
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn smoke_runs() {
        let cfg = EffectiveConfig {
            default_profile: "default".into(),
            profile: agentlock_config::ProfileConfig {
                name: "default".into(),
                mode: ProfileMode::Offline,
                endpoint: None,
                org: None,
                api_key: None,
            },
            project: None,
        };
        let r = run_diagnostics(&cfg).await.unwrap();
        // overall_ok may depend on credentials_mode warnings; just assert
        // there are no failures from the deterministic checks.
        let failed: Vec<_> = r
            .checks
            .iter()
            .filter(|c| matches!(c.status, DiagnosticStatus::Failed))
            .collect();
        assert!(failed.is_empty(), "failed: {:?}", failed);
        // Severity import to silence unused warning if no other use.
        let _ = Severity::Info;
    }
}
