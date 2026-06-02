//! Create and verify Agenomic release attestations.
//!
//! An attestation pins:
//!
//! - the bundle's logical and archive hashes
//! - optionally a replay-report hash
//! - optionally an ATEP root hash (BLAKE3 over the agent's per-stream merkle roots)
//! - an optional ed25519 signature over the canonical CBOR of the attestation

use std::path::{Path, PathBuf};

use agenomic_atep::AtepStore;
use agenomic_core::{io_at, CliError, CliResult};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    Signer, Verifier,
};
use serde::{Deserialize, Serialize};

/// Domain separator for attestation content hashes.
pub const ATTESTATION_DOMAIN: &[u8] = b"AGENTLOCK-ATTESTATION-v1\0";

/// Schema version of the attestation document.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// What kind of signing the caller wants.
#[derive(Debug, Clone)]
pub enum SigningMode {
    Unsigned,
    LocalEd25519 { key_path: PathBuf },
}

/// Options for [`create_attestation`].
#[derive(Debug, Clone)]
pub struct AttestationOptions {
    pub bundle: PathBuf,
    pub replay_report: Option<PathBuf>,
    pub atep_store: Option<PathBuf>,
    pub atep_root_hash: Option<String>,
    pub sign_with: Option<SigningMode>,
    pub output: PathBuf,
    pub agent_id_override: Option<String>,
}

/// Generator metadata block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratorInfo {
    pub name: String,
    pub version: String,
}

/// Embedded signature block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_pem: String,
    pub signature: String,
}

/// Release attestation document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseAttestation {
    pub schema_version: u32,
    pub attestation_type: String,
    pub agent_id: String,
    pub bundle_logical_hash: String,
    pub bundle_archive_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_report_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atep_root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_passed: Option<bool>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub generator: GeneratorInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<AttestationSignature>,
}

/// Create an attestation from a bundle (directory or archive) and optional
/// replay report / ATEP root.
///
/// ```no_run
/// use agenomic_attestation::{create_attestation, AttestationOptions};
/// let opts = AttestationOptions {
///     bundle: "./bundle.tar.zst".into(),
///     replay_report: None,
///     atep_store: None,
///     atep_root_hash: None,
///     sign_with: None,
///     output: "/tmp/attestation.json".into(),
///     agent_id_override: None,
/// };
/// let _ = create_attestation(opts).unwrap();
/// ```
pub fn create_attestation(options: AttestationOptions) -> CliResult<ReleaseAttestation> {
    let summary = agenomic_bundle::inspect_bundle(&options.bundle)?;

    let logical = summary.logical_bundle_hash.clone();

    let archive_hex = if options.bundle.is_file() {
        let bytes = std::fs::read(&options.bundle).map_err(|e| io_at(&options.bundle, e))?;
        hex::encode(blake3::hash(&bytes).as_bytes())
    } else {
        // Build an in-memory archive equivalent for the directory so we have a
        // stable archive hash. We re-use logical hash because the user
        // requested an "in-place" attestation against an unpacked bundle.
        logical.clone()
    };

    let replay_report_hash = match &options.replay_report {
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| io_at(p, e))?;
            Some(hex::encode(blake3::hash(&bytes).as_bytes()))
        }
        None => None,
    };
    let contract_passed = match &options.replay_report {
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| io_at(p, e))?;
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("contract_passed").and_then(|x| x.as_bool()))
        }
        None => None,
    };

    let atep_root = match (&options.atep_store, &options.atep_root_hash) {
        (Some(store_path), _) => {
            let manifest_bytes = std::fs::read(store_path.join("manifest.json"))
                .map_err(|e| io_at(store_path.join("manifest.json"), e))?;
            let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| CliError::Internal(format!("atep manifest parse: {e}")))?;
            let store = AtepStore::open_or_init(store_path, &manifest.agent_id)?;
            Some(hex::encode(store.store_merkle_root()))
        }
        (None, Some(h)) => Some(h.clone()),
        _ => None,
    };

    let agent_id = options
        .agent_id_override
        .clone()
        .unwrap_or_else(|| summary.agent_id.clone());

    let mut att = ReleaseAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        attestation_type: "release".into(),
        agent_id,
        bundle_logical_hash: logical,
        bundle_archive_hash: archive_hex,
        replay_report_hash,
        atep_root_hash: atep_root,
        contract_passed,
        generated_at: Utc::now(),
        generator: GeneratorInfo {
            name: "agenomic-cli".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        signature: None,
    };

    if let Some(SigningMode::LocalEd25519 { key_path }) = &options.sign_with {
        let sk = agenomic_atep::load_signing_key(key_path)?;
        let body = canonical_cbor_without_signature(&att)?;
        let mut h = blake3::Hasher::new();
        h.update(ATTESTATION_DOMAIN);
        h.update(&body);
        let content_hash = *h.finalize().as_bytes();
        let sig = sk.sign(&content_hash);
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| CliError::Internal(format!("encode public pem: {e}")))?;
        att.signature = Some(AttestationSignature {
            algorithm: "ed25519".into(),
            key_id: agenomic_atep::short_key_id(&sk.verifying_key()),
            public_key_pem: pub_pem,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        });
    }

    let json = serde_json::to_vec_pretty(&att)
        .map_err(|e| CliError::Internal(format!("attestation serialize: {e}")))?;
    agenomic_fs::write_atomic(&options.output, &json)?;

    Ok(att)
}

/// One verification check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Result of [`verify_attestation`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationResult {
    pub valid: bool,
    pub checks: Vec<VerificationCheck>,
}

/// Verify an attestation file. Optionally also verifies an ATEP store root
/// hash matches the embedded `atep_root_hash`.
pub fn verify_attestation(
    attestation_path: &Path,
    atep_store: Option<&Path>,
) -> CliResult<VerificationResult> {
    let bytes = std::fs::read(attestation_path).map_err(|e| io_at(attestation_path, e))?;
    let att: ReleaseAttestation = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::Internal(format!("attestation parse: {e}")))?;

    let mut checks: Vec<VerificationCheck> = Vec::new();

    checks.push(VerificationCheck {
        name: "schema_version".into(),
        passed: att.schema_version == ATTESTATION_SCHEMA_VERSION,
        detail: Some(format!("schema_version={}", att.schema_version)),
    });

    checks.push(VerificationCheck {
        name: "attestation_type_release".into(),
        passed: att.attestation_type == "release",
        detail: None,
    });

    checks.push(VerificationCheck {
        name: "logical_hash_format".into(),
        passed: att.bundle_logical_hash.len() == 64
            && att
                .bundle_logical_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
        detail: None,
    });

    if let Some(sig) = &att.signature {
        let body = canonical_cbor_without_signature(&att)?;
        let mut h = blake3::Hasher::new();
        h.update(ATTESTATION_DOMAIN);
        h.update(&body);
        let content_hash = *h.finalize().as_bytes();
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&sig.signature) {
            Ok(b) => b,
            Err(_) => {
                checks.push(VerificationCheck {
                    name: "signature_valid".into(),
                    passed: false,
                    detail: Some("signature not valid base64".into()),
                });
                return finalize(checks);
            }
        };
        if sig_bytes.len() != 64 {
            checks.push(VerificationCheck {
                name: "signature_valid".into(),
                passed: false,
                detail: Some(format!("signature has wrong length: {}", sig_bytes.len())),
            });
            return finalize(checks);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let vk = match ed25519_dalek::VerifyingKey::from_public_key_pem(&sig.public_key_pem) {
            Ok(vk) => vk,
            Err(e) => {
                checks.push(VerificationCheck {
                    name: "signature_valid".into(),
                    passed: false,
                    detail: Some(format!("public_key_pem parse: {e}")),
                });
                return finalize(checks);
            }
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let ok = vk.verify(&content_hash, &signature).is_ok();
        checks.push(VerificationCheck {
            name: "signature_valid".into(),
            passed: ok,
            detail: if ok {
                None
            } else {
                Some("ed25519 verify failed".into())
            },
        });
    } else {
        checks.push(VerificationCheck {
            name: "signature_present".into(),
            passed: false,
            detail: Some("attestation is unsigned (informational only)".into()),
        });
    }

    if let (Some(atep_path), Some(expected)) = (atep_store, &att.atep_root_hash) {
        let manifest_path = atep_path.join("manifest.json");
        match std::fs::read(&manifest_path) {
            Ok(b) => match serde_json::from_slice::<agenomic_atep::AtepManifest>(&b) {
                Ok(m) => match AtepStore::open_or_init(atep_path, &m.agent_id) {
                    Ok(store) => {
                        let computed = hex::encode(store.store_merkle_root());
                        checks.push(VerificationCheck {
                            name: "atep_root_matches".into(),
                            passed: computed == *expected,
                            detail: Some(format!("computed={computed} expected={expected}")),
                        });
                    }
                    Err(e) => checks.push(VerificationCheck {
                        name: "atep_store_open".into(),
                        passed: false,
                        detail: Some(format!("{e}")),
                    }),
                },
                Err(e) => checks.push(VerificationCheck {
                    name: "atep_manifest_parse".into(),
                    passed: false,
                    detail: Some(format!("{e}")),
                }),
            },
            Err(e) => checks.push(VerificationCheck {
                name: "atep_manifest_read".into(),
                passed: false,
                detail: Some(format!("{e}")),
            }),
        }
    }

    finalize(checks)
}

fn finalize(checks: Vec<VerificationCheck>) -> CliResult<VerificationResult> {
    // An attestation is "valid" if every non-informational check passed.
    // The "signature_present=false" check for unsigned attestations is the
    // only allowed informational failure.
    let valid = checks
        .iter()
        .all(|c| c.passed || c.name == "signature_present");
    Ok(VerificationResult { valid, checks })
}

fn canonical_cbor_without_signature(att: &ReleaseAttestation) -> CliResult<Vec<u8>> {
    let mut copy = att.clone();
    copy.signature = None;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&copy, &mut out)
        .map_err(|e| CliError::Internal(format!("cbor encode: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_bundle(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("genome.yaml"),
            "spec_version: '0.1'\nagent:\n  id: 'agent://acme/foo'\n  name: 'Foo'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n",
        )
        .unwrap();
        fs::write(
            dir.join("agent.lock.yaml"),
            "spec_version: '0.1'\nagent_id: 'agent://acme/foo'\nmodel:\n  provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nknowledge: []\n",
        )
        .unwrap();
        fs::write(
            dir.join("behavior.contract.yaml"),
            "spec_version: '0.1'\ncontract:\n  id: 'c'\n  rules: []\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("prompts")).unwrap();
        fs::write(dir.join("prompts/system.md"), "x").unwrap();
    }

    #[test]
    fn unsigned_create_then_verify_ok() {
        let d = tempdir().unwrap();
        write_bundle(d.path());
        let out = d.path().join("att.json");
        let _ = create_attestation(AttestationOptions {
            bundle: d.path().to_path_buf(),
            replay_report: None,
            atep_store: None,
            atep_root_hash: None,
            sign_with: None,
            output: out.clone(),
            agent_id_override: None,
        })
        .unwrap();
        let r = verify_attestation(&out, None).unwrap();
        assert!(r.valid);
    }

    #[test]
    fn signed_create_then_verify_ok() {
        let d = tempdir().unwrap();
        write_bundle(d.path());
        let key = d.path().join("k.pem");
        agenomic_atep::generate_signing_key(&key).unwrap();

        let out = d.path().join("att.json");
        let _ = create_attestation(AttestationOptions {
            bundle: d.path().to_path_buf(),
            replay_report: None,
            atep_store: None,
            atep_root_hash: None,
            sign_with: Some(SigningMode::LocalEd25519 {
                key_path: key.clone(),
            }),
            output: out.clone(),
            agent_id_override: None,
        })
        .unwrap();
        let r = verify_attestation(&out, None).unwrap();
        assert!(r.valid);
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "signature_valid" && c.passed));
    }

    #[test]
    fn tampered_attestation_fails() {
        let d = tempdir().unwrap();
        write_bundle(d.path());
        let key = d.path().join("k.pem");
        agenomic_atep::generate_signing_key(&key).unwrap();

        let out = d.path().join("att.json");
        let _ = create_attestation(AttestationOptions {
            bundle: d.path().to_path_buf(),
            replay_report: None,
            atep_store: None,
            atep_root_hash: None,
            sign_with: Some(SigningMode::LocalEd25519 {
                key_path: key.clone(),
            }),
            output: out.clone(),
            agent_id_override: None,
        })
        .unwrap();

        // Tamper: change agent_id
        let mut bytes = std::fs::read_to_string(&out).unwrap();
        bytes = bytes.replace("agent://acme/foo", "agent://evil/foo");
        std::fs::write(&out, bytes).unwrap();

        let r = verify_attestation(&out, None).unwrap();
        assert!(!r.valid);
    }
}
