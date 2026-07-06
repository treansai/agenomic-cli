//! Ledger proofs and the offline-verifiable evidence proof bundle
//! (prompt §5.10; format open per Q0, aligned with the cloud
//! evidence-package discipline).
//!
//! Two artifacts:
//! - [`LedgerProof`] — the compact proof block attached to tracking and
//!   replay reports (root hash, run chain head, block ids, key ids,
//!   verification / gap / queue-loss status).
//! - The **proof bundle** — a directory of canonical members
//!   (`ledger_manifest.json`, `run_chain.jsonl`, `ledger_blocks.json`,
//!   `merkle_proofs.json`, `signatures.json`, `public_keys.json`,
//!   `verification_report.json`, plus optional `replay_report.json` /
//!   `policy_results.json` / `risk_summary.md` when the caller supplies
//!   them — absent artifacts are listed as absent, never fabricated). The
//!   manifest is signed (`ed25519(blake3(DOMAIN ‖ canonical_json(manifest ∖
//!   signature)))`, the RFC 0008 discipline) and the bundle re-verifies on
//!   a clean machine with no network and no keystore — public keys ship
//!   inside.
//!
//! Locally-assembled bundles carry the platform's legal notice and a
//! non-probative status: org-attested probative packs are the cloud
//! service's job (Q0). The ledger proves provenance and integrity of
//! recorded events — it does not make replay deterministic, and nothing
//! here claims otherwise.

use crate::block::LedgerBlock;
use crate::canonical::{canonical_json, prefixed_blake3};
use crate::entry::LedgerEntry;
use crate::keystore::{KeyStatus, SigningKeyStore};
use crate::verify::{verify_ledger, VerificationReport};
use agenomic_core::{io_at, CliError, CliResult};
use ed25519_dalek::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Manifest schema version of a proof bundle.
pub const PROOF_MANIFEST_VERSION: &str = "agenomic.ledger.proof/v0.1";
/// Domain separator for the manifest digest.
pub const LEDGER_PROOF_DOMAIN: &[u8] = b"AGENOMIC-LEDGER-PROOF-v1\0";
/// Mirrors the platform's evidentiary framing: technical integrity only.
pub const LEGAL_NOTICE: &str =
    "Technical integrity evidence only; legal probative value must be validated by counsel.";
/// Status stamped on locally-signed bundles (org-attested probative packs
/// are the hosted trust service's job — Q0).
pub const LOCAL_PROBATIVE_STATUS: &str = "non-probative (locally signed)";

/// Compact ledger proof block attached to tracking/replay reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerProof {
    pub proof_version: String,
    /// Entry hash of the global chain head at proof time.
    pub ledger_head_hash: String,
    pub run_id: String,
    /// Entry hash of the run chain head.
    pub run_head_hash: String,
    pub run_entry_count: u64,
    /// Global sequence range `(first, last)` of the run's entries.
    pub entry_range: Option<(u64, u64)>,
    /// Blocks covering any of the run's entries.
    pub block_ids: Vec<String>,
    /// Every key that signed one of the run's entries.
    pub signing_key_ids: Vec<String>,
    /// Full-ledger verification verdict at proof time.
    pub verification_passed: bool,
    pub chain_valid: bool,
    pub sequence_gaps: Vec<(u64, u64)>,
    /// Queue-loss status: events parked in the dead-letter store and WAL
    /// records not yet sealed (0/0 = nothing in flight, nothing lost
    /// silently — losses would be dead-lettered, never dropped).
    pub dead_lettered: u64,
    pub wal_pending: u64,
}

/// Build a [`LedgerProof`] for `run_id` from ledger state. Pure over its
/// inputs; runs the full verification engine.
pub fn build_ledger_proof(
    run_id: &str,
    entries: &[LedgerEntry],
    blocks: &[LedgerBlock],
    keys: &dyn SigningKeyStore,
    wal_dir: Option<&Path>,
    dead_lettered: u64,
) -> CliResult<LedgerProof> {
    let report = verify_ledger(entries, blocks, keys, wal_dir)?;
    let run_entries: Vec<&LedgerEntry> = entries.iter().filter(|e| e.run_id == run_id).collect();
    let entry_range = match (run_entries.first(), run_entries.last()) {
        (Some(first), Some(last)) => Some((first.sequence_number, last.sequence_number)),
        _ => None,
    };
    let block_ids = blocks
        .iter()
        .filter(|b| {
            run_entries.iter().any(|e| {
                e.sequence_number >= b.start_sequence_number
                    && e.sequence_number <= b.end_sequence_number
            })
        })
        .map(|b| b.block_id.clone())
        .collect();
    let mut signing_key_ids: Vec<String> = run_entries
        .iter()
        .map(|e| e.signing_key_id.clone())
        .collect();
    signing_key_ids.sort();
    signing_key_ids.dedup();

    Ok(LedgerProof {
        proof_version: PROOF_MANIFEST_VERSION.to_string(),
        ledger_head_hash: report.chain_summary.head_hash.clone(),
        run_id: run_id.to_string(),
        run_head_hash: run_entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| crate::canonical::GENESIS_ENTRY_HASH.to_string()),
        run_entry_count: run_entries.len() as u64,
        entry_range,
        block_ids,
        signing_key_ids,
        verification_passed: report.passed,
        chain_valid: report.entries.chain_valid && report.chain_evaluated,
        sequence_gaps: report.sequence_gaps.clone(),
        dead_lettered,
        wal_pending: report.wal.as_ref().map(|w| w.pending_records).unwrap_or(0),
    })
}

// ---- proof bundle ----------------------------------------------------------

/// One member file of a bundle: path, BLAKE3, size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMember {
    pub path: String,
    pub blake3: String,
    pub bytes: u64,
}

/// The signed manifest at the root of a proof bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofManifest {
    pub manifest_version: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub probative_status: String,
    pub legal_notice: String,
    pub members: Vec<ManifestMember>,
    /// Canonical member names that were not available at assembly time
    /// (never fabricated).
    pub absent_members: Vec<String>,
    pub signing_key_id: String,
    /// Hex Ed25519 over `blake3(DOMAIN ‖ canonical_json(manifest ∖ signature))`.
    pub signature: String,
}

impl ProofManifest {
    fn digest(&self) -> CliResult<[u8; 32]> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| CliError::Internal(format!("serialize proof manifest: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("signature");
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(LEDGER_PROOF_DOMAIN);
        hasher.update(canonical_json(&value).as_bytes());
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Optional caller-supplied artifacts to include (paths to existing files;
/// absent ones are recorded as absent).
#[derive(Debug, Default, Clone)]
pub struct BundleExtras {
    pub replay_report: Option<std::path::PathBuf>,
    pub policy_results: Option<std::path::PathBuf>,
    pub risk_summary: Option<std::path::PathBuf>,
}

/// Assemble a proof bundle for `run_id` (or the whole ledger when `None`)
/// into `out_dir`. Returns the signed manifest.
pub fn assemble_bundle(
    out_dir: &Path,
    run_id: Option<&str>,
    entries: &[LedgerEntry],
    blocks: &[LedgerBlock],
    keys: &dyn SigningKeyStore,
    extras: &BundleExtras,
) -> CliResult<ProofManifest> {
    std::fs::create_dir_all(out_dir).map_err(|e| io_at(out_dir, e))?;

    let scoped: Vec<LedgerEntry> = match run_id {
        Some(run) => entries
            .iter()
            .filter(|e| e.run_id == run)
            .cloned()
            .collect(),
        None => entries.to_vec(),
    };
    if scoped.is_empty() {
        return Err(CliError::Schema(match run_id {
            Some(run) => format!("no entries for run '{run}'"),
            None => "the ledger is empty".to_string(),
        }));
    }
    // Blocks covering any scoped entry.
    let scoped_blocks: Vec<LedgerBlock> = blocks
        .iter()
        .filter(|b| {
            scoped.iter().any(|e| {
                e.sequence_number >= b.start_sequence_number
                    && e.sequence_number <= b.end_sequence_number
            })
        })
        .cloned()
        .collect();

    // The verification report is generated against the FULL ledger (the
    // chain claim is global), then shipped alongside the scoped chain.
    let report = verify_ledger(entries, blocks, keys, None)?;

    let mut members: Vec<(String, Vec<u8>)> = Vec::new();

    let mut run_chain = String::new();
    for e in &scoped {
        run_chain
            .push_str(&serde_json::to_string(e).map_err(|e| CliError::Internal(format!("{e}")))?);
        run_chain.push('\n');
    }
    members.push(("run_chain.jsonl".to_string(), run_chain.into_bytes()));
    members.push((
        "ledger_blocks.json".to_string(),
        serde_json::to_vec_pretty(&scoped_blocks)
            .map_err(|e| CliError::Internal(format!("{e}")))?,
    ));

    #[derive(Serialize)]
    struct MerkleProofEntry<'a> {
        block_id: &'a str,
        merkle_root: &'a str,
        entry_hashes: Vec<String>,
    }
    let merkle_proofs: Vec<MerkleProofEntry> = scoped_blocks
        .iter()
        .map(|b| MerkleProofEntry {
            block_id: &b.block_id,
            merkle_root: &b.merkle_root,
            entry_hashes: entries
                .iter()
                .filter(|e| {
                    e.sequence_number >= b.start_sequence_number
                        && e.sequence_number <= b.end_sequence_number
                })
                .map(|e| e.entry_hash.clone())
                .collect(),
        })
        .collect();
    members.push((
        "merkle_proofs.json".to_string(),
        serde_json::to_vec_pretty(&merkle_proofs)
            .map_err(|e| CliError::Internal(format!("{e}")))?,
    ));

    #[derive(Serialize)]
    struct SignatureIndex<'a> {
        entries: Vec<(u64, &'a str, &'a str)>,
        blocks: Vec<(&'a str, &'a str, &'a str)>,
    }
    let signatures = SignatureIndex {
        entries: scoped
            .iter()
            .map(|e| {
                (
                    e.sequence_number,
                    e.signing_key_id.as_str(),
                    e.signature.as_str(),
                )
            })
            .collect(),
        blocks: scoped_blocks
            .iter()
            .map(|b| {
                (
                    b.block_id.as_str(),
                    b.signing_key_id.as_str(),
                    b.signature.as_str(),
                )
            })
            .collect(),
    };
    members.push((
        "signatures.json".to_string(),
        serde_json::to_vec_pretty(&signatures).map_err(|e| CliError::Internal(format!("{e}")))?,
    ));

    // Public keys: every key referenced by scoped entries/blocks + the
    // manifest signer, exported so verification is keystore-free.
    let mut key_ids: Vec<String> = scoped.iter().map(|e| e.signing_key_id.clone()).collect();
    key_ids.extend(scoped_blocks.iter().map(|b| b.signing_key_id.clone()));
    key_ids.push(keys.active_key_id()?);
    key_ids.sort();
    key_ids.dedup();
    #[derive(Serialize)]
    struct PublicKeyEntry {
        key_id: String,
        status: KeyStatus,
        public_key_pem: String,
    }
    let mut public_keys = Vec::new();
    for key_id in &key_ids {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let vk = keys.verifying_key(key_id)?;
        public_keys.push(PublicKeyEntry {
            key_id: key_id.clone(),
            status: keys.key_status(key_id)?,
            public_key_pem: vk
                .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .map_err(|e| CliError::Internal(format!("encode public key: {e}")))?,
        });
    }
    members.push((
        "public_keys.json".to_string(),
        serde_json::to_vec_pretty(&public_keys).map_err(|e| CliError::Internal(format!("{e}")))?,
    ));
    members.push((
        "verification_report.json".to_string(),
        serde_json::to_vec_pretty(&report).map_err(|e| CliError::Internal(format!("{e}")))?,
    ));

    let mut absent: Vec<String> = Vec::new();
    for (name, source) in [
        ("replay_report.json", &extras.replay_report),
        ("policy_results.json", &extras.policy_results),
        ("risk_summary.md", &extras.risk_summary),
    ] {
        match source {
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|e| io_at(path, e))?;
                members.push((name.to_string(), bytes));
            }
            None => absent.push(name.to_string()),
        }
    }

    // Write members, then the signed manifest over their hashes.
    let mut manifest_members = Vec::with_capacity(members.len());
    for (name, bytes) in &members {
        let path = out_dir.join(name);
        std::fs::write(&path, bytes).map_err(|e| io_at(&path, e))?;
        manifest_members.push(ManifestMember {
            path: name.clone(),
            blake3: prefixed_blake3(bytes),
            bytes: bytes.len() as u64,
        });
    }

    let mut manifest = ProofManifest {
        manifest_version: PROOF_MANIFEST_VERSION.to_string(),
        created_at: crate::entry::deterministic_timestamp(chrono::Utc::now()),
        run_id: run_id.map(String::from),
        probative_status: LOCAL_PROBATIVE_STATUS.to_string(),
        legal_notice: LEGAL_NOTICE.to_string(),
        members: manifest_members,
        absent_members: absent,
        signing_key_id: keys.active_key_id()?,
        signature: String::new(),
    };
    let digest = manifest.digest()?;
    let (signer_id, signature) = keys.sign(&digest)?;
    if signer_id != manifest.signing_key_id {
        return Err(CliError::LedgerConflict {
            reason: format!(
                "active key changed during bundle assembly ({} -> {signer_id}); retry",
                manifest.signing_key_id
            ),
        });
    }
    manifest.signature = signature;
    let manifest_path = out_dir.join("ledger_manifest.json");
    let raw =
        serde_json::to_vec_pretty(&manifest).map_err(|e| CliError::Internal(format!("{e}")))?;
    std::fs::write(&manifest_path, raw).map_err(|e| io_at(&manifest_path, e))?;
    Ok(manifest)
}

/// Key resolver backed by the bundle's own `public_keys.json` — verification
/// needs no keystore, no network, no prior state.
pub struct EmbeddedKeyResolver {
    keys: BTreeMap<String, (KeyStatus, ed25519_dalek::VerifyingKey)>,
}

impl EmbeddedKeyResolver {
    /// Parse `public_keys.json` content.
    pub fn from_json(raw: &str) -> CliResult<Self> {
        #[derive(Deserialize)]
        struct PublicKeyEntry {
            key_id: String,
            status: KeyStatus,
            public_key_pem: String,
        }
        let parsed: Vec<PublicKeyEntry> = serde_json::from_str(raw)
            .map_err(|e| CliError::Schema(format!("parse public_keys.json: {e}")))?;
        let mut keys = BTreeMap::new();
        for k in parsed {
            let vk = ed25519_dalek::VerifyingKey::from_public_key_pem(&k.public_key_pem)
                .map_err(|e| CliError::Schema(format!("parse public key {}: {e}", k.key_id)))?;
            keys.insert(k.key_id, (k.status, vk));
        }
        Ok(Self { keys })
    }
}

impl SigningKeyStore for EmbeddedKeyResolver {
    fn active_key_id(&self) -> CliResult<String> {
        Err(CliError::LedgerKeyStore(
            "a proof bundle can verify but never sign".to_string(),
        ))
    }
    fn sign(&self, _digest: &[u8; 32]) -> CliResult<(String, String)> {
        Err(CliError::LedgerKeyStore(
            "a proof bundle can verify but never sign".to_string(),
        ))
    }
    fn verifying_key(&self, key_id: &str) -> CliResult<ed25519_dalek::VerifyingKey> {
        self.keys
            .get(key_id)
            .map(|(_, vk)| *vk)
            .ok_or_else(|| CliError::LedgerKeyStore(format!("unknown key {key_id}")))
    }
    fn key_status(&self, key_id: &str) -> CliResult<KeyStatus> {
        self.keys
            .get(key_id)
            .map(|(status, _)| *status)
            .ok_or_else(|| CliError::LedgerKeyStore(format!("unknown key {key_id}")))
    }
}

/// Result of verifying a bundle offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerification {
    pub manifest_signature_valid: bool,
    /// Members whose bytes mismatch their manifest hash.
    pub member_hash_failures: Vec<String>,
    /// Members listed but missing on disk.
    pub missing_members: Vec<String>,
    pub probative_status: String,
    /// Re-run of the chain verification over the bundled entries/blocks
    /// using only the bundled public keys.
    pub ledger: VerificationReport,
    pub passed: bool,
}

/// Verify a proof bundle directory completely offline: manifest signature,
/// member hashes, then the full chain verification using only bundled keys.
pub fn verify_bundle(dir: &Path) -> CliResult<BundleVerification> {
    let manifest_path = dir.join("ledger_manifest.json");
    let raw = std::fs::read_to_string(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
    let manifest: ProofManifest = serde_json::from_str(&raw)
        .map_err(|e| CliError::Schema(format!("parse ledger_manifest.json: {e}")))?;

    let mut member_hash_failures = Vec::new();
    let mut missing_members = Vec::new();
    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for member in &manifest.members {
        let path = dir.join(&member.path);
        match std::fs::read(&path) {
            Ok(bytes) => {
                if prefixed_blake3(&bytes) != member.blake3 {
                    member_hash_failures.push(member.path.clone());
                }
                contents.insert(member.path.clone(), bytes);
            }
            Err(_) => missing_members.push(member.path.clone()),
        }
    }

    let keys_raw = contents
        .get("public_keys.json")
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .ok_or_else(|| CliError::Schema("bundle has no public_keys.json".to_string()))?;
    let resolver = EmbeddedKeyResolver::from_json(&keys_raw)?;

    let manifest_signature_valid = (|| -> CliResult<bool> {
        let vk = resolver.verifying_key(&manifest.signing_key_id)?;
        let raw_sig = hex::decode(&manifest.signature)
            .map_err(|_| CliError::Schema("malformed manifest signature".to_string()))?;
        let bytes: [u8; 64] = raw_sig
            .as_slice()
            .try_into()
            .map_err(|_| CliError::Schema("manifest signature is not 64 bytes".to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        Ok(vk.verify_strict(&manifest.digest()?, &sig).is_ok())
    })()
    .unwrap_or(false);

    let entries: Vec<LedgerEntry> = contents
        .get("run_chain.jsonl")
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).map_err(|e| CliError::LedgerIntegrity {
                reason: format!("corrupt run_chain.jsonl line: {e}"),
            })
        })
        .collect::<CliResult<_>>()?;
    let blocks: Vec<LedgerBlock> = match contents.get("ledger_blocks.json") {
        Some(b) => serde_json::from_slice(b)
            .map_err(|e| CliError::Schema(format!("parse ledger_blocks.json: {e}")))?,
        None => Vec::new(),
    };
    let ledger = verify_ledger(&entries, &blocks, &resolver, None)?;

    // A run-scoped bundle legitimately starts mid-chain: judge entry
    // integrity (hashes/signatures/conflicts), not global completeness.
    let entry_integrity = ledger.entries.hash_failures.is_empty()
        && ledger.entries.signature_failures.is_empty()
        && ledger.entries.unresolved_key_failures.is_empty()
        && ledger.conflicting_event_ids.is_empty()
        && ledger.duplicate_sequences.is_empty()
        && ledger.blocks.merkle_mismatches.is_empty()
        && ledger.blocks.entries_hash_mismatches.is_empty()
        && ledger.blocks.hash_failures.is_empty()
        && ledger.blocks.signature_failures.is_empty();

    let passed = manifest_signature_valid
        && member_hash_failures.is_empty()
        && missing_members.is_empty()
        && entry_integrity;

    Ok(BundleVerification {
        manifest_signature_valid,
        member_hash_failures,
        missing_members,
        probative_status: manifest.probative_status.clone(),
        ledger,
        passed,
    })
}
