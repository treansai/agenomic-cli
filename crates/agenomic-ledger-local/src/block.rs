//! Optional block sealing: signed Merkle commitments over contiguous ranges
//! of the global chain.
//!
//! Blocks are an *additional* integrity layer, not a durability one —
//! individual entries are already WAL-durable and signed before any block
//! exists. Sealing (by max-entries, max-age, explicit flush, or shutdown)
//! commits a `[start, end]` sequence range under one Merkle root and one
//! signature, so an auditor can verify a range without re-checking every
//! entry signature, and a gap or swap inside a sealed range is detectable
//! from the block alone.
//!
//! Entries are never mutated by sealing (`entry.merkle_root` stays unset in
//! v1 — it is inside the signed surface, so back-filling it would break the
//! entry's own hash and signature; block coverage is resolved by sequence
//! range instead).
//!
//! Hashing/signing discipline mirrors entries: the block **core** is the
//! canonical JSON minus `block_hash` + `signature`;
//! `digest = blake3(AGENOMIC-LEDGER-BLOCK-v1\0 ‖ canonical_json(core))`;
//! `block_hash = "blake3:" + hex(digest)`; Ed25519 signs the digest. Blocks
//! chain via `previous_block_hash`.

use crate::canonical::{canonical_json, entry_hash_from_digest, merkle_root, prefixed_blake3};
use crate::entry::{deterministic_timestamp, LedgerEntry};
use crate::keystore::SigningKeyStore;
use agenomic_core::{io_at, CliError, CliResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Schema version stamped on every block.
pub const BLOCK_SCHEMA_VERSION: &str = "agenomic.ledger.block/v0.1";
/// Domain separator for block digests.
pub const LEDGER_BLOCK_DOMAIN: &[u8] = b"AGENOMIC-LEDGER-BLOCK-v1\0";
/// File name of the append-only block log inside the ledger root.
pub const BLOCK_LOG_FILE: &str = "blocks.jsonl";
/// Genesis value for the first block's `previous_block_hash`.
pub const GENESIS_BLOCK_HASH: &str = crate::canonical::GENESIS_ENTRY_HASH;

/// The fields excluded from a block's hashed/signed core.
pub const BLOCK_VOLATILE_FIELDS: &[&str] = &["block_hash", "signature"];

/// A sealed, signed block covering entries
/// `start_sequence_number..=end_sequence_number` of the global chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub schema_version: String,
    /// ULID of this block.
    pub block_id: String,
    /// Reserved for multi-tenant deployments; `None` locally (tenant
    /// isolation = distinct store roots + distinct keys, per the plan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub start_sequence_number: u64,
    pub end_sequence_number: u64,
    pub entry_count: u64,
    /// `blake3:` hash of the canonical JSON array of covered entry hashes —
    /// a flat commitment that is trivial to recompute in any language.
    pub entries_hash: String,
    /// `blake3-merkle-v1:` root over the covered entry hashes (RFC 0010
    /// construction), enabling per-entry inclusion proofs later.
    pub merkle_root: String,
    pub previous_block_hash: String,
    /// Timestamp of the first covered entry.
    pub created_at: String,
    /// When the block was sealed.
    pub sealed_at: String,
    pub hash_algorithm: String,
    pub signature_algorithm: String,
    /// `blake3:` hash of the domain-separated canonical block core.
    pub block_hash: String,
    /// Hex-encoded detached Ed25519 signature over the block digest.
    pub signature: String,
    pub signing_key_id: String,
}

impl LedgerBlock {
    /// Canonical JSON of the block core (volatile fields removed) — the
    /// hashed/signed surface.
    pub fn canonical_core(&self) -> CliResult<String> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| CliError::Internal(format!("serialize ledger block: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            for field in BLOCK_VOLATILE_FIELDS {
                obj.remove(*field);
            }
        }
        Ok(canonical_json(&value))
    }

    /// The 32-byte domain-separated block digest (signing message and
    /// `block_hash` preimage).
    pub fn compute_digest(&self) -> CliResult<[u8; 32]> {
        let core = self.canonical_core()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(LEDGER_BLOCK_DOMAIN);
        hasher.update(core.as_bytes());
        Ok(*hasher.finalize().as_bytes())
    }

    /// Whether the stored `block_hash` matches the recomputed one.
    pub fn hash_is_valid(&self) -> CliResult<bool> {
        Ok(entry_hash_from_digest(&self.compute_digest()?) == self.block_hash)
    }

    /// Verify the detached Ed25519 signature over the block digest.
    pub fn verify_signature(&self, vk: &ed25519_dalek::VerifyingKey) -> CliResult<()> {
        let invalid = || CliError::LedgerSignatureInvalid {
            entry_id: self.block_id.clone(),
        };
        let raw = hex::decode(&self.signature).map_err(|_| invalid())?;
        let bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| invalid())?;
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        let digest = self.compute_digest()?;
        vk.verify_strict(&digest, &sig).map_err(|_| invalid())
    }
}

/// The flat entries commitment: `blake3:` over the canonical JSON array of
/// the covered entry hashes.
///
/// ```
/// # use agenomic_ledger_local::block::entries_hash;
/// let h = entries_hash(&[format!("blake3:{}", "aa".repeat(32))]);
/// assert!(h.starts_with("blake3:"));
/// ```
pub fn entries_hash(entry_hashes: &[String]) -> String {
    let array = serde_json::Value::Array(
        entry_hashes
            .iter()
            .map(|h| serde_json::Value::String(h.clone()))
            .collect(),
    );
    prefixed_blake3(canonical_json(&array).as_bytes())
}

/// File-backed block chain: append-only `blocks.jsonl` next to the ledger
/// store, plus the in-memory head (previous block hash + next uncovered
/// sequence).
#[derive(Debug)]
pub struct BlockChain {
    path: PathBuf,
    blocks: Vec<LedgerBlock>,
}

impl BlockChain {
    /// Open (or create) the block chain persisted at `path`.
    ///
    /// ```
    /// # use agenomic_ledger_local::block::BlockChain;
    /// # let dir = tempfile::tempdir().unwrap();
    /// let chain = BlockChain::open(&dir.path().join("blocks.jsonl")).unwrap();
    /// assert_eq!(chain.next_start_sequence(), 0);
    /// ```
    pub fn open(path: &Path) -> CliResult<Self> {
        let mut blocks = Vec::new();
        if path.exists() {
            let raw = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            for (i, line) in raw.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let block: LedgerBlock =
                    serde_json::from_str(line).map_err(|e| CliError::LedgerIntegrity {
                        reason: format!("corrupt block log line {}: {e}", i + 1),
                    })?;
                blocks.push(block);
            }
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            blocks,
        })
    }

    /// The first global sequence number not yet covered by a block.
    pub fn next_start_sequence(&self) -> u64 {
        self.blocks
            .last()
            .map(|b| b.end_sequence_number + 1)
            .unwrap_or(0)
    }

    /// Block hash of the latest block (genesis constant when empty).
    pub fn head_hash(&self) -> &str {
        self.blocks
            .last()
            .map(|b| b.block_hash.as_str())
            .unwrap_or(GENESIS_BLOCK_HASH)
    }

    /// All sealed blocks, in chain order.
    pub fn blocks(&self) -> &[LedgerBlock] {
        &self.blocks
    }

    /// Seal `entries` — the uncovered tail of the global chain, in order —
    /// into one signed block. `entries[0].sequence_number` must equal
    /// [`BlockChain::next_start_sequence`] and the range must be contiguous;
    /// anything else is refused (a block must never paper over a gap).
    pub fn seal(
        &mut self,
        entries: &[LedgerEntry],
        keys: &dyn SigningKeyStore,
    ) -> CliResult<LedgerBlock> {
        let Some(first) = entries.first() else {
            return Err(CliError::LedgerConflict {
                reason: "cannot seal an empty block".to_string(),
            });
        };
        let expected_start = self.next_start_sequence();
        if first.sequence_number != expected_start {
            return Err(CliError::LedgerIntegrity {
                reason: format!(
                    "block seal must start at sequence {expected_start}, got {}",
                    first.sequence_number
                ),
            });
        }
        for pair in entries.windows(2) {
            if pair[1].sequence_number != pair[0].sequence_number + 1 {
                return Err(CliError::LedgerIntegrity {
                    reason: format!(
                        "block seal range is not contiguous at sequence {}",
                        pair[1].sequence_number
                    ),
                });
            }
        }
        let last = entries.last().unwrap_or(first);
        let hashes: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();

        let mut block = LedgerBlock {
            schema_version: BLOCK_SCHEMA_VERSION.to_string(),
            block_id: ulid::Ulid::new().to_string(),
            tenant_id: None,
            start_sequence_number: first.sequence_number,
            end_sequence_number: last.sequence_number,
            entry_count: entries.len() as u64,
            entries_hash: entries_hash(&hashes),
            merkle_root: merkle_root(&hashes)?,
            previous_block_hash: self.head_hash().to_string(),
            created_at: first.timestamp.clone(),
            sealed_at: deterministic_timestamp(Utc::now()),
            hash_algorithm: "blake3".to_string(),
            signature_algorithm: "ed25519".to_string(),
            block_hash: String::new(),
            signature: String::new(),
            signing_key_id: keys.active_key_id()?,
        };

        let digest = block.compute_digest()?;
        block.block_hash = entry_hash_from_digest(&digest);
        let (signer_id, signature) = keys.sign(&digest)?;
        if signer_id != block.signing_key_id {
            return Err(CliError::LedgerConflict {
                reason: format!(
                    "active key changed during block seal ({} -> {signer_id}); retry",
                    block.signing_key_id
                ),
            });
        }
        block.signature = signature;

        let line = serde_json::to_string(&block)
            .map_err(|e| CliError::Internal(format!("serialize ledger block: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| io_at(&self.path, e))?;
        writeln!(file, "{line}").map_err(|e| io_at(&self.path, e))?;
        file.sync_all().map_err(|e| io_at(&self.path, e))?;

        self.blocks.push(block.clone());
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
    use crate::keystore::FileKeyStore;
    use crate::ledger::Ledger;
    use crate::store::MemoryLedgerStore;
    use serde_json::json;
    use tempfile::tempdir;

    fn ledger_with_entries(
        keys_dir: &Path,
        n: u64,
    ) -> (Ledger<MemoryLedgerStore, FileKeyStore>, Vec<LedgerEntry>) {
        let mut keys = FileKeyStore::open(keys_dir).unwrap();
        keys.generate().unwrap();
        let mut ledger = Ledger::open(MemoryLedgerStore::new(), keys).unwrap();
        for i in 0..n {
            ledger
                .append(LedgerEntryDraft::new(
                    "agent://acme/support",
                    "run-1",
                    "agent.started",
                    PayloadCommitment::Inline(json!({ "i": i })),
                    IngestionSource::Cli,
                ))
                .unwrap();
        }
        let entries = ledger.read_all().unwrap();
        (ledger, entries)
    }

    #[test]
    fn seal_signs_chains_and_persists() {
        let keys_dir = tempdir().unwrap();
        let block_dir = tempdir().unwrap();
        let (ledger, entries) = ledger_with_entries(keys_dir.path(), 5);
        let path = block_dir.path().join(BLOCK_LOG_FILE);

        let mut chain = BlockChain::open(&path).unwrap();
        let b1 = chain.seal(&entries[0..3], ledger.keystore()).unwrap();
        let b2 = chain.seal(&entries[3..5], ledger.keystore()).unwrap();

        assert_eq!(b1.previous_block_hash, GENESIS_BLOCK_HASH);
        assert_eq!(b2.previous_block_hash, b1.block_hash);
        assert_eq!(b1.entry_count, 3);
        assert_eq!((b2.start_sequence_number, b2.end_sequence_number), (3, 4));
        assert!(b1.merkle_root.starts_with("blake3-merkle-v1:"));
        assert!(b1.hash_is_valid().unwrap());
        let vk = ledger.keystore().verifying_key(&b1.signing_key_id).unwrap();
        b1.verify_signature(&vk).unwrap();

        // Reopen: chain state restored from disk.
        let reopened = BlockChain::open(&path).unwrap();
        assert_eq!(reopened.blocks().len(), 2);
        assert_eq!(reopened.next_start_sequence(), 5);
        assert_eq!(reopened.head_hash(), b2.block_hash);
    }

    #[test]
    fn seal_refuses_gaps_and_wrong_starts() {
        let keys_dir = tempdir().unwrap();
        let block_dir = tempdir().unwrap();
        let (ledger, entries) = ledger_with_entries(keys_dir.path(), 5);
        let path = block_dir.path().join(BLOCK_LOG_FILE);
        let mut chain = BlockChain::open(&path).unwrap();

        // Wrong start (skips sequence 0).
        assert!(chain.seal(&entries[1..3], ledger.keystore()).is_err());
        // Non-contiguous range.
        let gapped: Vec<LedgerEntry> = vec![entries[0].clone(), entries[2].clone()];
        assert!(chain.seal(&gapped, ledger.keystore()).is_err());
        // Empty range.
        assert!(chain.seal(&[], ledger.keystore()).is_err());
    }

    #[test]
    fn tampered_block_fields_break_hash_and_signature() {
        let keys_dir = tempdir().unwrap();
        let block_dir = tempdir().unwrap();
        let (ledger, entries) = ledger_with_entries(keys_dir.path(), 3);
        let mut chain = BlockChain::open(&block_dir.path().join(BLOCK_LOG_FILE)).unwrap();
        let block = chain.seal(&entries, ledger.keystore()).unwrap();
        let vk = ledger
            .keystore()
            .verifying_key(&block.signing_key_id)
            .unwrap();

        let mut tampered = block.clone();
        tampered.merkle_root = format!("blake3-merkle-v1:{}", "0".repeat(64));
        assert!(!tampered.hash_is_valid().unwrap());
        assert!(tampered.verify_signature(&vk).is_err());

        let mut resized = block;
        resized.end_sequence_number = 99;
        assert!(!resized.hash_is_valid().unwrap());
    }
}
