//! The ledger service: composes a [`LedgerStore`], a [`SigningKeyStore`],
//! and the in-memory [`ChainState`] into the append/verify surface.
//!
//! Phase 1 appends are synchronous and fully sealed (hash + signature)
//! before persistence — the entry lands in `ledger_appended` state. The
//! Phase 2 pipeline inserts the durable queue/WAL in front of this and walks
//! the earlier durability states; this type stays the single place where
//! chain linking and signing happen.

use crate::chain::ChainState;
use crate::entry::{
    deterministic_timestamp, DurabilityStatus, LedgerEntry, LedgerEntryDraft, VerificationStatus,
    LEDGER_SCHEMA_VERSION,
};
use crate::keystore::{KeyStatus, SigningKeyStore};
use crate::store::LedgerStore;
use agenomic_core::{CliError, CliResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Structured result of verifying a ledger end-to-end (Phase 1 scope: entry
/// hashes, chain wiring, signatures, key status; blocks/Merkle arrive in
/// Phase 3 and extend this report).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerVerification {
    pub entry_count: u64,
    /// Global + per-run chain wiring and sequence contiguity are intact.
    pub chain_valid: bool,
    /// Sequence number of the first entry that broke the chain, if any.
    pub broken_at_sequence: Option<u64>,
    /// Sequence numbers whose recomputed entry hash mismatches (tampering).
    pub hash_failures: Vec<u64>,
    /// Sequence numbers whose Ed25519 signature does not verify.
    pub signature_failures: Vec<u64>,
    /// Sequence numbers whose key resolution failed (unknown key id).
    pub unresolved_key_failures: Vec<u64>,
    /// Sequence numbers signed by a revoked key (verifies, but flagged).
    pub revoked_key_warnings: Vec<u64>,
    /// Entry hash of the latest entry (genesis constant when empty).
    pub head_hash: String,
    /// True only when the chain is intact and every hash and signature
    /// verified. Revoked-key warnings do not clear this flag on their own —
    /// they are warnings — but they must be surfaced to the caller.
    pub valid: bool,
}

/// Verify an ordered slice of entries against a key resolver. Pure — no I/O
/// beyond the resolver; usable offline against an exported chain.
pub fn verify_entries(
    entries: &[LedgerEntry],
    keys: &dyn SigningKeyStore,
) -> CliResult<LedgerVerification> {
    let mut chain = ChainState::new();
    let mut chain_valid = true;
    let mut broken_at_sequence = None;
    let mut hash_failures = Vec::new();
    let mut signature_failures = Vec::new();
    let mut unresolved_key_failures = Vec::new();
    let mut revoked_key_warnings = Vec::new();
    let mut head_hash = crate::canonical::GENESIS_ENTRY_HASH.to_string();

    for entry in entries {
        // 1. Chain wiring (only until the first break — positions after a
        //    break are meaningless).
        if chain_valid {
            let expected = chain.allocate(&entry.run_id);
            if entry.sequence_number != expected.sequence_number
                || entry.previous_entry_hash != expected.previous_entry_hash
                || entry.run_sequence_number != expected.run_sequence_number
                || entry.previous_run_entry_hash != expected.previous_run_entry_hash
            {
                chain_valid = false;
                broken_at_sequence = Some(entry.sequence_number);
            } else {
                chain.advance(entry);
            }
        }

        // 2. Content hash (tamper detection) — checked for every entry.
        if !entry.hash_is_valid()? {
            hash_failures.push(entry.sequence_number);
        }

        // 3. Signature + key status.
        match keys.verifying_key(&entry.signing_key_id) {
            Ok(vk) => {
                if entry.verify_signature(&vk).is_err() {
                    signature_failures.push(entry.sequence_number);
                } else if keys.key_status(&entry.signing_key_id)? == KeyStatus::Revoked {
                    revoked_key_warnings.push(entry.sequence_number);
                }
            }
            Err(_) => unresolved_key_failures.push(entry.sequence_number),
        }

        head_hash = entry.entry_hash.clone();
    }

    let valid = chain_valid
        && hash_failures.is_empty()
        && signature_failures.is_empty()
        && unresolved_key_failures.is_empty();

    Ok(LedgerVerification {
        entry_count: entries.len() as u64,
        chain_valid,
        broken_at_sequence,
        hash_failures,
        signature_failures,
        unresolved_key_failures,
        revoked_key_warnings,
        head_hash,
        valid,
    })
}

/// Append-and-verify service over a store and a keystore.
pub struct Ledger<S: LedgerStore, K: SigningKeyStore> {
    store: S,
    keys: K,
    chain: ChainState,
}

impl<S: LedgerStore, K: SigningKeyStore> Ledger<S, K> {
    /// Open a ledger, rebuilding chain state from the store. Fails closed
    /// with [`CliError::LedgerIntegrity`] if the persisted chain is
    /// inconsistent — a broken store must not be silently extended.
    ///
    /// ```
    /// # use agenomic_ledger_local::ledger::Ledger;
    /// # use agenomic_ledger_local::store::MemoryLedgerStore;
    /// # use agenomic_ledger_local::keystore::FileKeyStore;
    /// # let dir = tempfile::tempdir().unwrap();
    /// let mut keys = FileKeyStore::open(dir.path()).unwrap();
    /// keys.generate().unwrap();
    /// let ledger = Ledger::open(MemoryLedgerStore::new(), keys).unwrap();
    /// assert_eq!(ledger.len(), 0);
    /// ```
    pub fn open(store: S, keys: K) -> CliResult<Self> {
        let entries = store.read_all()?;
        let chain = ChainState::from_entries(&entries)?;
        Ok(Self { store, keys, chain })
    }

    /// Seal a draft into a signed, chain-linked entry and persist it.
    ///
    /// The entry is canonicalized, domain-hash-digested, signed with the
    /// active key ("sign the hash, not the body"), and appended. Returns the
    /// sealed entry in `ledger_appended` state.
    pub fn append(&mut self, draft: LedgerEntryDraft) -> CliResult<LedgerEntry> {
        let event_payload_hash = draft.payload.resolve()?;
        let pos = self.chain.allocate(&draft.run_id);
        let signing_key_id = self.keys.active_key_id()?;
        let timestamp = deterministic_timestamp(draft.timestamp.unwrap_or_else(Utc::now));

        let mut entry = LedgerEntry {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            ledger_entry_id: ulid::Ulid::new().to_string(),
            event_id: draft
                .event_id
                .unwrap_or_else(|| ulid::Ulid::new().to_string()),
            agent_id: draft.agent_id,
            run_id: draft.run_id,
            turn_id: draft.turn_id,
            session_id: draft.session_id,
            genome_hash: draft.genome_hash,
            release_id: draft.release_id,
            event_type: draft.event_type,
            event_payload_hash,
            redacted_payload_preview: draft.redacted_payload_preview,
            sequence_number: pos.sequence_number,
            run_sequence_number: pos.run_sequence_number,
            turn_sequence_number: draft.turn_sequence_number,
            timestamp,
            previous_entry_hash: pos.previous_entry_hash,
            previous_run_entry_hash: pos.previous_run_entry_hash,
            merkle_root: None,
            hash_algorithm: "blake3".to_string(),
            signature_algorithm: "ed25519".to_string(),
            ingestion_source: draft.ingestion_source,
            entry_hash: String::new(),
            signature: String::new(),
            signing_key_id,
            durability_status: DurabilityStatus::Hashed,
            verification_status: VerificationStatus::Unverified,
        };

        let digest = entry.compute_digest()?;
        entry.entry_hash = crate::canonical::entry_hash_from_digest(&digest);
        let (signer_id, signature) = self.keys.sign(&digest)?;
        if signer_id != entry.signing_key_id {
            // The active key changed between allocation and signing (e.g. a
            // concurrent rotation). The key id is part of the signed surface,
            // so a mismatch would produce an unverifiable entry — refuse.
            return Err(CliError::LedgerConflict {
                reason: format!(
                    "active key changed during append ({} -> {signer_id}); retry",
                    entry.signing_key_id
                ),
            });
        }
        entry.signature = signature;
        entry.durability_status = DurabilityStatus::LedgerAppended;

        self.store.append(&entry)?;
        self.chain.advance(&entry);
        Ok(entry)
    }

    /// Verify the whole ledger (chain, hashes, signatures, key status).
    pub fn verify(&self) -> CliResult<LedgerVerification> {
        verify_entries(&self.store.read_all()?, &self.keys)
    }

    /// All entries in append order.
    pub fn read_all(&self) -> CliResult<Vec<LedgerEntry>> {
        self.store.read_all()
    }

    /// Entries belonging to `run_id`, in run-chain order.
    pub fn read_run(&self, run_id: &str) -> CliResult<Vec<LedgerEntry>> {
        Ok(self
            .store
            .read_all()?
            .into_iter()
            .filter(|e| e.run_id == run_id)
            .collect())
    }

    /// Number of entries in the chain.
    pub fn len(&self) -> u64 {
        self.chain.len()
    }

    /// Whether the ledger has no entries.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Entry hash of the latest entry (genesis constant when empty).
    pub fn head_hash(&self) -> &str {
        self.chain.head_hash()
    }

    /// The underlying keystore (e.g. for CLI key listing).
    pub fn keystore(&self) -> &K {
        &self.keys
    }

    /// Mutable keystore access (rotate/revoke via the CLI).
    pub fn keystore_mut(&mut self) -> &mut K {
        &mut self.keys
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::ChainPositions;
    use crate::entry::{IngestionSource, PayloadCommitment};
    use crate::keystore::FileKeyStore;
    use crate::store::MemoryLedgerStore;
    use serde_json::json;
    use tempfile::tempdir;

    /// Unsigned entry occupying `pos` — shared with store tests.
    pub(crate) fn unsigned_entry_at(run_id: &str, pos: &ChainPositions) -> LedgerEntry {
        LedgerEntry {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            ledger_entry_id: format!("entry-{}", pos.sequence_number),
            event_id: format!("event-{}", pos.sequence_number),
            agent_id: "agent://acme/support".into(),
            run_id: run_id.into(),
            turn_id: None,
            session_id: None,
            genome_hash: None,
            release_id: None,
            event_type: "agent.started".into(),
            event_payload_hash: crate::canonical::payload_hash(&json!({})),
            redacted_payload_preview: None,
            sequence_number: pos.sequence_number,
            run_sequence_number: pos.run_sequence_number,
            turn_sequence_number: None,
            timestamp: "2026-07-06T12:00:00.000000Z".into(),
            previous_entry_hash: pos.previous_entry_hash.clone(),
            previous_run_entry_hash: pos.previous_run_entry_hash.clone(),
            merkle_root: None,
            hash_algorithm: "blake3".into(),
            signature_algorithm: "ed25519".into(),
            ingestion_source: IngestionSource::Cli,
            entry_hash: String::new(),
            signature: "00".repeat(64),
            signing_key_id: "ed25519:0000000000000000".into(),
            durability_status: DurabilityStatus::LedgerAppended,
            verification_status: VerificationStatus::Unverified,
        }
    }

    fn draft(run_id: &str, event_type: &str) -> LedgerEntryDraft {
        LedgerEntryDraft::new(
            "agent://acme/support",
            run_id,
            event_type,
            PayloadCommitment::Inline(json!({ "k": "v", "n": 1 })),
            IngestionSource::Cli,
        )
    }

    fn ledger_with_keys(dir: &std::path::Path) -> Ledger<MemoryLedgerStore, FileKeyStore> {
        let mut keys = FileKeyStore::open(dir).unwrap();
        keys.generate().unwrap();
        Ledger::open(MemoryLedgerStore::new(), keys).unwrap()
    }

    #[test]
    fn append_chains_signs_and_verifies() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        for i in 0..4 {
            let run = if i % 2 == 0 { "run-a" } else { "run-b" };
            let e = ledger.append(draft(run, "agent.started")).unwrap();
            assert_eq!(e.sequence_number, i);
            assert_eq!(e.durability_status, DurabilityStatus::LedgerAppended);
            assert!(e.entry_hash.starts_with("blake3:"));
        }
        let v = ledger.verify().unwrap();
        assert!(v.valid, "expected valid ledger: {v:?}");
        assert!(v.chain_valid);
        assert_eq!(v.entry_count, 4);
        assert_eq!(v.head_hash, ledger.head_hash());
        assert!(v.revoked_key_warnings.is_empty());
    }

    #[test]
    fn tampering_one_field_is_detected_at_the_right_sequence() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        for _ in 0..3 {
            ledger.append(draft("run-a", "agent.started")).unwrap();
        }
        let mut entries = ledger.read_all().unwrap();
        entries[1].event_type = "agent.completed".into();
        let v = verify_entries(&entries, ledger.keystore()).unwrap();
        assert!(!v.valid);
        assert_eq!(v.hash_failures, vec![1]);
        // The signature covers the same digest, so it fails too.
        assert_eq!(v.signature_failures, vec![1]);
        // Chain wiring itself is untouched by a content mutation.
        assert!(v.chain_valid);
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        for _ in 0..3 {
            ledger.append(draft("run-a", "agent.started")).unwrap();
        }
        let mut entries = ledger.read_all().unwrap();
        entries.swap(1, 2);
        let v = verify_entries(&entries, ledger.keystore()).unwrap();
        assert!(!v.chain_valid);
        assert_eq!(v.broken_at_sequence, Some(2));
    }

    #[test]
    fn rotation_mid_run_keeps_history_verifiable() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        let before = ledger.append(draft("run-a", "agent.started")).unwrap();
        let old_key = before.signing_key_id.clone();

        ledger.keystore_mut().rotate().unwrap();
        let after = ledger.append(draft("run-a", "agent.completed")).unwrap();
        assert_ne!(after.signing_key_id, old_key);

        let v = ledger.verify().unwrap();
        assert!(v.valid, "history must verify after rotation: {v:?}");
        assert!(v.revoked_key_warnings.is_empty());
    }

    #[test]
    fn revoked_key_entries_are_flagged_not_failed() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        let e = ledger.append(draft("run-a", "agent.started")).unwrap();
        let old_key = e.signing_key_id.clone();
        ledger.keystore_mut().rotate().unwrap();
        ledger.append(draft("run-a", "agent.completed")).unwrap();
        ledger.keystore_mut().revoke(&old_key).unwrap();

        let v = ledger.verify().unwrap();
        // Cryptographically intact...
        assert!(v.valid);
        assert!(v.signature_failures.is_empty());
        // ...but the revoked key is surfaced.
        assert_eq!(v.revoked_key_warnings, vec![0]);
    }

    #[test]
    fn reopen_continues_the_chain() {
        let dir = tempdir().unwrap();
        let store_dir = tempdir().unwrap();
        let mut keys = FileKeyStore::open(dir.path()).unwrap();
        keys.generate().unwrap();
        {
            let store = crate::store::FileLedgerStore::open(store_dir.path()).unwrap();
            let mut ledger = Ledger::open(store, keys).unwrap();
            ledger.append(draft("run-a", "agent.started")).unwrap();
            ledger.append(draft("run-a", "agent.turn.started")).unwrap();
        }
        let keys = FileKeyStore::open(dir.path()).unwrap();
        let store = crate::store::FileLedgerStore::open(store_dir.path()).unwrap();
        let mut ledger = Ledger::open(store, keys).unwrap();
        assert_eq!(ledger.len(), 2);
        let e = ledger.append(draft("run-a", "agent.completed")).unwrap();
        assert_eq!(e.sequence_number, 2);
        assert_eq!(e.run_sequence_number, 2);
        let v = ledger.verify().unwrap();
        assert!(v.valid);
    }

    #[test]
    fn unknown_key_id_is_a_resolution_failure() {
        let dir = tempdir().unwrap();
        let mut ledger = ledger_with_keys(dir.path());
        ledger.append(draft("run-a", "agent.started")).unwrap();
        let mut entries = ledger.read_all().unwrap();
        // Simulate a chain signed by a key this keystore has never seen.
        entries[0].signing_key_id = "ed25519:ffffffffffffffff".into();
        let v = verify_entries(&entries, ledger.keystore()).unwrap();
        assert!(!v.valid);
        // The key id is inside the signed surface, so the hash breaks too.
        assert_eq!(v.hash_failures, vec![0]);
        assert_eq!(v.unresolved_key_failures, vec![0]);
    }
}
