//! The ledger entry: the single record type of the ledger.
//!
//! An entry *extends* a producer event (tracking, ATEP, governance, replay) —
//! it never re-encodes or mutates it. The producer payload is committed by
//! `event_payload_hash` (Q4 `hash_only` default); the entry adds chain
//! position, hashes, and a signature.
//!
//! ## Hashed / signed surface
//!
//! The **core** of an entry is its canonical JSON with the volatile fields
//! removed: `entry_hash`, `signature`, `durability_status`,
//! `verification_status`. Everything else — including `signing_key_id`, which
//! binds the key to the entry — is covered. The 32-byte digest
//! `blake3(AGENOMIC-LEDGER-ENTRY-v1\0 ‖ canonical_json(core))` is both the
//! preimage of `entry_hash` and the exact message signed by Ed25519 ("sign
//! the hash, not the body" — the ATEP rule). Progressing the durability
//! state machine therefore never invalidates a hash or signature.

use crate::canonical::{canonical_json, entry_digest, entry_hash_from_digest};
use agenomic_core::{CliError, CliResult};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema version stamped on every entry. Bump on any breaking field change.
pub const LEDGER_SCHEMA_VERSION: &str = "agenomic.ledger/v0.1";

/// The fields excluded from the hashed/signed core. Order is irrelevant
/// (canonicalization sorts); membership is the contract.
pub const VOLATILE_FIELDS: &[&str] = &[
    "entry_hash",
    "signature",
    "durability_status",
    "verification_status",
];

/// Where an entry entered the ledger from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionSource {
    /// Online tracking (`agenomic-track` events).
    Tracking,
    /// ATEP store events (referenced by causal hash, never re-encoded).
    Atep,
    /// Governance engine descriptors.
    Governance,
    /// Local replay lifecycle events.
    Replay,
    /// Direct CLI append (`agenomic ledger append`).
    Cli,
}

impl IngestionSource {
    /// Stable snake_case label (matches the serde encoding).
    ///
    /// ```
    /// # use agenomic_ledger_local::entry::IngestionSource;
    /// assert_eq!(IngestionSource::Tracking.label(), "tracking");
    /// ```
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tracking => "tracking",
            Self::Atep => "atep",
            Self::Governance => "governance",
            Self::Replay => "replay",
            Self::Cli => "cli",
        }
    }
}

/// Durability state machine (plan §5.2 / prompt §5.2). Phase 1 appends jump
/// straight to `LedgerAppended`; the Phase 2 pipeline walks the earlier
/// states. Terminal failure states are explicit — silent drops are forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityStatus {
    Received,
    Queued,
    WalPersisted,
    Canonicalized,
    Hashed,
    Signed,
    LedgerAppended,
    CloudSyncPending,
    CloudSynced,
    Verified,
    Failed,
    DeadLettered,
}

/// Verification state of a persisted entry, updated by the verification
/// engine. Excluded from the signed surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Unverified,
    Verified,
    Failed,
}

/// How a draft commits its payload.
///
/// Serialization note: the WAL persists drafts, and the pipeline resolves
/// `Inline` payloads to their hash *before* the WAL write — so raw payloads
/// never touch disk (security §5.5). The `Inline` arm still round-trips for
/// in-memory use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PayloadCommitment {
    /// A JSON payload to be committed by canonical hash. The payload itself
    /// is never stored in the entry.
    Inline(Value),
    /// A precomputed content hash (e.g. an ATEP `causal_hash` rendered as
    /// `blake3:<hex>`, or a tracking `event_hash`). Must be a
    /// `blake3:`-prefixed 64-hex string.
    Hash(String),
}

impl PayloadCommitment {
    /// Resolve to the `blake3:`-prefixed payload hash.
    ///
    /// ```
    /// # use agenomic_ledger_local::entry::PayloadCommitment;
    /// # use serde_json::json;
    /// let h = PayloadCommitment::Inline(json!({"k": "v"})).resolve().unwrap();
    /// assert!(h.starts_with("blake3:"));
    /// ```
    pub fn resolve(&self) -> CliResult<String> {
        match self {
            Self::Inline(v) => Ok(crate::canonical::payload_hash(v)),
            Self::Hash(h) => {
                let hex_part =
                    h.strip_prefix("blake3:")
                        .ok_or_else(|| CliError::LedgerConflict {
                            reason: format!("payload hash must be blake3:-prefixed, got {h:?}"),
                        })?;
                if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(CliError::LedgerConflict {
                        reason: format!("payload hash is not 64 hex chars: {h:?}"),
                    });
                }
                Ok(h.clone())
            }
        }
    }
}

/// A producer event on its way into the ledger. The ledger assigns ids,
/// chain positions, hashes, and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntryDraft {
    /// Producer event id; assigned a fresh ULID if absent.
    pub event_id: Option<String>,
    pub agent_id: String,
    pub run_id: String,
    pub turn_id: Option<String>,
    pub session_id: Option<String>,
    pub genome_hash: Option<String>,
    pub release_id: Option<String>,
    pub event_type: String,
    pub payload: PayloadCommitment,
    /// Only persisted when `payload_storage_mode` allows it (opt-in; Q4).
    /// Redaction must have happened *before* this value was produced.
    pub redacted_payload_preview: Option<String>,
    /// Producer-supplied per-turn position (Q5: recorded, not chained in v1).
    pub turn_sequence_number: Option<u64>,
    /// Event time; defaults to now at seal time.
    pub timestamp: Option<DateTime<Utc>>,
    pub ingestion_source: IngestionSource,
}

impl LedgerEntryDraft {
    /// A minimal draft with only the required fields set.
    ///
    /// ```
    /// # use agenomic_ledger_local::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
    /// # use serde_json::json;
    /// let d = LedgerEntryDraft::new(
    ///     "agent://acme/support",
    ///     "run-1",
    ///     "agent.started",
    ///     PayloadCommitment::Inline(json!({"env": "dev"})),
    ///     IngestionSource::Cli,
    /// );
    /// assert!(d.event_id.is_none());
    /// ```
    pub fn new(
        agent_id: impl Into<String>,
        run_id: impl Into<String>,
        event_type: impl Into<String>,
        payload: PayloadCommitment,
        ingestion_source: IngestionSource,
    ) -> Self {
        Self {
            event_id: None,
            agent_id: agent_id.into(),
            run_id: run_id.into(),
            turn_id: None,
            session_id: None,
            genome_hash: None,
            release_id: None,
            event_type: event_type.into(),
            payload,
            redacted_payload_preview: None,
            turn_sequence_number: None,
            timestamp: None,
            ingestion_source,
        }
    }
}

/// A sealed, signed, chain-linked ledger entry.
///
/// Construct via [`crate::ledger::Ledger::append`]; deserialize from a store.
/// Field order here is irrelevant to hashing — the canonical form sorts keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub schema_version: String,
    /// ULID of this ledger entry (distinct from the producer `event_id`).
    pub ledger_entry_id: String,
    pub event_id: String,
    pub agent_id: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub event_type: String,
    /// `blake3:`-prefixed hash committing the producer payload.
    pub event_payload_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_payload_preview: Option<String>,
    /// Global (per-store) chain position, starting at 0.
    pub sequence_number: u64,
    /// Per-run chain position, starting at 0.
    pub run_sequence_number: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_sequence_number: Option<u64>,
    /// RFC 3339 UTC with fixed microsecond precision (deterministic form).
    pub timestamp: String,
    /// Hash of the previous entry in the global chain (genesis constant for
    /// the first entry).
    pub previous_entry_hash: String,
    /// Hash of the previous entry in this run's chain.
    pub previous_run_entry_hash: String,
    /// Set when the entry is covered by a sealed block (Phase 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    pub hash_algorithm: String,
    pub signature_algorithm: String,
    pub ingestion_source: IngestionSource,
    /// `blake3:`-prefixed hash of the domain-separated canonical core.
    pub entry_hash: String,
    /// Hex-encoded detached Ed25519 signature over the 32-byte entry digest.
    pub signature: String,
    /// Short key id (`ed25519:<8hex>`) of the signing key. Part of the
    /// signed surface (binds the key to the entry).
    pub signing_key_id: String,
    pub durability_status: DurabilityStatus,
    pub verification_status: VerificationStatus,
}

/// Normalise an event time to a stable microsecond-precision RFC 3339 string
/// (the same rule the cloud ledger uses so hashes survive storage
/// round-trips).
///
/// ```
/// # use agenomic_ledger_local::entry::deterministic_timestamp;
/// # use chrono::{TimeZone, Utc};
/// let t = Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap();
/// assert_eq!(deterministic_timestamp(t), "2026-07-06T12:00:00.000000Z");
/// ```
pub fn deterministic_timestamp(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

impl LedgerEntry {
    /// The canonical JSON string of this entry's core — the exact
    /// hashed/signed surface ([`VOLATILE_FIELDS`] removed).
    ///
    /// ```no_run
    /// # use agenomic_ledger_local::entry::LedgerEntry;
    /// # fn demo(entry: &LedgerEntry) -> agenomic_core::CliResult<()> {
    /// let core = entry.canonical_core()?;
    /// assert!(!core.contains("\"signature\""));
    /// # Ok(())
    /// # }
    /// ```
    pub fn canonical_core(&self) -> CliResult<String> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| CliError::Internal(format!("serialize ledger entry: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            for field in VOLATILE_FIELDS {
                obj.remove(*field);
            }
        }
        Ok(canonical_json(&value))
    }

    /// The 32-byte domain-separated digest of the canonical core. This is
    /// the signing message and the `entry_hash` preimage.
    pub fn compute_digest(&self) -> CliResult<[u8; 32]> {
        Ok(entry_digest(&self.canonical_core()?))
    }

    /// Recompute the `blake3:`-prefixed entry hash from the current fields.
    pub fn compute_entry_hash(&self) -> CliResult<String> {
        Ok(entry_hash_from_digest(&self.compute_digest()?))
    }

    /// Whether the stored `entry_hash` matches the recomputed one. `false`
    /// means the entry was tampered with after sealing.
    pub fn hash_is_valid(&self) -> CliResult<bool> {
        Ok(self.compute_entry_hash()? == self.entry_hash)
    }

    /// Verify the detached Ed25519 signature over the entry digest.
    ///
    /// Returns `Ok(())` on success; [`CliError::LedgerSignatureInvalid`] on a
    /// well-formed but wrong signature or malformed signature encoding.
    pub fn verify_signature(&self, vk: &ed25519_dalek::VerifyingKey) -> CliResult<()> {
        let invalid = || CliError::LedgerSignatureInvalid {
            entry_id: self.ledger_entry_id.clone(),
        };
        let raw = hex::decode(&self.signature).map_err(|_| invalid())?;
        let bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| invalid())?;
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        let digest = self.compute_digest()?;
        vk.verify_strict(&digest, &sig).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn fixed_entry() -> LedgerEntry {
        LedgerEntry {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            ledger_entry_id: "01JZFIXEDENTRY0000000000ZZ".to_string(),
            event_id: "01JZFIXEDEVENT0000000000ZZ".to_string(),
            agent_id: "agent://acme/support".to_string(),
            run_id: "run-1".to_string(),
            turn_id: None,
            session_id: Some("sess-1".to_string()),
            genome_hash: Some("blake3-merkle-v1:aa".to_string()),
            release_id: None,
            event_type: "agent.started".to_string(),
            event_payload_hash: crate::canonical::payload_hash(&json!({"env": "dev"})),
            redacted_payload_preview: None,
            sequence_number: 0,
            run_sequence_number: 0,
            turn_sequence_number: None,
            timestamp: "2026-07-06T12:00:00.000000Z".to_string(),
            previous_entry_hash: crate::canonical::GENESIS_ENTRY_HASH.to_string(),
            previous_run_entry_hash: crate::canonical::GENESIS_ENTRY_HASH.to_string(),
            merkle_root: None,
            hash_algorithm: "blake3".to_string(),
            signature_algorithm: "ed25519".to_string(),
            ingestion_source: IngestionSource::Cli,
            entry_hash: String::new(),
            signature: String::new(),
            signing_key_id: "ed25519:0000000000000000".to_string(),
            durability_status: DurabilityStatus::LedgerAppended,
            verification_status: VerificationStatus::Unverified,
        }
    }

    #[test]
    fn canonical_core_excludes_volatile_fields() {
        let mut e = fixed_entry();
        e.entry_hash = "blake3:ff".into();
        e.signature = "aa".into();
        let core = e.canonical_core().unwrap();
        assert!(!core.contains("\"entry_hash\":"));
        assert!(!core.contains("\"signature\":"));
        assert!(!core.contains("\"durability_status\":"));
        assert!(!core.contains("\"verification_status\":"));
        // The chain-link fields (different keys) stay covered.
        assert!(core.contains("\"previous_entry_hash\":"));
        assert!(core.contains("\"previous_run_entry_hash\":"));
        // But the signed surface DOES bind the key id and algorithms.
        assert!(core.contains("signing_key_id"));
        assert!(core.contains("\"hash_algorithm\":\"blake3\""));
    }

    #[test]
    fn volatile_fields_do_not_affect_digest() {
        let mut a = fixed_entry();
        let mut b = fixed_entry();
        a.durability_status = DurabilityStatus::Received;
        b.durability_status = DurabilityStatus::Verified;
        b.verification_status = VerificationStatus::Verified;
        b.entry_hash = "blake3:deadbeef".into();
        b.signature = "aa".repeat(64);
        assert_eq!(a.compute_digest().unwrap(), b.compute_digest().unwrap());
    }

    #[test]
    fn every_covered_field_changes_the_digest() {
        type Mutation = Box<dyn Fn(&mut LedgerEntry)>;
        let base = fixed_entry().compute_digest().unwrap();
        let mutations: Vec<Mutation> = vec![
            Box::new(|e| e.event_type = "agent.completed".into()),
            Box::new(|e| e.run_id = "run-2".into()),
            Box::new(|e| e.sequence_number = 7),
            Box::new(|e| e.run_sequence_number = 7),
            Box::new(|e| e.previous_entry_hash = "blake3:11".into()),
            Box::new(|e| e.previous_run_entry_hash = "blake3:11".into()),
            Box::new(|e| e.event_payload_hash = "blake3:22".into()),
            Box::new(|e| e.timestamp = "2027-01-01T00:00:00.000000Z".into()),
            Box::new(|e| e.signing_key_id = "ed25519:1111111111111111".into()),
            Box::new(|e| e.turn_id = Some("turn-1".into())),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let mut e = fixed_entry();
            m(&mut e);
            assert_ne!(
                base,
                e.compute_digest().unwrap(),
                "mutation {i} did not change the digest"
            );
        }
    }

    #[test]
    fn payload_commitment_rejects_malformed_hashes() {
        assert!(PayloadCommitment::Hash("sha256:ab".into())
            .resolve()
            .is_err());
        assert!(PayloadCommitment::Hash("blake3:xyz".into())
            .resolve()
            .is_err());
        assert!(
            PayloadCommitment::Hash(format!("blake3:{}", "a".repeat(64)))
                .resolve()
                .is_ok()
        );
    }

    #[test]
    fn entry_roundtrips_through_json() {
        let mut e = fixed_entry();
        e.entry_hash = e.compute_entry_hash().unwrap();
        let s = serde_json::to_string(&e).unwrap();
        let back: LedgerEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
        assert!(back.hash_is_valid().unwrap());
    }
}
