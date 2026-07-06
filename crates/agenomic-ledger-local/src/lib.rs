//! Local append-only, tamper-evident cryptographic event ledger.
//!
//! A private hash chain, **not** a blockchain: no consensus, no distribution,
//! no tokens. Entries are canonicalized (RFC 8785-flavoured JSON, see
//! [`canonical`]), BLAKE3-hashed under a domain separator, linked into a
//! global chain and a per-run chain, signed with Ed25519 (detached, over the
//! 32-byte digest), and persisted append-only. Verification is fully offline.
//!
//! Design contract: `docs/plans/atep-ledger-plan.md` (Phase 0, signed off).
//! The ledger *extends* ATEP/tracking/governance/replay events — producers'
//! payloads are committed by hash, never re-encoded or mutated.

pub mod canonical;
pub mod chain;
pub mod config;
pub mod entry;
pub mod keystore;
pub mod ledger;
pub mod store;

pub use canonical::{
    canonical_json, payload_hash, prefixed_blake3, BLAKE3_PREFIX, GENESIS_ENTRY_HASH,
    LEDGER_ENTRY_DOMAIN,
};
pub use chain::{ChainPositions, ChainState, RunHead};
pub use config::{LedgerConfig, LedgerMode};
pub use entry::{
    deterministic_timestamp, DurabilityStatus, IngestionSource, LedgerEntry, LedgerEntryDraft,
    PayloadCommitment, VerificationStatus, LEDGER_SCHEMA_VERSION, VOLATILE_FIELDS,
};
pub use keystore::{FileKeyStore, KeyRecord, KeyStatus, SigningKeyStore, KEYS_MANIFEST_VERSION};
pub use ledger::{verify_entries, Ledger, LedgerVerification};
pub use store::{FileLedgerStore, LedgerStore, MemoryLedgerStore, LEDGER_MANIFEST_VERSION};
