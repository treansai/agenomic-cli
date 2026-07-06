//! Snapshot the canonical (hashed/signed) form of a fixed entry.
//!
//! These snapshots ARE the wire-format contract: if one changes, the entry
//! hash of every existing ledger changes with it. Any intentional change
//! requires bumping `LEDGER_ENTRY_DOMAIN` / `LEDGER_SCHEMA_VERSION` and a
//! migration note — never just re-accept the snapshot.

use agenomic_ledger_local::entry::{
    DurabilityStatus, IngestionSource, LedgerEntry, VerificationStatus, LEDGER_SCHEMA_VERSION,
};
use agenomic_ledger_local::{payload_hash, GENESIS_ENTRY_HASH};
use serde_json::json;

fn fixed_entry() -> LedgerEntry {
    LedgerEntry {
        schema_version: LEDGER_SCHEMA_VERSION.to_string(),
        ledger_entry_id: "01JZFIXEDENTRY0000000000ZZ".to_string(),
        event_id: "01JZFIXEDEVENT0000000000ZZ".to_string(),
        agent_id: "agent://acme/support".to_string(),
        run_id: "run-1".to_string(),
        turn_id: Some("turn-1".to_string()),
        session_id: Some("sess-1".to_string()),
        genome_hash: Some(
            "blake3-merkle-v1:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        ),
        release_id: None,
        event_type: "agent.started".to_string(),
        event_payload_hash: payload_hash(&json!({ "env": "dev", "n": 1 })),
        redacted_payload_preview: None,
        sequence_number: 0,
        run_sequence_number: 0,
        turn_sequence_number: Some(0),
        timestamp: "2026-07-06T12:00:00.000000Z".to_string(),
        previous_entry_hash: GENESIS_ENTRY_HASH.to_string(),
        previous_run_entry_hash: GENESIS_ENTRY_HASH.to_string(),
        merkle_root: None,
        hash_algorithm: "blake3".to_string(),
        signature_algorithm: "ed25519".to_string(),
        ingestion_source: IngestionSource::Tracking,
        entry_hash: String::new(),
        signature: String::new(),
        signing_key_id: "ed25519:0011223344556677".to_string(),
        durability_status: DurabilityStatus::LedgerAppended,
        verification_status: VerificationStatus::Unverified,
    }
}

#[test]
fn canonical_core_snapshot() {
    let core = fixed_entry().canonical_core().unwrap();
    insta::assert_snapshot!("canonical_core", core);
}

#[test]
fn entry_hash_snapshot() {
    let hash = fixed_entry().compute_entry_hash().unwrap();
    insta::assert_snapshot!("entry_hash", hash);
}

#[test]
fn genesis_constant_snapshot() {
    insta::assert_snapshot!("genesis_entry_hash", GENESIS_ENTRY_HASH);
}
