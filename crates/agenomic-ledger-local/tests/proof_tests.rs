//! Proof-bundle tests: assemble, verify offline with ONLY the bundle
//! contents (no keystore, no ledger dirs), and fail on tampering.

use agenomic_ledger_local::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
use agenomic_ledger_local::keystore::FileKeyStore;
use agenomic_ledger_local::ledger::Ledger;
use agenomic_ledger_local::proof::{
    assemble_bundle, build_ledger_proof, verify_bundle, BundleExtras,
};
use agenomic_ledger_local::store::MemoryLedgerStore;
use agenomic_ledger_local::BlockChain;
use serde_json::json;
use tempfile::tempdir;

fn build_ledger(
    keys_dir: &std::path::Path,
    blocks_path: &std::path::Path,
) -> (
    Ledger<MemoryLedgerStore, FileKeyStore>,
    Vec<agenomic_ledger_local::LedgerEntry>,
    Vec<agenomic_ledger_local::LedgerBlock>,
) {
    let mut keys = FileKeyStore::open(keys_dir).unwrap();
    keys.generate().unwrap();
    let mut ledger = Ledger::open(MemoryLedgerStore::new(), keys).unwrap();
    for (i, run) in ["run-a", "run-a", "run-b", "run-a"].iter().enumerate() {
        let mut d = LedgerEntryDraft::new(
            "agent://acme/support",
            *run,
            "agent.started",
            PayloadCommitment::Inline(json!({ "i": i })),
            IngestionSource::Tracking,
        );
        d.event_id = Some(format!("e-{i}"));
        ledger.append(d).unwrap();
    }
    let entries = ledger.read_all().unwrap();
    let mut chain = BlockChain::open(blocks_path).unwrap();
    let blocks = vec![chain.seal(&entries, ledger.keystore()).unwrap()];
    (ledger, entries, blocks)
}

#[test]
fn bundle_roundtrip_verifies_offline() {
    let keys_dir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let (ledger, entries, blocks) =
        build_ledger(keys_dir.path(), &work.path().join("blocks.jsonl"));

    let out = work.path().join("bundle");
    let manifest = assemble_bundle(
        &out,
        Some("run-a"),
        &entries,
        &blocks,
        ledger.keystore(),
        &BundleExtras::default(),
    )
    .unwrap();
    assert_eq!(manifest.probative_status, "non-probative (locally signed)");
    assert!(manifest
        .absent_members
        .contains(&"replay_report.json".to_string()));

    // Offline: nothing but the bundle directory (the keystore could be gone).
    let result = verify_bundle(&out).unwrap();
    assert!(result.manifest_signature_valid);
    assert!(result.member_hash_failures.is_empty());
    assert!(result.missing_members.is_empty());
    assert!(result.passed, "{result:?}");
    // Run-scoped bundle: 3 of 4 entries, entry integrity fully checked.
    assert_eq!(result.ledger.entry_count, 3);
    assert!(result.ledger.entries.hash_failures.is_empty());
}

#[test]
fn tampered_member_and_tampered_chain_fail() {
    let keys_dir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let (ledger, entries, blocks) =
        build_ledger(keys_dir.path(), &work.path().join("blocks.jsonl"));

    // Tampered member bytes → member hash failure.
    let out = work.path().join("bundle1");
    assemble_bundle(
        &out,
        None,
        &entries,
        &blocks,
        ledger.keystore(),
        &BundleExtras::default(),
    )
    .unwrap();
    let target = out.join("verification_report.json");
    let mut raw = std::fs::read(&target).unwrap();
    let last = raw.len() - 2;
    raw[last] ^= 0x01;
    std::fs::write(&target, raw).unwrap();
    let result = verify_bundle(&out).unwrap();
    assert!(!result.passed);
    assert_eq!(
        result.member_hash_failures,
        vec!["verification_report.json"]
    );

    // Tampered chain entry inside run_chain.jsonl → entry + manifest-member
    // failures both fire.
    let out2 = work.path().join("bundle2");
    assemble_bundle(
        &out2,
        None,
        &entries,
        &blocks,
        ledger.keystore(),
        &BundleExtras::default(),
    )
    .unwrap();
    let chain_path = out2.join("run_chain.jsonl");
    let text = std::fs::read_to_string(&chain_path).unwrap();
    let tampered = text.replacen("agent.started", "agent.stopped", 1);
    std::fs::write(&chain_path, tampered).unwrap();
    let result = verify_bundle(&out2).unwrap();
    assert!(!result.passed);
    assert!(!result.ledger.entries.hash_failures.is_empty());
    assert!(result
        .member_hash_failures
        .contains(&"run_chain.jsonl".to_string()));
}

#[test]
fn ledger_proof_reflects_run_state() {
    let keys_dir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let (ledger, entries, blocks) =
        build_ledger(keys_dir.path(), &work.path().join("blocks.jsonl"));

    let proof = build_ledger_proof("run-a", &entries, &blocks, ledger.keystore(), None, 0).unwrap();
    assert_eq!(proof.run_entry_count, 3);
    assert_eq!(proof.entry_range, Some((0, 3)));
    assert_eq!(proof.block_ids.len(), 1);
    assert_eq!(proof.signing_key_ids.len(), 1);
    assert!(proof.verification_passed);
    assert!(proof.chain_valid);
    assert_eq!(proof.dead_lettered, 0);
    assert_eq!(
        proof.run_head_hash,
        entries
            .iter()
            .filter(|e| e.run_id == "run-a")
            .next_back()
            .unwrap()
            .entry_hash
    );
}
