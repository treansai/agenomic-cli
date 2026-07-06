//! Phase 3 tests: block sealing triggers, the §5.9 verification engine,
//! and the canonical tamper scenario (mutate one byte of a persisted entry
//! → verification fails with correct diagnostics).

use agenomic_ledger_local::config::{LedgerConfig, LedgerMode};
use agenomic_ledger_local::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
use agenomic_ledger_local::keystore::FileKeyStore;
use agenomic_ledger_local::pipeline::LedgerPipeline;
use agenomic_ledger_local::store::FileLedgerStore;
use agenomic_ledger_local::verify::verify_ledger;
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

const FLUSH: Duration = Duration::from_secs(20);

struct Dirs {
    _root: tempfile::TempDir,
    store: std::path::PathBuf,
    wal: std::path::PathBuf,
    dead_letter: std::path::PathBuf,
    keys: std::path::PathBuf,
    blocks: std::path::PathBuf,
}

fn dirs() -> Dirs {
    let root = tempdir().unwrap();
    let base = root.path().to_path_buf();
    Dirs {
        _root: root,
        store: base.join("store"),
        wal: base.join("wal"),
        dead_letter: base.join("dead-letter"),
        keys: base.join("keys"),
        blocks: base.join("blocks.jsonl"),
    }
}

fn keystore(dir: &Path) -> FileKeyStore {
    let mut keys = FileKeyStore::open(dir).unwrap();
    if keys.list().is_empty() {
        keys.generate().unwrap();
    }
    keys
}

fn start(d: &Dirs, config: LedgerConfig) -> LedgerPipeline<FileLedgerStore, FileKeyStore> {
    LedgerPipeline::start(
        FileLedgerStore::open(&d.store).unwrap(),
        keystore(&d.keys),
        Some(&d.wal),
        Some(&d.dead_letter),
        Some(&d.blocks),
        config,
    )
    .unwrap()
    .0
}

fn draft(event_id: &str, run: &str, n: u64) -> LedgerEntryDraft {
    let mut d = LedgerEntryDraft::new(
        "agent://acme/support",
        run,
        "agent.started",
        PayloadCommitment::Inline(json!({ "n": n })),
        IngestionSource::Tracking,
    );
    d.event_id = Some(event_id.to_string());
    d
}

#[test]
fn count_trigger_seals_blocks_and_explicit_seal_takes_the_tail() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            block_max_entries: Some(3),
            block_max_age_ms: None,
            ..LedgerConfig::default()
        },
    );
    for n in 0..7u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    pipeline.flush(FLUSH).unwrap();

    let blocks = pipeline.blocks().unwrap();
    assert_eq!(blocks.len(), 2, "two count-triggered seals");
    assert_eq!(
        (
            blocks[0].start_sequence_number,
            blocks[0].end_sequence_number
        ),
        (0, 2)
    );
    assert_eq!(
        (
            blocks[1].start_sequence_number,
            blocks[1].end_sequence_number
        ),
        (3, 5)
    );
    assert_eq!(blocks[1].previous_block_hash, blocks[0].block_hash);

    // Explicit flush trigger takes the unsealed tail (entry 6).
    let tail = pipeline.seal().unwrap().expect("tail sealed");
    assert_eq!(
        (tail.start_sequence_number, tail.end_sequence_number),
        (6, 6)
    );
    assert!(pipeline.seal().unwrap().is_none(), "nothing left to seal");

    let report = pipeline.verify().unwrap();
    assert!(report.passed, "{report:?}");
    assert!(report.blocks.valid);
    assert_eq!(report.blocks.block_count, 3);
    assert!(report.blocks.unsealed_tail.is_none());
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn age_trigger_seals_after_max_age() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            block_max_entries: None,
            block_max_age_ms: Some(50),
            ..LedgerConfig::default()
        },
    );
    pipeline.append(draft("e-0", "run-1", 0)).unwrap();
    pipeline.append(draft("e-1", "run-1", 1)).unwrap();
    pipeline.flush(FLUSH).unwrap();

    // Poll until the worker's age tick seals (bounded wait, no fixed sleep).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !pipeline.blocks().unwrap().is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "age trigger did not seal within 5s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let blocks = pipeline.blocks().unwrap();
    assert_eq!(blocks[0].entry_count, 2);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn shutdown_seals_the_unsealed_tail() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            block_max_entries: Some(100),
            block_max_age_ms: None,
            ..LedgerConfig::default()
        },
    );
    for n in 0..4u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    pipeline.shutdown(FLUSH).unwrap();

    // Reopen: the shutdown seal covered everything.
    let pipeline = start(&d, LedgerConfig::default());
    let blocks = pipeline.blocks().unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].entry_count, 4);
    let report = pipeline.verify().unwrap();
    assert!(report.passed);
    assert!(report.blocks.unsealed_tail.is_none());
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn strict_mode_seals_by_count_inline() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            mode: LedgerMode::StrictVerified,
            block_max_entries: Some(2),
            block_max_age_ms: None,
            ..LedgerConfig::default()
        },
    );
    for n in 0..4u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    assert_eq!(pipeline.blocks().unwrap().len(), 2, "inline count seals");
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn tamper_one_byte_fails_verification_with_correct_diagnostics() {
    let d = dirs();
    {
        let pipeline = start(
            &d,
            LedgerConfig {
                block_max_entries: Some(2),
                block_max_age_ms: None,
                ..LedgerConfig::default()
            },
        );
        for n in 0..4u64 {
            pipeline
                .append(draft(&format!("e-{n}"), "run-1", n))
                .unwrap();
        }
        pipeline.shutdown(FLUSH).unwrap();
    }

    // Mutate ONE byte of the persisted entry at sequence 1: flip a hex
    // character inside its event_payload_hash (JSON stays parseable).
    let log = d.store.join("ledger.jsonl");
    let raw = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = raw.lines().map(String::from).collect();
    let needle = "\"event_payload_hash\":\"blake3:";
    let pos = lines[1].find(needle).expect("payload hash present") + needle.len();
    let mut bytes = lines[1].clone().into_bytes();
    bytes[pos] = if bytes[pos] == b'0' { b'1' } else { b'0' };
    lines[1] = String::from_utf8(bytes).unwrap();
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();

    // Verify offline over the tampered files (no pipeline — the store
    // itself is the evidence).
    let store = agenomic_ledger_local::store::FileLedgerStore::open(&d.store).unwrap();
    let entries = agenomic_ledger_local::store::LedgerStore::read_all(&store).unwrap();
    let blocks = agenomic_ledger_local::block::BlockChain::open(&d.blocks)
        .unwrap()
        .blocks()
        .to_vec();
    let keys = keystore(&d.keys);
    let report = verify_ledger(&entries, &blocks, &keys, Some(&d.wal)).unwrap();

    assert!(!report.passed, "tampering must fail verification");
    assert_eq!(
        report.first_invalid_sequence,
        Some(1),
        "correct entry named"
    );
    assert_eq!(report.entries.hash_failures, vec![1]);
    assert_eq!(report.entries.signature_failures, vec![1]);
    assert!(report
        .recommendations
        .iter()
        .any(|r| r.contains("tampering")));

    // Complementary layer: tampering the STORED entry_hash instead (to make
    // the content check pass again) breaks the block commitments and the
    // chain wiring — the two layers close each other's escape hatch.
    let mut rehashed = entries.clone();
    rehashed[1].entry_hash = rehashed[1].compute_entry_hash().unwrap();
    let report = verify_ledger(&rehashed, &blocks, &keys, Some(&d.wal)).unwrap();
    assert!(!report.passed);
    assert!(
        report.entries.hash_failures.is_empty(),
        "content matches again"
    );
    // ...but the signature still fails (signed digest changed), the global
    // chain breaks at the next entry, and the sealed block no longer covers
    // these hashes.
    assert_eq!(report.entries.signature_failures, vec![1]);
    assert!(!report.entries.chain_valid);
    assert!(
        !report.blocks.merkle_mismatches.is_empty()
            && !report.blocks.entries_hash_mismatches.is_empty(),
        "block commitments must break: {report:?}"
    );
}

#[test]
fn missing_entries_surface_as_gaps_not_chain_breaks() {
    let d = dirs();
    let pipeline = start(&d, LedgerConfig::default());
    for n in 0..5u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    pipeline.flush(FLUSH).unwrap();
    let mut entries = pipeline.read_all().unwrap();
    let keys = keystore(&d.keys);
    pipeline.shutdown(FLUSH).unwrap();

    // Simulate a partial export: entry 2 is missing.
    entries.remove(2);
    let report = verify_ledger(&entries, &[], &keys, None).unwrap();
    assert!(!report.passed);
    assert!(!report.chain_evaluated, "wiring not judged across a gap");
    assert_eq!(report.sequence_gaps, vec![(2, 2)]);
    assert!(report
        .recommendations
        .iter()
        .any(|r| r.contains("missing events")));
    // Individual entries still verify (hashes + signatures intact).
    assert!(report.entries.hash_failures.is_empty());
    assert!(report.entries.signature_failures.is_empty());
}

#[test]
fn duplicate_and_conflicting_event_ids_are_reported() {
    let d = dirs();
    let pipeline = start(&d, LedgerConfig::default());
    for n in 0..3u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    pipeline.flush(FLUSH).unwrap();
    let entries = pipeline.read_all().unwrap();
    let keys = keystore(&d.keys);
    pipeline.shutdown(FLUSH).unwrap();

    // Duplicate: the same entry appears twice (e.g. a doubled export line).
    let mut duplicated = entries.clone();
    duplicated.push(entries[1].clone());
    let report = verify_ledger(&duplicated, &[], &keys, None).unwrap();
    assert!(!report.passed);
    assert_eq!(report.duplicate_sequences, vec![1]);
    assert_eq!(report.duplicate_event_ids, vec!["e-1".to_string()]);

    // Conflict: same event id, divergent payload hash (tampering warning).
    let mut conflicted = entries.clone();
    let mut fork = entries[2].clone();
    fork.sequence_number = 3;
    fork.event_payload_hash = format!("blake3:{}", "ab".repeat(32));
    conflicted.push(fork);
    let report = verify_ledger(&conflicted, &[], &keys, None).unwrap();
    assert!(!report.passed);
    assert_eq!(report.conflicting_event_ids, vec!["e-2".to_string()]);
    assert!(report
        .recommendations
        .iter()
        .any(|r| r.contains("tampering")));
}

#[test]
fn dropped_first_block_breaks_block_chain_wiring() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            block_max_entries: Some(2),
            block_max_age_ms: None,
            ..LedgerConfig::default()
        },
    );
    for n in 0..4u64 {
        pipeline
            .append(draft(&format!("e-{n}"), "run-1", n))
            .unwrap();
    }
    pipeline.flush(FLUSH).unwrap();
    let entries = pipeline.read_all().unwrap();
    let blocks = pipeline.blocks().unwrap();
    let keys = keystore(&d.keys);
    pipeline.shutdown(FLUSH).unwrap();
    assert_eq!(blocks.len(), 2);

    // An export that silently dropped block 0: wiring + coverage both flag.
    let partial = vec![blocks[1].clone()];
    let report = verify_ledger(&entries, &partial, &keys, None).unwrap();
    assert!(!report.passed);
    assert!(!report.blocks.chain_valid);
    assert_eq!(
        report.blocks.broken_at_block.as_deref(),
        Some(blocks[1].block_id.as_str())
    );
    assert_eq!(report.blocks.coverage_gaps, vec![(0, 1)]);
}

#[test]
fn verification_report_snapshot() {
    let d = dirs();
    let pipeline = start(
        &d,
        LedgerConfig {
            block_max_entries: Some(2),
            block_max_age_ms: None,
            ..LedgerConfig::default()
        },
    );
    for n in 0..3u64 {
        let run = if n < 2 { "run-a" } else { "run-b" };
        pipeline.append(draft(&format!("e-{n}"), run, n)).unwrap();
    }
    pipeline.flush(FLUSH).unwrap();
    let report = pipeline.verify().unwrap();
    pipeline.shutdown(FLUSH).unwrap();

    // Hashes/ids vary per run (fresh keys, ULIDs); redact them — the
    // snapshot pins the report SHAPE and the verdict logic.
    insta::assert_json_snapshot!("verification_report", report, {
        ".entries.head_hash" => "[hash]",
        ".chain_summary.head_hash" => "[hash]",
        ".chain_summary.runs.*.head_hash" => "[hash]",
    });
}
