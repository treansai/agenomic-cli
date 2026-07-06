//! End-to-end pipeline tests: the Phase 2 test plan (crash recovery,
//! corrupted segments, disk budget, backpressure, idempotent WAL replay,
//! and — above all — zero silent drops).

use agenomic_core::CliError;
use agenomic_ledger_local::config::{LedgerConfig, LedgerMode};
use agenomic_ledger_local::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
use agenomic_ledger_local::keystore::FileKeyStore;
use agenomic_ledger_local::pipeline::{AppendOutcome, LedgerPipeline};
use agenomic_ledger_local::store::FileLedgerStore;
use agenomic_ledger_local::wal::WalWriter;
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

fn start(
    d: &Dirs,
    config: LedgerConfig,
) -> (
    LedgerPipeline<FileLedgerStore, FileKeyStore>,
    agenomic_ledger_local::pipeline::RecoveryReport,
) {
    LedgerPipeline::start(
        FileLedgerStore::open(&d.store).unwrap(),
        keystore(&d.keys),
        Some(&d.wal),
        Some(&d.dead_letter),
        Some(&d.blocks),
        config,
    )
    .unwrap()
}

fn draft(event_id: &str, n: u64) -> LedgerEntryDraft {
    let mut d = LedgerEntryDraft::new(
        "agent://acme/support",
        "run-1",
        "agent.started",
        PayloadCommitment::Inline(json!({ "n": n })),
        IngestionSource::Tracking,
    );
    d.event_id = Some(event_id.to_string());
    d
}

#[test]
fn durable_mode_appends_everything_and_verifies() {
    let d = dirs();
    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert_eq!(recovery.replayed, 0);

    for n in 0..50u64 {
        let outcome = pipeline.append(draft(&format!("e-{n}"), n)).unwrap();
        assert!(matches!(outcome, AppendOutcome::WalPersisted { .. }));
    }
    pipeline.flush(FLUSH).unwrap();

    let status = pipeline.status().unwrap();
    assert_eq!(status.received, 50);
    assert_eq!(status.appended, 50);
    assert_eq!(status.dead_lettered, 0);
    assert_eq!(status.busy_rejections, 0);

    let verification = pipeline.verify().unwrap();
    assert!(verification.passed, "{verification:?}");
    assert_eq!(verification.entry_count, 50);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn duplicate_is_idempotent_and_divergent_hash_conflicts() {
    let d = dirs();
    let (pipeline, _) = start(&d, LedgerConfig::default());

    pipeline.append(draft("e-1", 1)).unwrap();
    pipeline.flush(FLUSH).unwrap();

    // Same event_id + same payload: idempotent success, no second entry.
    let outcome = pipeline.append(draft("e-1", 1)).unwrap();
    assert!(matches!(outcome, AppendOutcome::Duplicate { .. }));

    // Same event_id + different payload: conflict, never overwritten.
    let err = pipeline.append(draft("e-1", 999)).unwrap_err();
    assert!(matches!(err, CliError::LedgerConflict { .. }));

    pipeline.flush(FLUSH).unwrap();
    let status = pipeline.status().unwrap();
    assert_eq!(status.appended, 1);
    assert_eq!(status.duplicates, 1);
    assert_eq!(status.conflicts, 1);
    assert_eq!(
        status.dead_lettered, 1,
        "conflict is visible in dead-letter"
    );
    assert_eq!(pipeline.read_all().unwrap().len(), 1);

    let dl = agenomic_ledger_local::deadletter::DeadLetterStore::open(&d.dead_letter).unwrap();
    let records = dl.list().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].detail.contains("tampering"));
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn crash_recovery_replays_wal_without_loss_or_duplicates() {
    let d = dirs();
    // Simulate a crash: events reached the WAL but the sealer never ran
    // (write records directly, no pipeline).
    {
        let (mut wal, _) = WalWriter::open(&d.wal, 1 << 20, 1 << 24).unwrap();
        for n in 0..7u64 {
            let mut dr = draft(&format!("e-{n}"), n);
            dr.payload = PayloadCommitment::Hash(dr.payload.resolve().unwrap());
            wal.append(&dr).unwrap();
        }
    }

    // Restart: recovery replays all 7, exactly once.
    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert_eq!(recovery.replayed, 7);
    assert_eq!(recovery.deduplicated, 0);
    let v = pipeline.verify().unwrap();
    assert!(v.passed);
    assert_eq!(v.entry_count, 7);
    pipeline.shutdown(FLUSH).unwrap();

    // Second restart: checkpoint advanced, nothing replays, count stable.
    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert_eq!(recovery.replayed, 0);
    assert_eq!(pipeline.read_all().unwrap().len(), 7);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn lagging_checkpoint_deduplicates_instead_of_double_appending() {
    let d = dirs();
    {
        let (pipeline, _) = start(&d, LedgerConfig::default());
        for n in 0..5u64 {
            pipeline.append(draft(&format!("e-{n}"), n)).unwrap();
        }
        pipeline.shutdown(FLUSH).unwrap();
    }
    // Wipe the checkpoint: every WAL record looks pending again.
    std::fs::remove_file(d.wal.join("checkpoint.json")).unwrap();

    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert_eq!(recovery.replayed, 0, "no double appends");
    assert_eq!(recovery.deduplicated, 5, "replay was idempotent");
    assert_eq!(pipeline.read_all().unwrap().len(), 5);
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn corrupted_segment_is_quarantined_and_reported_at_startup() {
    let d = dirs();
    {
        let config = LedgerConfig {
            wal_segment_max_bytes: 64, // force multiple segments
            ..LedgerConfig::default()
        };
        let (mut wal, _) = WalWriter::open(&d.wal, config.wal_segment_max_bytes, 1 << 24).unwrap();
        for n in 0..4u64 {
            let mut dr = draft(&format!("e-{n}"), n);
            dr.payload = PayloadCommitment::Hash(dr.payload.resolve().unwrap());
            wal.append(&dr).unwrap();
        }
    }
    // Corrupt one byte in the first (non-final) segment.
    let first = d.wal.join("wal-00000001.wal");
    let mut raw = std::fs::read(&first).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    std::fs::write(&first, &raw).unwrap();

    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert!(
        !recovery.quarantined_segments.is_empty(),
        "surfaced, not hidden"
    );
    assert!(recovery.replayed > 0, "intact segments still recovered");
    // The quarantined segment is preserved on disk for forensics.
    assert!(d.wal.join(&recovery.quarantined_segments[0]).exists());
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn disk_budget_exhaustion_is_explicit_and_recoverable() {
    let d = dirs();
    let config = LedgerConfig {
        queue_max_disk_bytes: 2000, // tiny budget: the §5.7 disk-full fixture
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);

    let mut accepted = 0u64;
    let mut refused = 0u64;
    for n in 0..100u64 {
        match pipeline.append(draft(&format!("e-{n}"), n)) {
            Ok(_) => accepted += 1,
            Err(CliError::LedgerBusy { .. }) => refused += 1,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
    assert!(accepted > 0);
    assert!(
        refused > 0,
        "budget exhaustion is an explicit failure state"
    );
    assert_eq!(accepted + refused, 100, "zero silent outcomes");

    pipeline.flush(FLUSH).unwrap();
    let status = pipeline.status().unwrap();
    assert_eq!(
        status.appended, accepted,
        "everything accepted was appended"
    );
    assert_eq!(status.busy_rejections, refused);
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();

    // Recovery path: after the sealer drained the WAL, a restart accepts
    // events again (checkpointed segments are cleaned up).
    let (pipeline, _) = start(
        &d,
        LedgerConfig {
            queue_max_disk_bytes: 2000,
            ..LedgerConfig::default()
        },
    );
    pipeline.append(draft("post-recovery", 1000)).unwrap();
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn best_effort_backpressure_refuses_explicitly_never_drops() {
    let d = dirs();
    let config = LedgerConfig {
        mode: LedgerMode::BestEffortLowLatency,
        queue_max_memory_events: 2,
        worker_delay_ms: 15, // slow consumer: forces queue-full refusals
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);

    let mut enqueued = 0u64;
    let mut refused = 0u64;
    for n in 0..40u64 {
        match pipeline.append(draft(&format!("e-{n}"), n)) {
            Ok(AppendOutcome::Enqueued { .. }) => enqueued += 1,
            Err(CliError::LedgerBusy { .. }) => refused += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert!(refused > 0, "backpressure engaged");
    assert_eq!(enqueued + refused, 40, "every event accounted for");

    pipeline.flush(FLUSH).unwrap();
    let status = pipeline.status().unwrap();
    assert_eq!(status.appended, enqueued, "all accepted events landed");
    assert_eq!(status.busy_rejections, refused);
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn durable_overflow_spills_to_wal_and_preserves_run_order() {
    let d = dirs();
    let config = LedgerConfig {
        queue_max_memory_events: 1,
        worker_delay_ms: 10, // slow consumer: forces WAL-backlog spill
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);

    // In durable mode a slow consumer must never surface as an error: the
    // WAL is the spill buffer.
    for n in 0..30u64 {
        let outcome = pipeline.append(draft(&format!("e-{n}"), n)).unwrap();
        assert!(matches!(outcome, AppendOutcome::WalPersisted { .. }));
    }
    pipeline.flush(FLUSH).unwrap();

    let status = pipeline.status().unwrap();
    assert_eq!(status.appended, 30, "spilled events were all sealed");
    assert_eq!(status.busy_rejections, 0);

    // Per-run strict ordering survived the spill: run sequence numbers are
    // exactly arrival order (verify() also re-checks the run chain).
    let entries = pipeline.read_all().unwrap();
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.run_sequence_number, i as u64);
        assert_eq!(entry.event_id, format!("e-{i}"));
    }
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn strict_verified_returns_the_sealed_entry_synchronously() {
    let d = dirs();
    let config = LedgerConfig {
        mode: LedgerMode::StrictVerified,
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);

    let outcome = pipeline.append(draft("e-1", 1)).unwrap();
    let AppendOutcome::Appended(entry) = outcome else {
        panic!("strict mode must return the sealed entry");
    };
    assert!(entry.entry_hash.starts_with("blake3:"));
    assert!(entry.hash_is_valid().unwrap());
    assert_eq!(pipeline.read_all().unwrap().len(), 1, "synchronous persist");
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn strict_cloud_fails_closed_at_startup() {
    let d = dirs();
    let result = LedgerPipeline::start(
        FileLedgerStore::open(&d.store).unwrap(),
        keystore(&d.keys),
        Some(&d.wal),
        Some(&d.dead_letter),
        Some(&d.blocks),
        LedgerConfig {
            mode: LedgerMode::StrictCloud,
            ..LedgerConfig::default()
        },
    );
    match result {
        Err(CliError::LedgerCloudUnavailable { .. }) => {}
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("strict_cloud must fail closed"),
    }
}

#[test]
fn invalid_and_oversized_events_are_rejected_and_dead_lettered() {
    let d = dirs();
    let config = LedgerConfig {
        max_payload_bytes: 64,
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);

    // Empty run_id.
    let mut bad = draft("e-bad", 1);
    bad.run_id = "  ".into();
    assert!(pipeline.append(bad).is_err());

    // Oversized payload.
    let mut big = draft("e-big", 2);
    big.payload = PayloadCommitment::Inline(json!({ "blob": "x".repeat(500) }));
    assert!(pipeline.append(big).is_err());

    let status = pipeline.status().unwrap();
    assert_eq!(status.invalid, 2);
    assert_eq!(status.dead_lettered, 2, "explicit, inspectable failures");
    assert_eq!(status.appended, 0);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn load_accounting_proves_zero_silent_drops() {
    let d = dirs();
    let (pipeline, _) = start(&d, LedgerConfig::default());

    let total = 300u64;
    let mut outcomes = std::collections::HashMap::<&str, u64>::new();
    for n in 0..total {
        // Every 10th event is a duplicate of the previous one (same id +
        // same payload) to exercise the idempotent path under load.
        let (id, payload) = if n % 10 == 9 {
            (format!("e-{}", n - 1), n - 1)
        } else {
            (format!("e-{n}"), n)
        };
        let key = match pipeline.append(draft(&id, payload)) {
            Ok(AppendOutcome::WalPersisted { .. }) => "accepted",
            Ok(AppendOutcome::Duplicate { .. }) => "duplicate",
            Ok(_) => "other_ok",
            Err(CliError::LedgerBusy { .. }) => "busy",
            Err(CliError::LedgerConflict { .. }) => "conflict",
            Err(_) => "error",
        };
        *outcomes.entry(key).or_default() += 1;
    }
    pipeline.flush(FLUSH).unwrap();
    let status = pipeline.status().unwrap();

    // The invariant: every received event has exactly one explicit outcome.
    let explained = status.appended
        + status.duplicates
        + status.conflicts
        + status.invalid
        + status.busy_rejections;
    assert_eq!(status.received, total);
    assert_eq!(
        explained, total,
        "zero silent drops: {status:?} {outcomes:?}"
    );
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}

#[test]
fn shutdown_flushes_everything() {
    let d = dirs();
    let config = LedgerConfig {
        worker_delay_ms: 5,
        ..LedgerConfig::default()
    };
    let (pipeline, _) = start(&d, config);
    for n in 0..20u64 {
        pipeline.append(draft(&format!("e-{n}"), n)).unwrap();
    }
    // No explicit flush: shutdown must drain queue + backlog itself.
    let status = pipeline.shutdown(FLUSH).unwrap();
    assert_eq!(status.appended, 20);
    assert_eq!(status.queue_depth, 0);
    assert_eq!(status.wal_backlog, 0);

    // And the result is durable: a fresh open sees all 20, chain intact.
    let (pipeline, recovery) = start(&d, LedgerConfig::default());
    assert_eq!(recovery.replayed, 0);
    assert_eq!(pipeline.read_all().unwrap().len(), 20);
    assert!(pipeline.verify().unwrap().passed);
    pipeline.shutdown(FLUSH).unwrap();
}
