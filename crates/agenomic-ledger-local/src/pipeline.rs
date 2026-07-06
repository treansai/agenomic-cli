//! Durable ingestion pipeline: the non-blocking hot path, the background
//! sealer, and every explicit failure state in between.
//!
//! ## Threading model
//!
//! std threads + a bounded [`std::sync::mpsc::sync_channel`]. Decided at the
//! Phase 2 gate (see the plan §5.3): every stage is synchronous work — file
//! IO, BLAKE3, Ed25519 — and this workspace has no long-lived async runtime
//! anywhere, so a dedicated tokio runtime would add an ownership problem
//! without buying concurrency. The API surface is runtime-agnostic either
//! way (`start` / `append` / `flush` / `shutdown` / `status`).
//!
//! ## Hot path (`append`)
//!
//! validate minimal envelope → assign `event_id` → resolve the payload to
//! its hash (raw payloads never travel further) → dedup check → then by
//! mode: enqueue (best-effort), WAL-append + enqueue (durable, the default),
//! or seal inline (strict). Every outcome is explicit: accepted states in
//! [`AppendOutcome`], refusals as typed errors. **Nothing is ever silently
//! dropped** — the accounting invariant `received == appended + duplicates +
//! conflicts + invalid + busy_rejections + dead_lettered + in_flight` holds
//! at all times and is asserted by the load tests.
//!
//! ## Ordering
//!
//! One sealer worker per pipeline: chain linking is inherently serial, so
//! per-run strict ordering falls out of processing WAL/queue items in
//! arrival order. In durable mode, once anything has spilled to the WAL
//! backlog (queue full), subsequent events also spill until the worker
//! drains the backlog — the queue is never allowed to overtake the WAL.

use crate::block::{BlockChain, LedgerBlock};
use crate::config::{LedgerConfig, LedgerMode};
use crate::deadletter::{DeadLetterReason, DeadLetterStore};
use crate::entry::{LedgerEntry, LedgerEntryDraft, PayloadCommitment};
use crate::keystore::SigningKeyStore;
use crate::ledger::Ledger;
use crate::store::LedgerStore;
use crate::verify::VerificationReport;
use crate::wal::WalWriter;
use agenomic_core::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Result of a hot-path append. Which arm you get is a function of the
/// pipeline's [`LedgerMode`], never of load.
#[derive(Debug, Clone)]
pub enum AppendOutcome {
    /// Sealed, signed, persisted (strict_verified, and recovery replays).
    Appended(Box<LedgerEntry>),
    /// Durable in the WAL; sealing happens on the worker
    /// (durable_low_latency).
    WalPersisted { event_id: String, wal_seq: u64 },
    /// In the in-memory queue only (best_effort_low_latency).
    Enqueued { event_id: String },
    /// Same `event_id` + same payload hash already in the ledger —
    /// idempotent success, nothing re-appended.
    Duplicate { event_id: String },
}

impl AppendOutcome {
    /// The event id this outcome refers to.
    pub fn event_id(&self) -> &str {
        match self {
            Self::Appended(e) => &e.event_id,
            Self::WalPersisted { event_id, .. }
            | Self::Enqueued { event_id }
            | Self::Duplicate { event_id } => event_id,
        }
    }
}

/// Point-in-time pipeline health (the §5.2 states, exposed as counters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatus {
    pub mode: LedgerMode,
    /// Events accepted by `append` (all outcomes).
    pub received: u64,
    /// Sealed and persisted to the ledger.
    pub appended: u64,
    /// Idempotent duplicates (same id, same hash).
    pub duplicates: u64,
    /// Conflicts (same id, different hash) — dead-lettered, never applied.
    pub conflicts: u64,
    /// Drafts rejected by validation.
    pub invalid: u64,
    /// Explicit saturation refusals (queue full in best-effort, WAL disk
    /// budget exhausted in durable).
    pub busy_rejections: u64,
    /// Worker retry attempts performed.
    pub retries: u64,
    /// Events parked in the dead-letter store.
    pub dead_lettered: u64,
    /// Items currently in the in-memory queue.
    pub queue_depth: u64,
    /// Events durable in the WAL but not yet enqueued (spill backlog).
    pub wal_backlog: u64,
    /// Live WAL bytes on disk (0 when the mode has no WAL).
    pub wal_bytes: u64,
}

/// What pipeline startup recovered from the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Events replayed from the WAL into the ledger.
    pub replayed: u64,
    /// WAL records skipped because the ledger already contained them
    /// (checkpoint lag; dedup made replay idempotent).
    pub deduplicated: u64,
    /// Corrupt segments quarantined as `.corrupt` (preserved on disk).
    pub quarantined_segments: Vec<String>,
    /// Bytes truncated off a torn segment tail (crash artifact).
    pub truncated_bytes: u64,
}

#[derive(Default)]
struct Counters {
    received: AtomicU64,
    appended: AtomicU64,
    duplicates: AtomicU64,
    conflicts: AtomicU64,
    invalid: AtomicU64,
    busy_rejections: AtomicU64,
    retries: AtomicU64,
    dead_lettered: AtomicU64,
    queue_depth: AtomicU64,
    wal_backlog: AtomicU64,
}

/// Everything the sealer needs, behind one mutex (chain linking is serial
/// by design — see module docs).
struct Core<S: LedgerStore, K: SigningKeyStore> {
    ledger: Ledger<S, K>,
    /// `event_id` → `event_payload_hash` of every appended entry.
    dedup: HashMap<String, String>,
    wal: Option<WalWriter>,
    dead_letter: Option<DeadLetterStore>,
    applied_wal_seq: u64,
    /// Block sealing (None = blocks disabled).
    blocks: Option<BlockChain>,
    /// When the oldest currently-unsealed entry was appended (age trigger).
    oldest_unsealed_since: Option<std::time::Instant>,
    /// WAL dir for verification reports.
    wal_dir: Option<std::path::PathBuf>,
}

struct WorkItem {
    wal_seq: Option<u64>,
    draft: LedgerEntryDraft,
}

/// The ingestion pipeline. Construct with [`LedgerPipeline::start`]; always
/// call [`LedgerPipeline::shutdown`] for a clean flush (drop alone joins the
/// worker but skips the final flush wait).
pub struct LedgerPipeline<S: LedgerStore + Send + 'static, K: SigningKeyStore + Send + 'static> {
    core: Arc<Mutex<Core<S, K>>>,
    counters: Arc<Counters>,
    config: LedgerConfig,
    sender: Option<SyncSender<WorkItem>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn validate_draft(draft: &LedgerEntryDraft, config: &LedgerConfig) -> CliResult<()> {
    fn required(name: &str, value: &str) -> CliResult<()> {
        if value.trim().is_empty() {
            return Err(CliError::Schema(format!(
                "ledger draft field `{name}` must not be empty"
            )));
        }
        Ok(())
    }
    required("agent_id", &draft.agent_id)?;
    required("run_id", &draft.run_id)?;
    required("event_type", &draft.event_type)?;
    if draft.event_type.len() > 256 || draft.event_type.chars().any(char::is_control) {
        return Err(CliError::Schema(
            "ledger draft field `event_type` must be <= 256 chars with no control characters"
                .to_string(),
        ));
    }
    if let PayloadCommitment::Inline(value) = &draft.payload {
        let canonical_len = crate::canonical::canonical_json(value).len();
        if canonical_len > config.max_payload_bytes {
            return Err(CliError::Schema(format!(
                "payload canonical form is {canonical_len} bytes, over the \
                 max_payload_bytes limit of {}",
                config.max_payload_bytes
            )));
        }
    }
    Ok(())
}

impl<S: LedgerStore + Send + 'static, K: SigningKeyStore + Send + 'static> LedgerPipeline<S, K> {
    /// Start the pipeline: validate the mode (fail closed — `strict_cloud`
    /// refuses here, Q6), run WAL crash recovery, and spawn the sealer
    /// worker (async modes only).
    ///
    /// `wal_dir` is required by WAL-bearing modes and ignored by
    /// best-effort; `dead_letter_dir` is required unless
    /// `dead_letter_enabled` is false.
    /// `blocks_path` enables block sealing (the `blocks.jsonl` location);
    /// `None` disables blocks entirely — they are optional by design.
    pub fn start(
        store: S,
        keys: K,
        wal_dir: Option<&Path>,
        dead_letter_dir: Option<&Path>,
        blocks_path: Option<&Path>,
        config: LedgerConfig,
    ) -> CliResult<(Self, RecoveryReport)> {
        config.validate()?;

        let dead_letter = if config.dead_letter_enabled {
            let dir = dead_letter_dir.ok_or_else(|| {
                CliError::Internal("dead_letter_enabled requires a dead-letter dir".to_string())
            })?;
            Some(DeadLetterStore::open(dir)?)
        } else {
            None
        };

        let (wal, wal_report) = if config.mode.uses_wal() {
            let dir = wal_dir.ok_or_else(|| {
                CliError::Internal(format!(
                    "mode {} requires a WAL directory",
                    config.mode.label()
                ))
            })?;
            let (wal, report) = WalWriter::open(
                dir,
                config.wal_segment_max_bytes,
                config.queue_max_disk_bytes,
            )?;
            (Some(wal), Some(report))
        } else {
            (None, None)
        };

        let ledger = Ledger::open(store, keys)?;
        let dedup: HashMap<String, String> = ledger
            .read_all()?
            .into_iter()
            .map(|e| (e.event_id, e.event_payload_hash))
            .collect();

        let blocks = match blocks_path {
            Some(path) => Some(BlockChain::open(path)?),
            None => None,
        };

        let counters = Arc::new(Counters::default());
        let mut core = Core {
            ledger,
            dedup,
            wal,
            dead_letter,
            applied_wal_seq: 0,
            blocks,
            oldest_unsealed_since: None,
            wal_dir: wal_dir.map(|p| p.to_path_buf()),
        };

        // Recovery: replay WAL records above the checkpoint, in order,
        // through the same seal path appends use. Dedup makes this
        // idempotent — a lagging checkpoint yields duplicates, not double
        // appends.
        let mut recovery = RecoveryReport {
            replayed: 0,
            deduplicated: 0,
            quarantined_segments: Vec::new(),
            truncated_bytes: 0,
        };
        if let Some(report) = wal_report {
            recovery.quarantined_segments = report.quarantined_segments;
            recovery.truncated_bytes = report.truncated_bytes;
            core.applied_wal_seq = report
                .pending
                .first()
                .map(|r| r.wal_seq.saturating_sub(1))
                .unwrap_or(report.last_wal_seq);
            for record in report.pending {
                match seal_one(
                    &mut core,
                    &counters,
                    &config,
                    record.draft,
                    Some(record.wal_seq),
                )? {
                    SealOutcome::Appended(_) => recovery.replayed += 1,
                    SealOutcome::Duplicate => recovery.deduplicated += 1,
                    SealOutcome::Terminal => {}
                }
            }
        }

        let core = Arc::new(Mutex::new(core));
        let (sender, worker) = if config.mode == LedgerMode::StrictVerified {
            (None, None)
        } else {
            let (tx, rx) = std::sync::mpsc::sync_channel(config.queue_max_memory_events);
            let handle =
                spawn_worker(rx, Arc::clone(&core), Arc::clone(&counters), config.clone())?;
            (Some(tx), Some(handle))
        };

        Ok((
            Self {
                core,
                counters,
                config,
                sender,
                worker,
            },
            recovery,
        ))
    }

    /// Accept one event. Non-blocking in the default mode: returns after
    /// the fsync'd WAL append. See [`AppendOutcome`] for the per-mode
    /// contract and the module docs for the no-silent-drop invariant.
    pub fn append(&self, mut draft: LedgerEntryDraft) -> CliResult<AppendOutcome> {
        self.counters.received.fetch_add(1, AtomicOrdering::SeqCst);

        // 1. Minimal envelope validation + payload commitment. Raw payloads
        //    stop here: past this point only the hash travels.
        if let Err(e) = validate_draft(&draft, &self.config) {
            self.counters.invalid.fetch_add(1, AtomicOrdering::SeqCst);
            let core = self.lock_core()?;
            if let Some(dl) = &core.dead_letter {
                dl.record(&draft, DeadLetterReason::InvalidEvent, e.to_string(), 1)?;
                self.counters
                    .dead_lettered
                    .fetch_add(1, AtomicOrdering::SeqCst);
            }
            return Err(e);
        }
        let payload_hash = draft.payload.resolve()?;
        draft.payload = PayloadCommitment::Hash(payload_hash.clone());
        if draft.event_id.is_none() {
            draft.event_id = Some(ulid::Ulid::new().to_string());
        }
        let event_id = draft.event_id.clone().unwrap_or_default();

        let mut core = self.lock_core()?;

        // 2. Idempotency / conflict (§5.3): same id + same hash succeeds
        //    idempotently; same id + different hash is a conflict that never
        //    overwrites.
        if let Some(existing) = core.dedup.get(&event_id) {
            if *existing == payload_hash {
                self.counters
                    .duplicates
                    .fetch_add(1, AtomicOrdering::SeqCst);
                return Ok(AppendOutcome::Duplicate { event_id });
            }
            self.counters.conflicts.fetch_add(1, AtomicOrdering::SeqCst);
            let reason = format!(
                "event {event_id} already appended with hash {existing}; refusing divergent \
                 hash {payload_hash} (possible tampering upstream)"
            );
            if let Some(dl) = &core.dead_letter {
                dl.record(&draft, DeadLetterReason::Conflict, &reason, 1)?;
                self.counters
                    .dead_lettered
                    .fetch_add(1, AtomicOrdering::SeqCst);
            }
            return Err(CliError::LedgerConflict { reason });
        }

        // 3. Mode dispatch.
        match self.config.mode {
            LedgerMode::BestEffortLowLatency => {
                drop(core);
                if self.try_enqueue(WorkItem {
                    wal_seq: None,
                    draft,
                })? {
                    Ok(AppendOutcome::Enqueued { event_id })
                } else {
                    // No WAL to fall back on: a full queue is an explicit
                    // refusal, never a silent drop.
                    self.counters
                        .busy_rejections
                        .fetch_add(1, AtomicOrdering::SeqCst);
                    Err(CliError::LedgerBusy {
                        reason: format!(
                            "in-memory queue is full ({} events); the event was refused, not \
                             dropped",
                            self.config.queue_max_memory_events
                        ),
                    })
                }
            }
            LedgerMode::DurableLowLatency => {
                let wal = core
                    .wal
                    .as_mut()
                    .ok_or_else(|| CliError::Internal("durable mode without a WAL".to_string()))?;
                let wal_seq = match wal.append(&draft) {
                    Ok(seq) => seq,
                    Err(e) => {
                        // Disk budget / IO failure: explicit refusal, agents
                        // stay unblocked, nothing was half-written.
                        self.counters
                            .busy_rejections
                            .fetch_add(1, AtomicOrdering::SeqCst);
                        return Err(e);
                    }
                };
                // Durable: the event is safe in the WAL either way. The
                // spill decision happens UNDER the core lock (same lock the
                // backlog drain holds) so the ordering invariant holds: once
                // anything has spilled, everything spills until the drain
                // resets the backlog — the queue never overtakes the WAL.
                let spilled = self.counters.wal_backlog.load(AtomicOrdering::SeqCst) > 0
                    || !self.try_enqueue(WorkItem {
                        wal_seq: Some(wal_seq),
                        draft,
                    })?;
                if spilled {
                    self.counters
                        .wal_backlog
                        .fetch_add(1, AtomicOrdering::SeqCst);
                }
                drop(core);
                Ok(AppendOutcome::WalPersisted { event_id, wal_seq })
            }
            LedgerMode::StrictVerified => {
                let wal_seq = {
                    let wal = core.wal.as_mut().ok_or_else(|| {
                        CliError::Internal("strict mode without a WAL".to_string())
                    })?;
                    wal.append(&draft)?
                };
                match seal_one(
                    &mut core,
                    &self.counters,
                    &self.config,
                    draft,
                    Some(wal_seq),
                )? {
                    SealOutcome::Appended(entry) => Ok(AppendOutcome::Appended(entry)),
                    SealOutcome::Duplicate => Ok(AppendOutcome::Duplicate { event_id }),
                    SealOutcome::Terminal => Err(CliError::LedgerIntegrity {
                        reason: format!("event {event_id} was dead-lettered during strict append"),
                    }),
                }
            }
            // Refused in start(); unreachable here by construction.
            LedgerMode::StrictCloud => Err(CliError::LedgerCloudUnavailable {
                reason: "no cloud ledger ingestion API exists yet".to_string(),
            }),
        }
    }

    /// Block until the queue and WAL backlog are fully drained, or `timeout`
    /// elapses (explicit `LedgerBusy` — never a silent partial flush).
    pub fn flush(&self, timeout: Duration) -> CliResult<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let queued = self.counters.queue_depth.load(AtomicOrdering::SeqCst);
            let backlog = self.counters.wal_backlog.load(AtomicOrdering::SeqCst);
            if queued == 0 && backlog == 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(CliError::LedgerBusy {
                    reason: format!(
                        "flush timed out with {queued} queued and {backlog} backlog events \
                         still pending (all remain durable/visible; nothing was dropped)"
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Flush, stop the worker, seal the unsealed tail (the shutdown seal
    /// trigger), and write the final checkpoint. Consumes the pipeline.
    /// Returns the final status snapshot.
    pub fn shutdown(mut self, flush_timeout: Duration) -> CliResult<QueueStatus> {
        let flush_result = self.flush(flush_timeout);
        self.sender.take(); // Disconnect: the worker drains and exits.
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| {
                CliError::Internal("ledger worker panicked during shutdown".to_string())
            })?;
        }
        flush_result?;
        seal_unsealed_range(&mut *self.lock_core()?)?;
        self.status()
    }

    /// Point-in-time health snapshot (durability states as counters).
    pub fn status(&self) -> CliResult<QueueStatus> {
        let wal_bytes = {
            let core = self.lock_core()?;
            core.wal.as_ref().map(|w| w.total_bytes()).unwrap_or(0)
        };
        let c = &self.counters;
        Ok(QueueStatus {
            mode: self.config.mode,
            received: c.received.load(AtomicOrdering::SeqCst),
            appended: c.appended.load(AtomicOrdering::SeqCst),
            duplicates: c.duplicates.load(AtomicOrdering::SeqCst),
            conflicts: c.conflicts.load(AtomicOrdering::SeqCst),
            invalid: c.invalid.load(AtomicOrdering::SeqCst),
            busy_rejections: c.busy_rejections.load(AtomicOrdering::SeqCst),
            retries: c.retries.load(AtomicOrdering::SeqCst),
            dead_lettered: c.dead_lettered.load(AtomicOrdering::SeqCst),
            queue_depth: c.queue_depth.load(AtomicOrdering::SeqCst),
            wal_backlog: c.wal_backlog.load(AtomicOrdering::SeqCst),
            wal_bytes,
        })
    }

    /// Seal all currently-unsealed entries into one block (the explicit
    /// flush trigger; also used by `agenomic ledger seal` and shutdown).
    /// Returns `None` when blocks are disabled or nothing is unsealed.
    pub fn seal(&self) -> CliResult<Option<LedgerBlock>> {
        seal_unsealed_range(&mut *self.lock_core()?)
    }

    /// All sealed blocks, in chain order (empty when blocks are disabled).
    pub fn blocks(&self) -> CliResult<Vec<LedgerBlock>> {
        Ok(self
            .lock_core()?
            .blocks
            .as_ref()
            .map(|c| c.blocks().to_vec())
            .unwrap_or_default())
    }

    /// Run the full §5.9 verification engine over this ledger: entries,
    /// blocks, key status, and WAL health, with a structured report.
    pub fn verify(&self) -> CliResult<VerificationReport> {
        let core = self.lock_core()?;
        let entries = core.ledger.read_all()?;
        let blocks = core
            .blocks
            .as_ref()
            .map(|c| c.blocks().to_vec())
            .unwrap_or_default();
        crate::verify::verify_ledger(
            &entries,
            &blocks,
            core.ledger.keystore(),
            core.wal_dir.as_deref(),
        )
    }

    /// All ledger entries in append order.
    pub fn read_all(&self) -> CliResult<Vec<LedgerEntry>> {
        self.lock_core()?.ledger.read_all()
    }

    /// Non-blocking enqueue. `Ok(true)` = queued, `Ok(false)` = queue full
    /// (the caller decides whether "full" is a refusal or a WAL spill).
    fn try_enqueue(&self, item: WorkItem) -> CliResult<bool> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| CliError::Internal("pipeline has no queue".to_string()))?;
        match sender.try_send(item) {
            Ok(()) => {
                self.counters
                    .queue_depth
                    .fetch_add(1, AtomicOrdering::SeqCst);
                Ok(true)
            }
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => Err(CliError::Internal(
                "ledger worker is not running".to_string(),
            )),
        }
    }

    fn lock_core(&self) -> CliResult<std::sync::MutexGuard<'_, Core<S, K>>> {
        self.core
            .lock()
            .map_err(|_| CliError::Internal("ledger pipeline mutex poisoned".to_string()))
    }
}

enum SealOutcome {
    Appended(Box<LedgerEntry>),
    Duplicate,
    /// Terminally handled without an append (conflict / dead-letter). The
    /// WAL watermark still advances — the failure is recorded elsewhere.
    Terminal,
}

/// Seal one draft into the ledger with retry + dead-letter semantics, and
/// advance the WAL watermark on any terminal outcome. The single funnel used
/// by the worker, recovery, and strict-mode appends.
fn seal_one<S: LedgerStore, K: SigningKeyStore>(
    core: &mut Core<S, K>,
    counters: &Counters,
    config: &LedgerConfig,
    draft: LedgerEntryDraft,
    wal_seq: Option<u64>,
) -> CliResult<SealOutcome> {
    let event_id = draft.event_id.clone().unwrap_or_default();
    let payload_hash = match draft.payload.resolve() {
        Ok(h) => h,
        Err(e) => {
            record_dead_letter(
                core,
                counters,
                &draft,
                DeadLetterReason::InvalidEvent,
                e.to_string(),
                1,
            )?;
            advance_watermark(core, wal_seq)?;
            return Ok(SealOutcome::Terminal);
        }
    };

    // Recheck dedup at seal time (recovery replays and racing producers).
    if let Some(existing) = core.dedup.get(&event_id) {
        if *existing == payload_hash {
            counters.duplicates.fetch_add(1, AtomicOrdering::SeqCst);
            advance_watermark(core, wal_seq)?;
            return Ok(SealOutcome::Duplicate);
        }
        counters.conflicts.fetch_add(1, AtomicOrdering::SeqCst);
        let reason = format!(
            "event {event_id} already appended with hash {existing}; refusing divergent hash \
             {payload_hash} (possible tampering upstream)"
        );
        record_dead_letter(
            core,
            counters,
            &draft,
            DeadLetterReason::Conflict,
            reason,
            1,
        )?;
        advance_watermark(core, wal_seq)?;
        return Ok(SealOutcome::Terminal);
    }

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match core.ledger.append(draft.clone()) {
            Ok(entry) => {
                core.dedup
                    .insert(entry.event_id.clone(), entry.event_payload_hash.clone());
                counters.appended.fetch_add(1, AtomicOrdering::SeqCst);
                advance_watermark(core, wal_seq)?;
                if core.blocks.is_some() {
                    if core.oldest_unsealed_since.is_none() {
                        core.oldest_unsealed_since = Some(std::time::Instant::now());
                    }
                    maybe_seal_by_count(core, config)?;
                }
                return Ok(SealOutcome::Appended(Box::new(entry)));
            }
            Err(e) if attempt <= config.retry_max_attempts => {
                counters.retries.fetch_add(1, AtomicOrdering::SeqCst);
                let backoff = config.retry_backoff_ms.saturating_mul(1 << (attempt - 1));
                std::thread::sleep(Duration::from_millis(backoff));
                let _ = e; // transient by classification; retried
            }
            Err(e) => {
                record_dead_letter(
                    core,
                    counters,
                    &draft,
                    DeadLetterReason::RetriesExhausted,
                    e.to_string(),
                    attempt,
                )?;
                advance_watermark(core, wal_seq)?;
                return Ok(SealOutcome::Terminal);
            }
        }
    }
}

fn record_dead_letter<S: LedgerStore, K: SigningKeyStore>(
    core: &Core<S, K>,
    counters: &Counters,
    draft: &LedgerEntryDraft,
    reason: DeadLetterReason,
    detail: String,
    attempts: u32,
) -> CliResult<()> {
    if let Some(dl) = &core.dead_letter {
        dl.record(draft, reason, detail, attempts)?;
        counters.dead_lettered.fetch_add(1, AtomicOrdering::SeqCst);
    }
    Ok(())
}

/// Seal everything currently unsealed into one block, regardless of
/// thresholds (explicit flush / shutdown triggers). `None` when blocks are
/// disabled or nothing is unsealed.
fn seal_unsealed_range<S: LedgerStore, K: SigningKeyStore>(
    core: &mut Core<S, K>,
) -> CliResult<Option<LedgerBlock>> {
    let Some(chain) = core.blocks.as_mut() else {
        return Ok(None);
    };
    let start = chain.next_start_sequence();
    let entries = core.ledger.read_all()?;
    if entries.len() as u64 <= start {
        core.oldest_unsealed_since = None;
        return Ok(None);
    }
    let block = chain.seal(&entries[start as usize..], core.ledger.keystore())?;
    core.oldest_unsealed_since = None;
    Ok(Some(block))
}

/// The max-entries trigger: seal once the unsealed tail reaches the
/// configured size.
fn maybe_seal_by_count<S: LedgerStore, K: SigningKeyStore>(
    core: &mut Core<S, K>,
    config: &LedgerConfig,
) -> CliResult<()> {
    let Some(max_entries) = config.block_max_entries else {
        return Ok(());
    };
    let Some(chain) = core.blocks.as_ref() else {
        return Ok(());
    };
    let unsealed = core
        .ledger
        .len()
        .saturating_sub(chain.next_start_sequence());
    if unsealed >= max_entries {
        seal_unsealed_range(core)?;
    }
    Ok(())
}

/// The max-age trigger: seal once the oldest unsealed entry has waited the
/// configured time. Runs on worker idle ticks.
fn maybe_seal_by_age<S: LedgerStore, K: SigningKeyStore>(
    core: &Arc<Mutex<Core<S, K>>>,
    config: &LedgerConfig,
) {
    let Some(max_age_ms) = config.block_max_age_ms else {
        return;
    };
    let Ok(mut core) = core.lock() else { return };
    let due = core
        .oldest_unsealed_since
        .map(|t| t.elapsed() >= Duration::from_millis(max_age_ms))
        .unwrap_or(false);
    if due {
        // A seal failure here is retried on the next tick; the entries
        // remain individually signed and WAL-durable either way.
        let _ = seal_unsealed_range(&mut core);
    }
}

fn advance_watermark<S: LedgerStore, K: SigningKeyStore>(
    core: &mut Core<S, K>,
    wal_seq: Option<u64>,
) -> CliResult<()> {
    if let Some(seq) = wal_seq {
        if seq > core.applied_wal_seq {
            core.applied_wal_seq = seq;
            if let Some(wal) = &core.wal {
                wal.checkpoint(seq)?;
            }
        }
    }
    Ok(())
}

fn spawn_worker<S: LedgerStore + Send + 'static, K: SigningKeyStore + Send + 'static>(
    rx: Receiver<WorkItem>,
    core: Arc<Mutex<Core<S, K>>>,
    counters: Arc<Counters>,
    config: LedgerConfig,
) -> CliResult<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("agenomic-ledger-sealer".to_string())
        .spawn(move || loop {
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(item) => {
                    process_item(&core, &counters, &config, item);
                }
                Err(RecvTimeoutError::Timeout) => {
                    drain_backlog(&core, &counters, &config);
                    maybe_seal_by_age(&core, &config);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // Shutdown: drain whatever is left, then the backlog.
                    while let Ok(item) = rx.try_recv() {
                        process_item(&core, &counters, &config, item);
                    }
                    drain_backlog(&core, &counters, &config);
                    return;
                }
            }
        })
        .map_err(|e| CliError::Internal(format!("spawn ledger worker: {e}")))
}

fn process_item<S: LedgerStore, K: SigningKeyStore>(
    core: &Arc<Mutex<Core<S, K>>>,
    counters: &Counters,
    config: &LedgerConfig,
    item: WorkItem,
) {
    if let Ok(mut core) = core.lock() {
        if config.worker_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(config.worker_delay_ms));
        }
        // seal_one records every failure explicitly (dead-letter, counters);
        // an Err here is an IO failure *recording the failure*, which the
        // status counters still surface via dead_lettered lag.
        let _ = seal_one(&mut core, counters, config, item.draft, item.wal_seq);
    }
    counters.queue_depth.fetch_sub(1, AtomicOrdering::SeqCst);
}

/// Replay WAL records that never made it into the queue (spill backlog),
/// strictly in WAL order. Runs on worker idle ticks and at shutdown.
///
/// Ordering safety: all queued items carry lower `wal_seq`s than any
/// spilled record (the spill rule is sticky and lock-protected), so the
/// drain runs only once the queue is empty — the backlog must never
/// overtake queued work. Holding the core lock across scan + process +
/// counter reset keeps racing producers on the sticky spill path until the
/// backlog is genuinely empty.
fn drain_backlog<S: LedgerStore, K: SigningKeyStore>(
    core: &Arc<Mutex<Core<S, K>>>,
    counters: &Counters,
    config: &LedgerConfig,
) {
    if counters.wal_backlog.load(AtomicOrdering::SeqCst) == 0 {
        return;
    }
    if counters.queue_depth.load(AtomicOrdering::SeqCst) > 0 {
        // Queued items (lower wal_seqs) first; the next idle tick retries.
        return;
    }
    let Ok(mut core) = core.lock() else { return };
    while let Some(Ok(pending)) = core.wal.as_ref().map(|w| w.pending()) {
        let todo: Vec<_> = pending
            .into_iter()
            .filter(|r| r.wal_seq > core.applied_wal_seq)
            .collect();
        if todo.is_empty() {
            break;
        }
        for record in todo {
            let _ = seal_one(
                &mut core,
                counters,
                config,
                record.draft,
                Some(record.wal_seq),
            );
        }
        // Re-scan: a producer may have spilled more records before we took
        // the lock; the loop exits only on a clean empty scan.
    }
    counters.wal_backlog.store(0, AtomicOrdering::SeqCst);
}

impl<S: LedgerStore + Send + 'static, K: SigningKeyStore + Send + 'static> Drop
    for LedgerPipeline<S, K>
{
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
