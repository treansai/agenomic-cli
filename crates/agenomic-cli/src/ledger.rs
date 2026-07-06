//! `agenomic ledger` — the append-only, tamper-evident cryptographic event
//! ledger.
//!
//! Offline-first: every subcommand reads and writes local state (default
//! data root `<cwd>/.agenomic/ledger`, keys `~/.config/agenomic/keys`).
//! Verification never touches the network. Integrity failures exit with
//! [`ExitCode::LedgerIntegrityFailed`] (19).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use agenomic_core::{io_at, CliError, CliResult, ExitCode};
use agenomic_ledger_local::block::BlockChain;
use agenomic_ledger_local::deadletter::{DeadLetterRecord, DeadLetterStore};
use agenomic_ledger_local::entry::{
    IngestionSource, LedgerEntry, LedgerEntryDraft, PayloadCommitment,
};
use agenomic_ledger_local::keystore::{FileKeyStore, KeyStatus, SigningKeyStore};
use agenomic_ledger_local::pipeline::LedgerPipeline;
use agenomic_ledger_local::store::{FileLedgerStore, LedgerStore};
use agenomic_ledger_local::verify::{verify_ledger, VerificationReport};
use agenomic_ledger_local::{LedgerBlock, LedgerConfig, WalHealth};
use agenomic_report::{RenderOptions, Renderable};
use serde::Serialize;

use crate::cli::{
    LedgerCommand, LedgerDeadLetterSub, LedgerDirs, LedgerKeysSub, LedgerQueueSub, LedgerSub,
    OutputFormat,
};
use crate::render::render;

const FLUSH_TIMEOUT: Duration = Duration::from_secs(60);

pub fn cmd_ledger(
    args: &LedgerCommand,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        LedgerSub::Init { dirs } => init(dirs, format, no_color),
        LedgerSub::Status { dirs } => status(dirs, format, no_color),
        LedgerSub::Seal { dirs } => seal(dirs, format, no_color),
        LedgerSub::Append { event, dirs } => append(event, dirs, format, no_color),
        LedgerSub::Tail { run, limit, dirs } => {
            tail(run.as_deref(), *limit, dirs, format, no_color)
        }
        LedgerSub::Verify { run, block, dirs } => {
            verify(run.as_deref(), block.as_deref(), dirs, format, no_color)
        }
        LedgerSub::Export { run, output, dirs } => {
            export(run.as_deref(), output, dirs, format, no_color)
        }
        LedgerSub::Inspect { entry, dirs } => inspect(entry, dirs, format, no_color),
        LedgerSub::Queue(queue) => match &queue.command {
            LedgerQueueSub::Status { dirs } => queue_status(dirs, format, no_color),
            LedgerQueueSub::Flush { dirs } => queue_drain(dirs, "flush", format, no_color),
            LedgerQueueSub::Retry { dirs } => queue_drain(dirs, "retry", format, no_color),
            LedgerQueueSub::DeadLetter(dl) => match &dl.command {
                LedgerDeadLetterSub::List { dirs } => dead_letter_list(dirs, format, no_color),
                LedgerDeadLetterSub::Replay { id, dirs } => {
                    dead_letter_replay(id.as_deref(), dirs, format, no_color)
                }
            },
        },
        LedgerSub::Keys(keys) => match &keys.command {
            LedgerKeysSub::Generate { dirs } => keys_generate(dirs, format, no_color),
            LedgerKeysSub::List { dirs } => keys_list(dirs, format, no_color),
            LedgerKeysSub::Rotate { dirs } => keys_rotate(dirs, format, no_color),
            LedgerKeysSub::Revoke { key_id, dirs } => keys_revoke(key_id, dirs, format, no_color),
            LedgerKeysSub::ExportPublic { key, output, dirs } => {
                keys_export_public(key.as_deref(), output.as_deref(), dirs, format, no_color)
            }
        },
    }
}

// ---- layout ----------------------------------------------------------------

/// Resolved on-disk layout (Q8 defaults).
struct Layout {
    root: PathBuf,
    store: PathBuf,
    wal: PathBuf,
    dead_letter: PathBuf,
    blocks: PathBuf,
    keys: PathBuf,
}

fn layout(dirs: &LedgerDirs) -> CliResult<Layout> {
    let root = match &dirs.store {
        Some(p) => p.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::Internal(format!("cwd: {e}")))?
            .join(".agenomic")
            .join("ledger"),
    };
    let keys = match &dirs.keys {
        Some(p) => p.clone(),
        None => directories::ProjectDirs::from("dev", "agenomic", "agenomic")
            .ok_or_else(|| CliError::Internal("cannot resolve config directory".to_string()))?
            .config_dir()
            .join("keys"),
    };
    Ok(Layout {
        store: root.join("store"),
        wal: root.join("wal"),
        dead_letter: root.join("dead-letter"),
        blocks: root.join("blocks.jsonl"),
        root,
        keys,
    })
}

fn open_keys(l: &Layout) -> CliResult<FileKeyStore> {
    FileKeyStore::open(&l.keys)
}

fn require_initialized(l: &Layout) -> CliResult<()> {
    if !l.store.exists() {
        return Err(CliError::Schema(format!(
            "no ledger at {} (run `agenomic ledger init` first)",
            l.root.display()
        )));
    }
    Ok(())
}

fn open_pipeline(
    l: &Layout,
) -> CliResult<(
    LedgerPipeline<FileLedgerStore, FileKeyStore>,
    agenomic_ledger_local::RecoveryReport,
)> {
    LedgerPipeline::start(
        FileLedgerStore::open(&l.store)?,
        open_keys(l)?,
        Some(&l.wal),
        Some(&l.dead_letter),
        Some(&l.blocks),
        LedgerConfig::default(),
    )
}

fn read_entries(l: &Layout) -> CliResult<Vec<LedgerEntry>> {
    FileLedgerStore::open(&l.store)?.read_all()
}

fn read_input(path: &Path) -> CliResult<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::Internal(format!("read stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| io_at(path, e))
    }
}

// ---- output types ----------------------------------------------------------

fn io(e: std::io::Error) -> CliError {
    CliError::Internal(format!("write output: {e}"))
}

fn write_json<T: Serialize>(w: &mut dyn Write, v: &T, pretty: bool) -> CliResult<()> {
    let s = if pretty {
        serde_json::to_string_pretty(v).map_err(|e| CliError::Internal(format!("{e}")))?
    } else {
        serde_json::to_string(v).map_err(|e| CliError::Internal(format!("{e}")))?
    };
    w.write_all(s.as_bytes()).map_err(io)?;
    w.write_all(b"\n").map_err(io)?;
    Ok(())
}

/// Implement `render_json` + `render_markdown` (JSON block under a heading);
/// each type writes its own human view.
macro_rules! impl_render_tail {
    ($ty:ty, $title:expr) => {
        impl Renderable for $ty {
            fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
                self.human(w, opts)
            }
            fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
                write_json(w, self, pretty)
            }
            fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
                writeln!(w, "# {}\n", $title).map_err(io)?;
                writeln!(w, "```json").map_err(io)?;
                write_json(w, self, true)?;
                writeln!(w, "```").map_err(io)?;
                Ok(())
            }
        }
    };
}

#[derive(Debug, Serialize)]
struct InitOut {
    root: String,
    keys: String,
    signing_key_id: String,
    key_generated: bool,
}
impl InitOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(w, "Ledger initialized at {}", self.root).map_err(io)?;
        writeln!(w, "  keys: {}", self.keys).map_err(io)?;
        let verb = if self.key_generated {
            "generated"
        } else {
            "existing"
        };
        writeln!(w, "  signing key ({verb}): {}", self.signing_key_id).map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(InitOut, "Ledger Init");

#[derive(Debug, Serialize)]
struct OverviewOut {
    root: String,
    entry_count: u64,
    run_count: u64,
    head_hash: String,
    block_count: u64,
    unsealed_entries: u64,
    wal: WalHealth,
    dead_letters: u64,
}
impl OverviewOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(w, "Ledger at {}", self.root).map_err(io)?;
        writeln!(
            w,
            "  entries:  {} across {} run(s)",
            self.entry_count, self.run_count
        )
        .map_err(io)?;
        writeln!(w, "  head:     {}", self.head_hash).map_err(io)?;
        writeln!(
            w,
            "  blocks:   {} sealed, {} entrie(s) unsealed",
            self.block_count, self.unsealed_entries
        )
        .map_err(io)?;
        writeln!(
            w,
            "  wal:      {} segment(s), {} pending, {} damaged, {} quarantined",
            self.wal.segments,
            self.wal.pending_records,
            self.wal.damaged_segments.len(),
            self.wal.quarantined_segments.len()
        )
        .map_err(io)?;
        writeln!(w, "  dead-letter: {} record(s)", self.dead_letters).map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(OverviewOut, "Ledger Status");

#[derive(Debug, Serialize)]
struct SealOut {
    sealed: bool,
    block_id: Option<String>,
    start_sequence_number: Option<u64>,
    end_sequence_number: Option<u64>,
    merkle_root: Option<String>,
}
impl SealOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        match (
            &self.block_id,
            self.start_sequence_number,
            self.end_sequence_number,
        ) {
            (Some(id), Some(s), Some(e)) => {
                writeln!(w, "Sealed block {id} covering sequences {s}..={e}").map_err(io)?;
                if let Some(root) = &self.merkle_root {
                    writeln!(w, "  merkle root: {root}").map_err(io)?;
                }
            }
            _ => writeln!(w, "Nothing to seal (no unsealed entries).").map_err(io)?,
        }
        Ok(())
    }
}
impl_render_tail!(SealOut, "Ledger Seal");

#[derive(Debug, Serialize)]
struct AppendOut {
    event_id: String,
    outcome: String,
    entry_hash: Option<String>,
    sequence_number: Option<u64>,
}
impl AppendOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(w, "Appended event {} [{}]", self.event_id, self.outcome).map_err(io)?;
        if let (Some(h), Some(s)) = (&self.entry_hash, self.sequence_number) {
            writeln!(w, "  sequence {s}: {h}").map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(AppendOut, "Ledger Append");

#[derive(Debug, Serialize)]
struct EntriesOut {
    count: usize,
    entries: Vec<LedgerEntry>,
}
impl EntriesOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        if self.entries.is_empty() {
            writeln!(w, "No entries.").map_err(io)?;
            return Ok(());
        }
        for e in &self.entries {
            writeln!(
                w,
                "#{:<6} {}  run={} rseq={} {} key={}",
                e.sequence_number,
                e.timestamp,
                e.run_id,
                e.run_sequence_number,
                e.event_type,
                e.signing_key_id
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(EntriesOut, "Ledger Entries");

#[derive(Debug, Serialize)]
struct EntryOut {
    entry: LedgerEntry,
}
impl EntryOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        write_json(w, &self.entry, true)
    }
}
impl_render_tail!(EntryOut, "Ledger Entry");

#[derive(Debug, Serialize)]
struct VerifyOut {
    scope: String,
    passed: bool,
    report: VerificationReport,
}
impl VerifyOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        let r = &self.report;
        let verdict = if self.passed { "PASSED" } else { "FAILED" };
        writeln!(w, "Ledger verification [{verdict}]  scope: {}", self.scope).map_err(io)?;
        writeln!(
            w,
            "  entries: {}  runs: {}  blocks: {}",
            r.entry_count, r.chain_summary.run_count, r.blocks.block_count
        )
        .map_err(io)?;
        writeln!(w, "  head:    {}", r.chain_summary.head_hash).map_err(io)?;
        if let Some(seq) = r.first_invalid_sequence {
            writeln!(w, "  first invalid sequence: {seq}").map_err(io)?;
        }
        let mut findings: Vec<String> = Vec::new();
        if !r.entries.hash_failures.is_empty() {
            findings.push(format!(
                "entry hash failures at {:?}",
                r.entries.hash_failures
            ));
        }
        if !r.entries.signature_failures.is_empty() {
            findings.push(format!(
                "signature failures at {:?}",
                r.entries.signature_failures
            ));
        }
        if !r.entries.unresolved_key_failures.is_empty() {
            findings.push(format!(
                "unresolved signing keys at {:?}",
                r.entries.unresolved_key_failures
            ));
        }
        if !r.chain_evaluated {
            findings.push("chain wiring not evaluated (gaps or duplicates present)".to_string());
        } else if let Some(seq) = r.entries.broken_at_sequence {
            findings.push(format!("chain break at sequence {seq}"));
        }
        if !r.sequence_gaps.is_empty() {
            findings.push(format!("missing sequence ranges {:?}", r.sequence_gaps));
        }
        if !r.duplicate_sequences.is_empty() {
            findings.push(format!("duplicate sequences {:?}", r.duplicate_sequences));
        }
        if !r.conflicting_event_ids.is_empty() {
            findings.push(format!(
                "conflicting event ids (tampering warning): {:?}",
                r.conflicting_event_ids
            ));
        }
        if !r.blocks.merkle_mismatches.is_empty() || !r.blocks.entries_hash_mismatches.is_empty() {
            findings.push("block commitments mismatch".to_string());
        }
        if !r.blocks.chain_valid {
            findings.push("block chain wiring broken".to_string());
        }
        if !r.entries.revoked_key_warnings.is_empty() {
            findings.push(format!(
                "warning: entries signed by revoked keys at {:?}",
                r.entries.revoked_key_warnings
            ));
        }
        if let Some((from, to)) = r.blocks.unsealed_tail {
            findings.push(format!("info: unsealed entries {from}..={to}"));
        }
        for f in &findings {
            writeln!(w, "  - {f}").map_err(io)?;
        }
        for rec in &r.recommendations {
            writeln!(w, "  recommendation: {rec}").map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(VerifyOut, "Ledger Verification");

#[derive(Debug, Serialize)]
struct ExportOut {
    output: String,
    entries: usize,
    run: Option<String>,
}
impl ExportOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        match &self.run {
            Some(run) => writeln!(
                w,
                "Exported {} entrie(s) of run {} to {}",
                self.entries, run, self.output
            )
            .map_err(io)?,
            None => {
                writeln!(w, "Exported {} entrie(s) to {}", self.entries, self.output).map_err(io)?
            }
        }
        Ok(())
    }
}
impl_render_tail!(ExportOut, "Ledger Export");

#[derive(Debug, Serialize)]
struct DrainOut {
    operation: String,
    replayed: u64,
    deduplicated: u64,
    quarantined_segments: Vec<String>,
    pending_after: u64,
}
impl DrainOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "Queue {}: {} replayed, {} deduplicated, {} pending after",
            self.operation, self.replayed, self.deduplicated, self.pending_after
        )
        .map_err(io)?;
        for s in &self.quarantined_segments {
            writeln!(w, "  quarantined: {s}").map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(DrainOut, "Ledger Queue Drain");

#[derive(Debug, Serialize)]
struct DeadLettersOut {
    count: usize,
    records: Vec<DeadLetterRecord>,
}
impl DeadLettersOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        if self.records.is_empty() {
            writeln!(w, "Dead-letter store is empty.").map_err(io)?;
            return Ok(());
        }
        for r in &self.records {
            writeln!(
                w,
                "{}  event={} reason={} attempts={} at {}",
                r.dead_letter_id,
                r.event_id,
                r.reason.label(),
                r.attempts,
                r.failed_at
            )
            .map_err(io)?;
            writeln!(w, "  {}", r.detail).map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(DeadLettersOut, "Ledger Dead Letters");

#[derive(Debug, Serialize)]
struct ReplayOut {
    replayed: Vec<String>,
    failed: Vec<(String, String)>,
}
impl ReplayOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "Dead-letter replay: {} succeeded, {} failed",
            self.replayed.len(),
            self.failed.len()
        )
        .map_err(io)?;
        for id in &self.replayed {
            writeln!(w, "  replayed {id}").map_err(io)?;
        }
        for (id, why) in &self.failed {
            writeln!(w, "  kept {id}: {why}").map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(ReplayOut, "Ledger Dead-Letter Replay");

#[derive(Debug, Serialize)]
struct KeyOut {
    key_id: String,
    action: String,
}
impl KeyOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(w, "{}: {}", self.action, self.key_id).map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(KeyOut, "Ledger Key");

#[derive(Debug, Serialize)]
struct KeysOut {
    keys: Vec<KeyRow>,
}
#[derive(Debug, Serialize)]
struct KeyRow {
    key_id: String,
    status: KeyStatus,
    created_at: String,
    entries_signed: u64,
}
impl KeysOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        if self.keys.is_empty() {
            writeln!(w, "No keys (run `agenomic ledger keys generate`).").map_err(io)?;
            return Ok(());
        }
        for k in &self.keys {
            writeln!(
                w,
                "{}  {:?}  created {}  signed {} entrie(s)",
                k.key_id, k.status, k.created_at, k.entries_signed
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(KeysOut, "Ledger Keys");

// ---- commands ----------------------------------------------------------------

fn init(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    let mut keys = open_keys(&l)?;
    let (key_id, generated) = match keys.active_key_id() {
        Ok(id) => (id, false),
        Err(_) => (keys.generate()?, true),
    };
    // Opening the pipeline creates the store/WAL/dead-letter layout.
    let (pipeline, _) = open_pipeline(&l)?;
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    let out = InitOut {
        root: l.root.display().to_string(),
        keys: l.keys.display().to_string(),
        signing_key_id: key_id,
        key_generated: generated,
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

fn overview(l: &Layout) -> CliResult<OverviewOut> {
    let entries = read_entries(l)?;
    let blocks = BlockChain::open(&l.blocks)?;
    let wal = agenomic_ledger_local::wal::scan_health(&l.wal)?;
    let dead_letters = if l.dead_letter.exists() {
        DeadLetterStore::open(&l.dead_letter)?.len()?
    } else {
        0
    };
    let run_count = {
        let mut runs: Vec<&str> = entries.iter().map(|e| e.run_id.as_str()).collect();
        runs.sort_unstable();
        runs.dedup();
        runs.len() as u64
    };
    let head_hash = entries
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| agenomic_ledger_local::GENESIS_ENTRY_HASH.to_string());
    Ok(OverviewOut {
        root: l.root.display().to_string(),
        entry_count: entries.len() as u64,
        run_count,
        head_hash,
        block_count: blocks.blocks().len() as u64,
        unsealed_entries: (entries.len() as u64).saturating_sub(blocks.next_start_sequence()),
        wal,
        dead_letters,
    })
}

fn status(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    render(&overview(&l)?, format, no_color)?;
    Ok(ExitCode::Success)
}

fn seal(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let (pipeline, _) = open_pipeline(&l)?;
    let block = pipeline.seal()?;
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    let out = match block {
        Some(b) => SealOut {
            sealed: true,
            block_id: Some(b.block_id),
            start_sequence_number: Some(b.start_sequence_number),
            end_sequence_number: Some(b.end_sequence_number),
            merkle_root: Some(b.merkle_root),
        },
        None => SealOut {
            sealed: false,
            block_id: None,
            start_sequence_number: None,
            end_sequence_number: None,
            merkle_root: None,
        },
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

/// Input shape for `ledger append --event`.
#[derive(Debug, serde::Deserialize)]
struct AppendEventInput {
    agent_id: String,
    run_id: String,
    event_type: String,
    #[serde(default)]
    payload: serde_json::Value,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    turn_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    genome_hash: Option<String>,
    #[serde(default)]
    release_id: Option<String>,
    #[serde(default)]
    turn_sequence_number: Option<u64>,
}

fn append(
    event: &Path,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let raw = read_input(event)?;
    let input: AppendEventInput = serde_json::from_str(&raw)
        .map_err(|e| CliError::Schema(format!("parse event JSON: {e}")))?;
    let mut draft = LedgerEntryDraft::new(
        input.agent_id,
        input.run_id,
        input.event_type,
        PayloadCommitment::Inline(input.payload),
        IngestionSource::Cli,
    );
    draft.event_id = input.event_id;
    draft.turn_id = input.turn_id;
    draft.session_id = input.session_id;
    draft.genome_hash = input.genome_hash;
    draft.release_id = input.release_id;
    draft.turn_sequence_number = input.turn_sequence_number;

    // One-shot append: blocks disabled so each CLI invocation does not seal
    // a one-entry block at shutdown; sealing belongs to `ledger seal` and
    // the long-running auto-triggers.
    let (pipeline, _) = LedgerPipeline::start(
        FileLedgerStore::open(&l.store)?,
        open_keys(&l)?,
        Some(&l.wal),
        Some(&l.dead_letter),
        None,
        LedgerConfig::default(),
    )?;
    let outcome = pipeline.append(draft)?;
    pipeline.flush(FLUSH_TIMEOUT)?;
    let (event_id, label) = match &outcome {
        agenomic_ledger_local::AppendOutcome::Appended(e) => {
            (e.event_id.clone(), "appended".to_string())
        }
        agenomic_ledger_local::AppendOutcome::WalPersisted { event_id, .. } => {
            (event_id.clone(), "appended".to_string())
        }
        agenomic_ledger_local::AppendOutcome::Enqueued { event_id } => {
            (event_id.clone(), "enqueued".to_string())
        }
        agenomic_ledger_local::AppendOutcome::Duplicate { event_id } => {
            (event_id.clone(), "duplicate (idempotent)".to_string())
        }
    };
    // After flush, the sealed entry is in the store — surface its position.
    let sealed = pipeline
        .read_all()?
        .into_iter()
        .find(|e| e.event_id == event_id);
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    let out = AppendOut {
        event_id,
        outcome: label,
        entry_hash: sealed.as_ref().map(|e| e.entry_hash.clone()),
        sequence_number: sealed.as_ref().map(|e| e.sequence_number),
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

fn tail(
    run: Option<&str>,
    limit: usize,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let mut entries = read_entries(&l)?;
    if let Some(run) = run {
        entries.retain(|e| e.run_id == run);
    }
    let skip = entries.len().saturating_sub(limit);
    let out = EntriesOut {
        count: entries.len() - skip,
        entries: entries.into_iter().skip(skip).collect(),
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

/// Run-scoped verification: the run chain plus per-entry checks.
fn verify_run_scope(
    run: &str,
    entries: &[LedgerEntry],
    blocks: &[LedgerBlock],
    keys: &FileKeyStore,
    l: &Layout,
) -> CliResult<VerificationReport> {
    let mut run_entries: Vec<LedgerEntry> = entries
        .iter()
        .filter(|e| e.run_id == run)
        .cloned()
        .collect();
    if run_entries.is_empty() {
        return Err(CliError::Schema(format!("no entries for run '{run}'")));
    }
    run_entries.sort_by_key(|e| e.run_sequence_number);
    // Re-map run positions onto the global-shaped checker: within one run,
    // the run chain IS the chain (contiguous run_sequence_number wired by
    // previous_run_entry_hash) — feed the engine a projection.
    let mut report = verify_ledger(&run_entries, &[], keys, Some(&l.wal))?;
    // The global-chain columns are meaningless for a subset; the run chain
    // is what was actually checked below.
    let mut chain_valid = true;
    let mut broken_at = None;
    let mut prev = agenomic_ledger_local::GENESIS_ENTRY_HASH.to_string();
    for (i, e) in run_entries.iter().enumerate() {
        if e.run_sequence_number != i as u64 || e.previous_run_entry_hash != prev {
            chain_valid = false;
            broken_at = Some(e.run_sequence_number);
            break;
        }
        prev = e.entry_hash.clone();
    }
    report.chain_evaluated = true;
    report.entries.chain_valid = chain_valid;
    report.entries.broken_at_sequence = broken_at;
    report.sequence_gaps.clear(); // global gaps are expected in a run slice
    report.passed = chain_valid
        && report.entries.hash_failures.is_empty()
        && report.entries.signature_failures.is_empty()
        && report.entries.unresolved_key_failures.is_empty();
    // Blocks are global-scope; only relevant to note coverage of this run.
    let _ = blocks;
    Ok(report)
}

fn verify(
    run: Option<&str>,
    block: Option<&str>,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let entries = read_entries(&l)?;
    let chain = BlockChain::open(&l.blocks)?;
    let keys = open_keys(&l)?;

    let (scope, report) = match (run, block) {
        (Some(run), None) => (
            format!("run {run}"),
            verify_run_scope(run, &entries, chain.blocks(), &keys, &l)?,
        ),
        (None, Some(block_id)) => {
            let selected: Vec<LedgerBlock> = chain
                .blocks()
                .iter()
                .filter(|b| b.block_id == block_id)
                .cloned()
                .collect();
            if selected.is_empty() {
                return Err(CliError::Schema(format!("unknown block '{block_id}'")));
            }
            // Single-block scope: check the block against its covered
            // entries; wiring/coverage of OTHER blocks is out of scope.
            let mut report = verify_ledger(&entries, &selected, &keys, Some(&l.wal))?;
            report.blocks.chain_valid = true;
            report.blocks.broken_at_block = None;
            report.blocks.coverage_gaps.clear();
            report.blocks.unsealed_tail = None;
            report.blocks.valid = report.blocks.merkle_mismatches.is_empty()
                && report.blocks.entries_hash_mismatches.is_empty()
                && report.blocks.hash_failures.is_empty()
                && report.blocks.signature_failures.is_empty()
                && report.blocks.unverifiable_ranges.is_empty();
            report.passed = report.entries.valid && report.chain_evaluated && report.blocks.valid;
            (format!("block {block_id}"), report)
        }
        (None, None) => (
            "full ledger".to_string(),
            verify_ledger(&entries, chain.blocks(), &keys, Some(&l.wal))?,
        ),
        (Some(_), Some(_)) => {
            return Err(CliError::Schema(
                "--run and --block are mutually exclusive".to_string(),
            ))
        }
    };

    let passed = report.passed;
    let out = VerifyOut {
        scope,
        passed,
        report,
    };
    render(&out, format, no_color)?;
    Ok(if passed {
        ExitCode::Success
    } else {
        ExitCode::LedgerIntegrityFailed
    })
}

fn export(
    run: Option<&str>,
    output: &Path,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let mut entries = read_entries(&l)?;
    if let Some(run) = run {
        entries.retain(|e| e.run_id == run);
    }
    let mut lines = String::new();
    for e in &entries {
        lines.push_str(&serde_json::to_string(e).map_err(|e| CliError::Internal(format!("{e}")))?);
        lines.push('\n');
    }
    std::fs::write(output, lines).map_err(|e| io_at(output, e))?;
    let out = ExportOut {
        output: output.display().to_string(),
        entries: entries.len(),
        run: run.map(String::from),
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

fn inspect(
    entry: &str,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let found = read_entries(&l)?
        .into_iter()
        .find(|e| e.ledger_entry_id == entry || e.event_id == entry)
        .ok_or_else(|| CliError::Schema(format!("no entry with id '{entry}'")))?;
    render(&EntryOut { entry: found }, format, no_color)?;
    Ok(ExitCode::Success)
}

fn queue_status(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    // The queue view is the durable subset of the overview.
    status(dirs, format, no_color)
}

fn queue_drain(
    dirs: &LedgerDirs,
    operation: &str,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    // Opening the pipeline runs WAL recovery — that IS the drain/retry.
    let (pipeline, recovery) = open_pipeline(&l)?;
    pipeline.flush(FLUSH_TIMEOUT)?;
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    let pending_after = agenomic_ledger_local::wal::scan_health(&l.wal)?.pending_records;
    let out = DrainOut {
        operation: operation.to_string(),
        replayed: recovery.replayed,
        deduplicated: recovery.deduplicated,
        quarantined_segments: recovery.quarantined_segments,
        pending_after,
    };
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

fn dead_letter_list(
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let records = DeadLetterStore::open(&l.dead_letter)?.list()?;
    render(
        &DeadLettersOut {
            count: records.len(),
            records,
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

fn dead_letter_replay(
    id: Option<&str>,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let store = DeadLetterStore::open(&l.dead_letter)?;
    let records: Vec<DeadLetterRecord> = store
        .list()?
        .into_iter()
        .filter(|r| id.map(|id| r.dead_letter_id == id).unwrap_or(true))
        .collect();
    if let Some(id) = id {
        if records.is_empty() {
            return Err(CliError::Schema(format!(
                "unknown dead-letter record '{id}'"
            )));
        }
    }
    let (pipeline, _) = open_pipeline(&l)?;
    let mut out = ReplayOut {
        replayed: Vec::new(),
        failed: Vec::new(),
    };
    for record in records {
        match pipeline.append(record.draft.clone()) {
            Ok(_) => {
                store.remove(&record.dead_letter_id)?;
                out.replayed.push(record.dead_letter_id);
            }
            Err(e) => out.failed.push((record.dead_letter_id, e.to_string())),
        }
    }
    pipeline.flush(FLUSH_TIMEOUT)?;
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    render(&out, format, no_color)?;
    Ok(ExitCode::Success)
}

fn keys_generate(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    let key_id = open_keys(&l)?.generate()?;
    render(
        &KeyOut {
            key_id,
            action: "generated".to_string(),
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

fn keys_list(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    let keys = open_keys(&l)?;
    let entries = if l.store.exists() {
        read_entries(&l)?
    } else {
        Vec::new()
    };
    let usage = agenomic_ledger_local::verify::key_usage(&entries, &keys);
    let rows = keys
        .list()
        .into_iter()
        .map(|k| KeyRow {
            key_id: k.key_id.clone(),
            status: k.status,
            created_at: k.created_at.to_rfc3339(),
            entries_signed: usage
                .iter()
                .find(|(id, _, _)| *id == k.key_id)
                .map(|(_, _, n)| *n)
                .unwrap_or(0),
        })
        .collect();
    render(&KeysOut { keys: rows }, format, no_color)?;
    Ok(ExitCode::Success)
}

fn keys_rotate(dirs: &LedgerDirs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    let key_id = open_keys(&l)?.rotate()?;
    render(
        &KeyOut {
            key_id,
            action: "rotated to".to_string(),
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

fn keys_revoke(
    key_id: &str,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    open_keys(&l)?.revoke(key_id)?;
    render(
        &KeyOut {
            key_id: key_id.to_string(),
            action: "revoked".to_string(),
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

fn keys_export_public(
    key: Option<&str>,
    output: Option<&Path>,
    dirs: &LedgerDirs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let l = layout(dirs)?;
    let keys = open_keys(&l)?;
    let key_id = match key {
        Some(id) => id.to_string(),
        None => keys.active_key_id()?,
    };
    let pem = keys.export_public(&key_id)?;
    match output {
        Some(path) => {
            std::fs::write(path, &pem).map_err(|e| io_at(path, e))?;
            render(
                &KeyOut {
                    key_id,
                    action: format!("public key written to {}", path.display()),
                },
                format,
                no_color,
            )?;
        }
        None => {
            // The PEM itself is the output — print it raw for piping.
            print!("{pem}");
        }
    }
    Ok(ExitCode::Success)
}

// ---- cross-command integration helpers -------------------------------------

/// Ensure the ledger layout + an active signing key exist (used by
/// integrations like `track start --ledger` so they work without a prior
/// explicit `ledger init`).
pub(crate) fn ensure_ready(dirs: &LedgerDirs) -> CliResult<()> {
    let l = layout(dirs)?;
    let mut keys = open_keys(&l)?;
    if keys.active_key_id().is_err() {
        keys.generate()?;
    }
    if !l.store.exists() {
        let (pipeline, _) = open_pipeline(&l)?;
        pipeline.shutdown(FLUSH_TIMEOUT)?;
    }
    Ok(())
}

/// Append producer drafts through the durable pipeline (blocks disabled —
/// integration appends are one-shot processes; sealing belongs to
/// `ledger seal` and the auto-triggers). Conflicts and validation failures
/// surface as errors after all drafts were attempted; duplicates are
/// idempotent successes.
pub(crate) fn append_drafts(
    dirs: &LedgerDirs,
    drafts: Vec<LedgerEntryDraft>,
) -> CliResult<Vec<agenomic_ledger_local::AppendOutcome>> {
    let l = layout(dirs)?;
    ensure_ready(dirs)?;
    let (pipeline, _) = LedgerPipeline::start(
        FileLedgerStore::open(&l.store)?,
        open_keys(&l)?,
        Some(&l.wal),
        Some(&l.dead_letter),
        None,
        LedgerConfig::default(),
    )?;
    let mut outcomes = Vec::with_capacity(drafts.len());
    let mut first_error: Option<CliError> = None;
    for draft in drafts {
        match pipeline.append(draft) {
            Ok(outcome) => outcomes.push(outcome),
            Err(e) => {
                // Keep appending the rest (each failure is already recorded
                // explicitly by the pipeline); report the first error.
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    pipeline.flush(FLUSH_TIMEOUT)?;
    pipeline.shutdown(FLUSH_TIMEOUT)?;
    match first_error {
        Some(e) => Err(e),
        None => Ok(outcomes),
    }
}

/// Build the ledger proof block for one run (tracking session / replay
/// source). Runs the full verification engine over the ledger.
pub(crate) fn build_proof(
    dirs: &LedgerDirs,
    run_id: &str,
) -> CliResult<agenomic_ledger_local::LedgerProof> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let entries = read_entries(&l)?;
    let blocks = BlockChain::open(&l.blocks)?;
    let keys = open_keys(&l)?;
    let dead_lettered = if l.dead_letter.exists() {
        DeadLetterStore::open(&l.dead_letter)?.len()?
    } else {
        0
    };
    agenomic_ledger_local::build_ledger_proof(
        run_id,
        &entries,
        blocks.blocks(),
        &keys,
        Some(&l.wal),
        dead_lettered,
    )
}

/// Verify one run's chain (used by `replay --from-ledger` as the mandatory
/// pre-replay check). Returns the report; the caller decides the exit path.
pub(crate) fn verify_run_for_integration(
    dirs: &LedgerDirs,
    run_id: &str,
) -> CliResult<VerificationReport> {
    let l = layout(dirs)?;
    require_initialized(&l)?;
    let entries = read_entries(&l)?;
    let chain = BlockChain::open(&l.blocks)?;
    let keys = open_keys(&l)?;
    verify_run_scope(run_id, &entries, chain.blocks(), &keys, &l)
}

// ---- evidence proof bundles -------------------------------------------------

#[derive(Debug, Serialize)]
struct EvidenceExportOut {
    output: String,
    run: Option<String>,
    members: usize,
    absent_members: Vec<String>,
    probative_status: String,
    signing_key_id: String,
}
impl EvidenceExportOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        writeln!(w, "Evidence proof bundle written to {}", self.output).map_err(io)?;
        if let Some(run) = &self.run {
            writeln!(w, "  scope: run {run}").map_err(io)?;
        }
        writeln!(
            w,
            "  members: {} (absent: {})",
            self.members,
            if self.absent_members.is_empty() {
                "none".to_string()
            } else {
                self.absent_members.join(", ")
            }
        )
        .map_err(io)?;
        writeln!(w, "  status: {}", self.probative_status).map_err(io)?;
        writeln!(w, "  signed by: {}", self.signing_key_id).map_err(io)?;
        writeln!(
            w,
            "  verify offline with: agenomic evidence verify {}",
            self.output
        )
        .map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(EvidenceExportOut, "Evidence Export");

#[derive(Debug, Serialize)]
struct EvidenceVerifyOut {
    bundle: String,
    passed: bool,
    result: agenomic_ledger_local::BundleVerification,
}
impl EvidenceVerifyOut {
    fn human(&self, w: &mut dyn Write, _o: &RenderOptions) -> CliResult<()> {
        let verdict = if self.passed { "PASSED" } else { "FAILED" };
        writeln!(
            w,
            "Evidence bundle verification [{verdict}]  {}",
            self.bundle
        )
        .map_err(io)?;
        writeln!(
            w,
            "  manifest signature: {}",
            if self.result.manifest_signature_valid {
                "valid"
            } else {
                "INVALID"
            }
        )
        .map_err(io)?;
        writeln!(w, "  status: {}", self.result.probative_status).map_err(io)?;
        for m in &self.result.member_hash_failures {
            writeln!(w, "  - member hash mismatch: {m}").map_err(io)?;
        }
        for m in &self.result.missing_members {
            writeln!(w, "  - missing member: {m}").map_err(io)?;
        }
        if !self.result.ledger.entries.hash_failures.is_empty() {
            writeln!(
                w,
                "  - entry hash failures at {:?}",
                self.result.ledger.entries.hash_failures
            )
            .map_err(io)?;
        }
        if !self.result.ledger.entries.signature_failures.is_empty() {
            writeln!(
                w,
                "  - entry signature failures at {:?}",
                self.result.ledger.entries.signature_failures
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(EvidenceVerifyOut, "Evidence Verification");

pub fn cmd_evidence(
    args: &crate::cli::EvidenceCommand,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        crate::cli::EvidenceSub::Export {
            run,
            output,
            include_ledger,
            replay_report,
            policy_results,
            risk_summary,
            dirs,
        } => {
            if !include_ledger {
                return Err(CliError::Schema(
                    "only ledger-backed bundles exist locally; pass --include-ledger".to_string(),
                ));
            }
            let l = layout(dirs)?;
            require_initialized(&l)?;
            let entries = read_entries(&l)?;
            let chain = BlockChain::open(&l.blocks)?;
            let keys = open_keys(&l)?;
            let extras = agenomic_ledger_local::BundleExtras {
                replay_report: replay_report.clone(),
                policy_results: policy_results.clone(),
                risk_summary: risk_summary.clone(),
            };
            let manifest = agenomic_ledger_local::assemble_bundle(
                output,
                run.as_deref(),
                &entries,
                chain.blocks(),
                &keys,
                &extras,
            )?;
            let out = EvidenceExportOut {
                output: output.display().to_string(),
                run: run.clone(),
                members: manifest.members.len(),
                absent_members: manifest.absent_members.clone(),
                probative_status: manifest.probative_status.clone(),
                signing_key_id: manifest.signing_key_id.clone(),
            };
            render(&out, format, no_color)?;
            Ok(ExitCode::Success)
        }
        crate::cli::EvidenceSub::Verify { bundle } => {
            let result = agenomic_ledger_local::verify_bundle(bundle)?;
            let passed = result.passed;
            let out = EvidenceVerifyOut {
                bundle: bundle.display().to_string(),
                passed,
                result,
            };
            render(&out, format, no_color)?;
            Ok(if passed {
                ExitCode::Success
            } else {
                ExitCode::LedgerIntegrityFailed
            })
        }
    }
}
