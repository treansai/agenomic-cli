//! Write-ahead log: the durable spool between the hot path and the ledger.
//!
//! Design template: `agenomic-atep::segment` (framing, CRC, magic, tail
//! discipline), simplified for a spool whose records are *drained into* the
//! signed ledger rather than being the ledger themselves.
//!
//! ## Segment binary layout (LE)
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │ MAGIC        "ALWL"        4 B                │
//! │ VERSION      u16           2 B                │
//! │ RESERVED     u16           2 B                │
//! │ FRAMES (repeated):                            │
//! │   FRAME_LEN  u32           4 B                │
//! │   FRAME_CRC  u32 (crc32 of payload)           │
//! │   PAYLOAD    FRAME_LEN B (JSON WalRecord)     │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! Segments are `wal-<8digit>.wal`, rotated by size. Records carry a
//! monotonically increasing `wal_seq` spanning segments. A `checkpoint.json`
//! records the highest `wal_seq` already applied to the ledger; recovery
//! replays everything above it (idempotently — the pipeline dedups by
//! `event_id`).
//!
//! Corruption rules (§5.7: never silently drop):
//! - A truncated tail in the **last** segment is a crash artifact: the good
//!   prefix is kept, the truncation is reported, and the file is truncated
//!   so new appends continue cleanly.
//! - A CRC/framing error anywhere else quarantines the segment as
//!   `<name>.corrupt` (preserved for forensics, never deleted) and is
//!   reported; recovery continues with the remaining segments.

use crate::entry::LedgerEntryDraft;
use agenomic_core::{io_at, CliError, CliResult};
use agenomic_fs::write_atomic;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Magic bytes opening every WAL segment.
pub const WAL_MAGIC: &[u8; 4] = b"ALWL";
/// Current segment format version.
pub const WAL_VERSION: u16 = 1;
/// Checkpoint file name inside the WAL directory.
pub const WAL_CHECKPOINT_FILE: &str = "checkpoint.json";

const HEADER_LEN: u64 = 8;
const FRAME_HEADER_LEN: usize = 8;
/// Hard sanity cap on a single frame (a corrupt length prefix must not
/// trigger a giant allocation).
const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

/// One spooled event: the draft as accepted by the hot path (payload already
/// resolved to a hash — raw payloads never reach the WAL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    /// Monotonic position in the WAL, spanning segments.
    pub wal_seq: u64,
    /// The draft; `event_id` is always assigned by the time it is spooled.
    pub draft: LedgerEntryDraft,
}

/// What recovery found and did (surfaced by status APIs — corruption is
/// reported, never hidden).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalRecoveryReport {
    /// Records above the checkpoint, in `wal_seq` order (replay candidates).
    #[serde(skip)]
    pub pending: Vec<WalRecord>,
    /// Segments quarantined as `.corrupt`.
    pub quarantined_segments: Vec<String>,
    /// Bytes truncated off the last segment (crash artifact).
    pub truncated_bytes: u64,
    /// Fully-applied segments removed during cleanup.
    pub removed_segments: Vec<String>,
    /// Highest `wal_seq` seen anywhere in the WAL.
    pub last_wal_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    applied_wal_seq: u64,
}

/// Read-only WAL health snapshot for verification reports (§5.9 "corrupted
/// WAL segments" check). Unlike [`WalWriter::open`], this never truncates,
/// quarantines, or deletes anything.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalHealth {
    /// Live `.wal` segments on disk.
    pub segments: u64,
    /// Segments with CRC/framing damage (including a torn tail).
    pub damaged_segments: Vec<String>,
    /// Previously quarantined `.corrupt` files still present.
    pub quarantined_segments: Vec<String>,
    /// Records above the checkpoint (durable but not yet sealed into the
    /// ledger).
    pub pending_records: u64,
}

/// Scan a WAL directory read-only and report its health.
///
/// ```
/// # use agenomic_ledger_local::wal::scan_health;
/// # let dir = tempfile::tempdir().unwrap();
/// let health = scan_health(dir.path()).unwrap();
/// assert_eq!(health.segments, 0);
/// ```
pub fn scan_health(dir: &Path) -> CliResult<WalHealth> {
    let mut health = WalHealth::default();
    if !dir.exists() {
        return Ok(health);
    }
    let checkpoint = WalWriter::read_checkpoint(dir)?;
    for segment in list_segments(dir)? {
        health.segments += 1;
        let name = segment
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        match read_segment(&segment) {
            Ok((records, _, torn)) => {
                if torn {
                    health.damaged_segments.push(name);
                }
                health.pending_records +=
                    records.iter().filter(|r| r.wal_seq > checkpoint).count() as u64;
            }
            Err(_) => health.damaged_segments.push(name),
        }
    }
    for entry in std::fs::read_dir(dir).map_err(|e| io_at(dir, e))? {
        let path = entry.map_err(|e| io_at(dir, e))?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".corrupt") {
            health.quarantined_segments.push(name.to_string());
        }
    }
    Ok(health)
}

/// Append-side handle over a WAL directory.
#[derive(Debug)]
pub struct WalWriter {
    dir: PathBuf,
    segment_max_bytes: u64,
    disk_max_bytes: u64,
    /// Path + current size of the open segment.
    current: PathBuf,
    current_len: u64,
    /// Total bytes across all live segments (disk-cap accounting).
    total_len: u64,
    next_wal_seq: u64,
}

fn segment_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("wal-{index:08}.wal"))
}

fn list_segments(dir: &Path) -> CliResult<Vec<PathBuf>> {
    let mut segments = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(dir).map_err(|e| io_at(dir, e))? {
            let path = entry.map_err(|e| io_at(dir, e))?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("wal-") && name.ends_with(".wal") {
                segments.push(path);
            }
        }
    }
    segments.sort();
    Ok(segments)
}

fn segment_index(path: &Path) -> u32 {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("wal-"))
        .and_then(|n| n.strip_suffix(".wal"))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Read every intact frame of one segment. Returns the records plus the
/// byte offset after the last good frame (for tail truncation) and whether
/// the segment ended mid-frame.
fn read_segment(path: &Path) -> CliResult<(Vec<WalRecord>, u64, bool)> {
    let mut file = std::fs::File::open(path).map_err(|e| io_at(path, e))?;
    let mut header = [0u8; HEADER_LEN as usize];
    if file.read_exact(&mut header).is_err() {
        // Shorter than a header: nothing recoverable in this segment.
        return Ok((Vec::new(), 0, true));
    }
    if &header[0..4] != WAL_MAGIC {
        return Err(CliError::LedgerIntegrity {
            reason: format!("{} is not a WAL segment (bad magic)", path.display()),
        });
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != WAL_VERSION {
        return Err(CliError::LedgerIntegrity {
            reason: format!(
                "unsupported WAL segment version {version} in {}",
                path.display()
            ),
        });
    }

    let mut rest = Vec::new();
    file.read_to_end(&mut rest).map_err(|e| io_at(path, e))?;

    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut good_end = HEADER_LEN;
    let mut torn = false;
    while offset < rest.len() {
        if rest.len() - offset < FRAME_HEADER_LEN {
            torn = true;
            break;
        }
        let len = u32::from_le_bytes([
            rest[offset],
            rest[offset + 1],
            rest[offset + 2],
            rest[offset + 3],
        ]);
        let crc = u32::from_le_bytes([
            rest[offset + 4],
            rest[offset + 5],
            rest[offset + 6],
            rest[offset + 7],
        ]);
        if len > MAX_FRAME_LEN || rest.len() - offset - FRAME_HEADER_LEN < len as usize {
            torn = true;
            break;
        }
        let start = offset + FRAME_HEADER_LEN;
        let payload = &rest[start..start + len as usize];
        if crc32fast::hash(payload) != crc {
            torn = true;
            break;
        }
        let record: WalRecord =
            serde_json::from_slice(payload).map_err(|e| CliError::LedgerIntegrity {
                reason: format!("undecodable WAL record in {}: {e}", path.display()),
            })?;
        records.push(record);
        offset = start + len as usize;
        good_end = HEADER_LEN + offset as u64;
    }
    Ok((records, good_end, torn))
}

impl WalWriter {
    /// Open (or create) the WAL at `dir` and run recovery: collect records
    /// above the checkpoint, quarantine corrupt segments, truncate a torn
    /// tail, and delete fully-applied segments.
    ///
    /// ```
    /// # use agenomic_ledger_local::wal::WalWriter;
    /// # let dir = tempfile::tempdir().unwrap();
    /// let (wal, report) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
    /// assert!(report.pending.is_empty());
    /// assert_eq!(wal.total_bytes(), 0);
    /// ```
    pub fn open(
        dir: &Path,
        segment_max_bytes: u64,
        disk_max_bytes: u64,
    ) -> CliResult<(Self, WalRecoveryReport)> {
        std::fs::create_dir_all(dir).map_err(|e| io_at(dir, e))?;
        let checkpoint = Self::read_checkpoint(dir)?;
        let mut report = WalRecoveryReport::default();
        let segments = list_segments(dir)?;
        let last_index = segments.last().map(|p| segment_index(p)).unwrap_or(0);

        let mut total_len = 0u64;
        for (i, segment) in segments.iter().enumerate() {
            let is_last = i + 1 == segments.len();
            match read_segment(segment) {
                Ok((records, good_end, torn)) => {
                    if torn && is_last {
                        // Crash artifact: keep the good prefix, drop the torn
                        // tail so future appends produce a clean segment.
                        let full = std::fs::metadata(segment)
                            .map_err(|e| io_at(segment, e))?
                            .len();
                        report.truncated_bytes += full - good_end;
                        let file = std::fs::OpenOptions::new()
                            .write(true)
                            .open(segment)
                            .map_err(|e| io_at(segment, e))?;
                        file.set_len(good_end).map_err(|e| io_at(segment, e))?;
                        file.sync_all().map_err(|e| io_at(segment, e))?;
                    } else if torn {
                        // Torn frames in a non-final segment: quarantine what
                        // follows the good prefix; the good records still
                        // count.
                        Self::quarantine(segment, &mut report)?;
                    }
                    let mut fully_applied = true;
                    for record in records {
                        report.last_wal_seq = report.last_wal_seq.max(record.wal_seq);
                        if record.wal_seq > checkpoint {
                            fully_applied = false;
                            report.pending.push(record);
                        }
                    }
                    if fully_applied && !torn {
                        // Every record is already in the signed ledger; the
                        // segment is safe to remove (also for the last one —
                        // a fresh segment starts on the next append, and
                        // `next_wal_seq` stays above the checkpoint so
                        // sequence numbers are never reused).
                        std::fs::remove_file(segment).map_err(|e| io_at(segment, e))?;
                        report.removed_segments.push(
                            segment
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("")
                                .to_string(),
                        );
                        continue;
                    }
                }
                Err(_) => Self::quarantine(segment, &mut report)?,
            }
            if segment.exists() {
                total_len += std::fs::metadata(segment)
                    .map_err(|e| io_at(segment, e))?
                    .len();
            }
        }
        report.pending.sort_by_key(|r| r.wal_seq);

        let current = segment_path(dir, last_index.max(1));
        let current_len = if current.exists() {
            std::fs::metadata(&current)
                .map_err(|e| io_at(&current, e))?
                .len()
        } else {
            0
        };
        Ok((
            Self {
                dir: dir.to_path_buf(),
                segment_max_bytes,
                disk_max_bytes,
                current,
                current_len,
                total_len,
                // Above both the highest surviving record AND the
                // checkpoint: after a full cleanup the sequence must not
                // restart below the checkpoint, or recovery would skip
                // fresh records as already-applied.
                next_wal_seq: report.last_wal_seq.max(checkpoint) + 1,
            },
            report,
        ))
    }

    /// Append one record durably (fsync'd) and return its `wal_seq`.
    ///
    /// Hitting `disk_max_bytes` is an explicit [`CliError::LedgerBusy`] —
    /// the §5.7 disk-full behavior: a clear failure state, not data loss.
    pub fn append(&mut self, draft: &LedgerEntryDraft) -> CliResult<u64> {
        let wal_seq = self.next_wal_seq;
        let record = WalRecord {
            wal_seq,
            draft: draft.clone(),
        };
        let payload = serde_json::to_vec(&record)
            .map_err(|e| CliError::Internal(format!("serialize WAL record: {e}")))?;
        let frame_len = (FRAME_HEADER_LEN + payload.len()) as u64;

        if self.total_len + frame_len > self.disk_max_bytes {
            return Err(CliError::LedgerBusy {
                reason: format!(
                    "WAL disk budget exhausted ({} of {} bytes used); the event was refused, \
                     not dropped",
                    self.total_len, self.disk_max_bytes
                ),
            });
        }
        if self.current_len >= self.segment_max_bytes {
            self.rotate()?;
        }

        let is_new = !self.current.exists();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current)
            .map_err(|e| io_at(&self.current, e))?;
        if is_new || self.current_len == 0 {
            let mut header = Vec::with_capacity(HEADER_LEN as usize);
            header.extend_from_slice(WAL_MAGIC);
            header.extend_from_slice(&WAL_VERSION.to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            file.write_all(&header)
                .map_err(|e| io_at(&self.current, e))?;
            self.current_len = HEADER_LEN;
            self.total_len += HEADER_LEN;
        }
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        frame.extend_from_slice(&payload);
        file.write_all(&frame)
            .map_err(|e| io_at(&self.current, e))?;
        file.sync_all().map_err(|e| io_at(&self.current, e))?;

        self.current_len += frame.len() as u64;
        self.total_len += frame.len() as u64;
        self.next_wal_seq += 1;
        Ok(wal_seq)
    }

    /// Persist the applied watermark: every record with `wal_seq <=
    /// applied_wal_seq` is in the signed ledger.
    pub fn checkpoint(&self, applied_wal_seq: u64) -> CliResult<()> {
        let raw = serde_json::to_vec_pretty(&Checkpoint { applied_wal_seq })
            .map_err(|e| CliError::Internal(format!("serialize WAL checkpoint: {e}")))?;
        write_atomic(&self.dir.join(WAL_CHECKPOINT_FILE), &raw)
    }

    /// Records above the current checkpoint, in order (the durable backlog).
    pub fn pending(&self) -> CliResult<Vec<WalRecord>> {
        let checkpoint = Self::read_checkpoint(&self.dir)?;
        let mut pending = Vec::new();
        for segment in list_segments(&self.dir)? {
            let (records, _, _) = read_segment(&segment)?;
            pending.extend(records.into_iter().filter(|r| r.wal_seq > checkpoint));
        }
        pending.sort_by_key(|r| r.wal_seq);
        Ok(pending)
    }

    /// Total live WAL bytes on disk.
    pub fn total_bytes(&self) -> u64 {
        self.total_len
    }

    /// WAL directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn rotate(&mut self) -> CliResult<()> {
        let next_index = segment_index(&self.current) + 1;
        self.current = segment_path(&self.dir, next_index);
        self.current_len = 0;
        Ok(())
    }

    fn read_checkpoint(dir: &Path) -> CliResult<u64> {
        let path = dir.join(WAL_CHECKPOINT_FILE);
        if !path.exists() {
            return Ok(0);
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
        let checkpoint: Checkpoint =
            serde_json::from_str(&raw).map_err(|e| CliError::LedgerIntegrity {
                reason: format!("corrupt WAL checkpoint: {e}"),
            })?;
        Ok(checkpoint.applied_wal_seq)
    }

    fn quarantine(segment: &Path, report: &mut WalRecoveryReport) -> CliResult<()> {
        let corrupt = segment.with_extension("wal.corrupt");
        std::fs::rename(segment, &corrupt).map_err(|e| io_at(segment, e))?;
        report.quarantined_segments.push(
            corrupt
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
    use tempfile::tempdir;

    fn draft(n: u64) -> LedgerEntryDraft {
        let mut d = LedgerEntryDraft::new(
            "agent://acme/support",
            "run-1",
            "agent.started",
            PayloadCommitment::Hash(format!("blake3:{}", format!("{n:02x}").repeat(32))),
            IngestionSource::Tracking,
        );
        d.event_id = Some(format!("event-{n}"));
        d
    }

    #[test]
    fn append_recover_roundtrip() {
        let dir = tempdir().unwrap();
        {
            let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
            for n in 0..5 {
                wal.append(&draft(n)).unwrap();
            }
        }
        // Reopen with no checkpoint: everything is pending, in order.
        let (_, report) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        assert_eq!(report.pending.len(), 5);
        let seqs: Vec<u64> = report.pending.iter().map(|r| r.wal_seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        assert!(report.quarantined_segments.is_empty());
        assert_eq!(report.truncated_bytes, 0);
    }

    #[test]
    fn checkpoint_limits_replay() {
        let dir = tempdir().unwrap();
        let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        for n in 0..4 {
            wal.append(&draft(n)).unwrap();
        }
        wal.checkpoint(2).unwrap();
        let (_, report) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        let seqs: Vec<u64> = report.pending.iter().map(|r| r.wal_seq).collect();
        assert_eq!(seqs, vec![3, 4]);
    }

    #[test]
    fn torn_tail_is_truncated_and_reported() {
        let dir = tempdir().unwrap();
        let segment = {
            let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
            for n in 0..3 {
                wal.append(&draft(n)).unwrap();
            }
            wal.current.clone()
        };
        // Simulate a crash mid-write: append garbage half-frame.
        let mut raw = std::fs::read(&segment).unwrap();
        let good_len = raw.len() as u64;
        raw.extend_from_slice(&[0x2a, 0x00, 0x00]);
        std::fs::write(&segment, &raw).unwrap();

        let (wal, report) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        assert_eq!(report.pending.len(), 3, "good prefix survives");
        assert_eq!(report.truncated_bytes, 3);
        assert_eq!(std::fs::metadata(&segment).unwrap().len(), good_len);
        // Appends continue cleanly after truncation.
        drop(wal);
        let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        wal.append(&draft(9)).unwrap();
    }

    #[test]
    fn corrupted_crc_mid_segment_quarantines_but_keeps_prefix() {
        let dir = tempdir().unwrap();
        // Two segments: tiny segment cap forces rotation.
        let first_segment = {
            let (mut wal, _) = WalWriter::open(dir.path(), 64, 1 << 24).unwrap();
            for n in 0..4 {
                wal.append(&draft(n)).unwrap();
            }
            segment_path(dir.path(), 1)
        };
        // Flip one payload byte in the FIRST (non-final) segment: CRC breaks.
        let mut raw = std::fs::read(&first_segment).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&first_segment, &raw).unwrap();

        let (_, report) = WalWriter::open(dir.path(), 64, 1 << 24).unwrap();
        // The corrupt segment is preserved for forensics, not deleted.
        assert_eq!(report.quarantined_segments.len(), 1);
        assert!(dir.path().join(&report.quarantined_segments[0]).exists());
        // Records from intact segments are still pending.
        assert!(!report.pending.is_empty());
    }

    #[test]
    fn disk_budget_is_an_explicit_busy_error() {
        let dir = tempdir().unwrap();
        let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 600).unwrap();
        let mut accepted = 0u32;
        let mut refused = 0u32;
        for n in 0..50 {
            match wal.append(&draft(n)) {
                Ok(_) => accepted += 1,
                Err(CliError::LedgerBusy { .. }) => refused += 1,
                Err(other) => panic!("unexpected error: {other}"),
            }
        }
        assert!(accepted > 0, "some appends fit the budget");
        assert!(refused > 0, "budget exhaustion is explicit");
        assert_eq!(accepted + refused, 50, "no silent outcomes");
    }

    #[test]
    fn fully_applied_segments_are_removed_on_open() {
        let dir = tempdir().unwrap();
        {
            let (mut wal, _) = WalWriter::open(dir.path(), 64, 1 << 24).unwrap();
            for n in 0..6 {
                wal.append(&draft(n)).unwrap();
            }
            wal.checkpoint(6).unwrap();
        }
        let segments_before = list_segments(dir.path()).unwrap().len();
        assert!(segments_before > 1, "rotation produced multiple segments");
        let (_, report) = WalWriter::open(dir.path(), 64, 1 << 24).unwrap();
        assert!(report.pending.is_empty());
        assert!(!report.removed_segments.is_empty());
        let segments_after = list_segments(dir.path()).unwrap().len();
        assert!(segments_after < segments_before);
    }

    #[test]
    fn wal_never_contains_raw_payloads() {
        let dir = tempdir().unwrap();
        let (mut wal, _) = WalWriter::open(dir.path(), 1 << 20, 1 << 24).unwrap();
        // The pipeline resolves inline payloads before spooling; simulate
        // that contract here and assert the on-disk bytes hold only hashes.
        let mut d = draft(0);
        d.payload = PayloadCommitment::Hash(
            PayloadCommitment::Inline(serde_json::json!({ "secret": "s3cr3t-value" }))
                .resolve()
                .unwrap(),
        );
        wal.append(&d).unwrap();
        for segment in list_segments(dir.path()).unwrap() {
            let raw = std::fs::read(segment).unwrap();
            let text = String::from_utf8_lossy(&raw);
            assert!(!text.contains("s3cr3t-value"));
        }
    }
}
