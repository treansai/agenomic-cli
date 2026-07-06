//! Dead-letter store: the explicit, visible terminal state for events the
//! pipeline could not append.
//!
//! Product guarantee #1: every emitted event reaches a durable state or an
//! explicit failure state — the dead-letter store *is* that failure state.
//! Records are JSON files (one per event) so they are inspectable with
//! nothing but a text editor and replayable via
//! `agenomic ledger queue dead-letter replay` (Phase 4).

use crate::entry::LedgerEntryDraft;
use agenomic_core::{io_at, CliError, CliResult};
use agenomic_fs::write_atomic;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Why an event was dead-lettered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    /// Draft failed validation (empty required field, malformed or
    /// oversized payload).
    InvalidEvent,
    /// Same `event_id` already appended with a *different* payload hash —
    /// recorded with a tampering warning, the original is never overwritten.
    Conflict,
    /// Transient failures exhausted the retry budget.
    RetriesExhausted,
}

impl DeadLetterReason {
    /// Stable snake_case label (matches the serde encoding).
    ///
    /// ```
    /// # use agenomic_ledger_local::deadletter::DeadLetterReason;
    /// assert_eq!(DeadLetterReason::Conflict.label(), "conflict");
    /// ```
    pub fn label(&self) -> &'static str {
        match self {
            Self::InvalidEvent => "invalid_event",
            Self::Conflict => "conflict",
            Self::RetriesExhausted => "retries_exhausted",
        }
    }
}

/// One dead-lettered event, with everything needed to diagnose and replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterRecord {
    /// File-name id (`dl-<ulid>`), unique per record.
    pub dead_letter_id: String,
    pub event_id: String,
    pub reason: DeadLetterReason,
    /// Human-readable detail (e.g. the underlying error, sanitized).
    pub detail: String,
    /// How many append attempts were made before dead-lettering.
    pub attempts: u32,
    pub failed_at: DateTime<Utc>,
    /// The draft as it entered the pipeline (payload committed by hash —
    /// never raw content).
    pub draft: LedgerEntryDraft,
}

/// Directory-backed dead-letter store (`<ledger>/dead-letter/dl-<ulid>.json`).
#[derive(Debug)]
pub struct DeadLetterStore {
    dir: PathBuf,
}

impl DeadLetterStore {
    /// Open (creating if needed) the store at `dir`.
    ///
    /// ```
    /// # use agenomic_ledger_local::deadletter::DeadLetterStore;
    /// # let dir = tempfile::tempdir().unwrap();
    /// let store = DeadLetterStore::open(dir.path()).unwrap();
    /// assert!(store.list().unwrap().is_empty());
    /// ```
    pub fn open(dir: &Path) -> CliResult<Self> {
        std::fs::create_dir_all(dir).map_err(|e| io_at(dir, e))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Record a dead-lettered event. Returns the `dead_letter_id`.
    pub fn record(
        &self,
        draft: &LedgerEntryDraft,
        reason: DeadLetterReason,
        detail: impl Into<String>,
        attempts: u32,
    ) -> CliResult<String> {
        let dead_letter_id = format!("dl-{}", ulid::Ulid::new());
        let record = DeadLetterRecord {
            dead_letter_id: dead_letter_id.clone(),
            event_id: draft.event_id.clone().unwrap_or_default(),
            reason,
            detail: detail.into(),
            attempts,
            failed_at: Utc::now(),
            draft: draft.clone(),
        };
        let raw = serde_json::to_vec_pretty(&record)
            .map_err(|e| CliError::Internal(format!("serialize dead-letter record: {e}")))?;
        write_atomic(&self.dir.join(format!("{dead_letter_id}.json")), &raw)?;
        Ok(dead_letter_id)
    }

    /// All records, oldest first (ULID file names sort chronologically).
    pub fn list(&self) -> CliResult<Vec<DeadLetterRecord>> {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(|e| io_at(&self.dir, e))? {
            let path = entry.map_err(|e| io_at(&self.dir, e))?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("dl-") && name.ends_with(".json") {
                paths.push(path);
            }
        }
        paths.sort();
        let mut records = Vec::with_capacity(paths.len());
        for path in paths {
            let raw = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
            let record = serde_json::from_str(&raw).map_err(|e| CliError::LedgerIntegrity {
                reason: format!("corrupt dead-letter record {}: {e}", path.display()),
            })?;
            records.push(record);
        }
        Ok(records)
    }

    /// Remove a record after a successful replay. Refuses unknown ids.
    pub fn remove(&self, dead_letter_id: &str) -> CliResult<()> {
        let path = self.dir.join(format!("{dead_letter_id}.json"));
        if !path.exists() {
            return Err(CliError::LedgerConflict {
                reason: format!("unknown dead-letter record {dead_letter_id}"),
            });
        }
        std::fs::remove_file(&path).map_err(|e| io_at(&path, e))
    }

    /// Number of records currently dead-lettered.
    pub fn len(&self) -> CliResult<u64> {
        Ok(self.list()?.len() as u64)
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> CliResult<bool> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{IngestionSource, PayloadCommitment};
    use serde_json::json;
    use tempfile::tempdir;

    fn draft(event_id: &str) -> LedgerEntryDraft {
        let mut d = LedgerEntryDraft::new(
            "agent://acme/support",
            "run-1",
            "agent.started",
            PayloadCommitment::Hash(
                PayloadCommitment::Inline(json!({"k": "v"}))
                    .resolve()
                    .unwrap(),
            ),
            IngestionSource::Tracking,
        );
        d.event_id = Some(event_id.to_string());
        d
    }

    #[test]
    fn record_list_remove_roundtrip() {
        let dir = tempdir().unwrap();
        let store = DeadLetterStore::open(dir.path()).unwrap();
        let id1 = store
            .record(
                &draft("e-1"),
                DeadLetterReason::InvalidEvent,
                "empty run_id",
                1,
            )
            .unwrap();
        store
            .record(
                &draft("e-2"),
                DeadLetterReason::RetriesExhausted,
                "io error",
                3,
            )
            .unwrap();

        let records = store.list().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].dead_letter_id, id1);
        assert_eq!(records[0].event_id, "e-1");
        assert_eq!(records[1].attempts, 3);

        store.remove(&id1).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        assert!(store.remove(&id1).is_err(), "double remove refused");
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempdir().unwrap();
        {
            let store = DeadLetterStore::open(dir.path()).unwrap();
            store
                .record(
                    &draft("e-1"),
                    DeadLetterReason::Conflict,
                    "hash mismatch",
                    1,
                )
                .unwrap();
        }
        let store = DeadLetterStore::open(dir.path()).unwrap();
        let records = store.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, DeadLetterReason::Conflict);
    }
}
