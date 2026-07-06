//! Ledger persistence: the `LedgerStore` trait plus the in-memory and
//! file-backed implementations that ship in v1 (per the Phase 0 plan; a
//! DB-backed store is out of scope for this workspace).
//!
//! Stores are dumb append-only logs — chain linking, hashing, and signing
//! happen in [`crate::ledger::Ledger`] before an entry reaches a store.
//! The Phase 2 WAL/segment format replaces the simple JSONL file as the
//! durable path; the trait is deliberately minimal so that lands without
//! breaking callers.

use crate::entry::LedgerEntry;
use agenomic_core::{io_at, CliError, CliResult};
use agenomic_fs::write_atomic;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Manifest schema version for the file store.
pub const LEDGER_MANIFEST_VERSION: &str = "agenomic.ledger.store/v0.1";
/// File name of the store manifest inside the ledger root.
pub const LEDGER_MANIFEST_FILE: &str = "manifest.json";
/// File name of the append-only entry log inside the ledger root.
pub const LEDGER_LOG_FILE: &str = "ledger.jsonl";

/// Append-only persistence for sealed entries.
pub trait LedgerStore {
    /// Append one sealed entry. Implementations must be append-only; an
    /// entry, once written, is never mutated or removed.
    fn append(&mut self, entry: &LedgerEntry) -> CliResult<()>;
    /// All entries in append order.
    fn read_all(&self) -> CliResult<Vec<LedgerEntry>>;
    /// Number of persisted entries.
    fn len(&self) -> CliResult<u64>;
    /// Whether the store holds no entries.
    fn is_empty(&self) -> CliResult<bool> {
        Ok(self.len()? == 0)
    }
}

/// In-memory store for tests and `best_effort` experimentation. Contents
/// vanish with the process.
#[derive(Debug, Default)]
pub struct MemoryLedgerStore {
    entries: Vec<LedgerEntry>,
}

impl MemoryLedgerStore {
    /// An empty in-memory store.
    ///
    /// ```
    /// # use agenomic_ledger_local::store::{LedgerStore, MemoryLedgerStore};
    /// let store = MemoryLedgerStore::new();
    /// assert!(store.is_empty().unwrap());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
}

impl LedgerStore for MemoryLedgerStore {
    fn append(&mut self, entry: &LedgerEntry) -> CliResult<()> {
        self.entries.push(entry.clone());
        Ok(())
    }

    fn read_all(&self) -> CliResult<Vec<LedgerEntry>> {
        Ok(self.entries.clone())
    }

    fn len(&self) -> CliResult<u64> {
        Ok(self.entries.len() as u64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerManifest {
    manifest_version: String,
    entry_count: u64,
    /// Entry hash of the latest entry (genesis constant when empty). A fast
    /// consistency probe; the log itself is the source of truth.
    head_hash: String,
}

/// File-backed store rooted at a directory (default `.agenomic/ledger/`,
/// Q8): an append-only `ledger.jsonl` (one entry per line) plus a
/// `manifest.json` updated atomically after each append.
#[derive(Debug)]
pub struct FileLedgerStore {
    root: PathBuf,
    manifest: LedgerManifest,
}

impl FileLedgerStore {
    /// Open the store at `root`, creating an empty one if absent.
    ///
    /// ```
    /// # use agenomic_ledger_local::store::{FileLedgerStore, LedgerStore};
    /// # let dir = tempfile::tempdir().unwrap();
    /// let store = FileLedgerStore::open(dir.path()).unwrap();
    /// assert_eq!(store.len().unwrap(), 0);
    /// ```
    pub fn open(root: &Path) -> CliResult<Self> {
        let manifest_path = root.join(LEDGER_MANIFEST_FILE);
        let manifest = if manifest_path.exists() {
            let raw =
                std::fs::read_to_string(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: LedgerManifest = serde_json::from_str(&raw)
                .map_err(|e| CliError::Schema(format!("parse ledger manifest: {e}")))?;
            if manifest.manifest_version != LEDGER_MANIFEST_VERSION {
                return Err(CliError::Schema(format!(
                    "unsupported ledger manifest version {:?} (expected {LEDGER_MANIFEST_VERSION:?})",
                    manifest.manifest_version
                )));
            }
            manifest
        } else {
            std::fs::create_dir_all(root).map_err(|e| io_at(root, e))?;
            LedgerManifest {
                manifest_version: LEDGER_MANIFEST_VERSION.to_string(),
                entry_count: 0,
                head_hash: crate::canonical::GENESIS_ENTRY_HASH.to_string(),
            }
        };
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
        })
    }

    /// Root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn save_manifest(&self) -> CliResult<()> {
        let raw = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| CliError::Internal(format!("serialize ledger manifest: {e}")))?;
        write_atomic(&self.root.join(LEDGER_MANIFEST_FILE), &raw)
    }
}

impl LedgerStore for FileLedgerStore {
    fn append(&mut self, entry: &LedgerEntry) -> CliResult<()> {
        let log_path = self.root.join(LEDGER_LOG_FILE);
        let line = serde_json::to_string(entry)
            .map_err(|e| CliError::Internal(format!("serialize ledger entry: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| io_at(&log_path, e))?;
        // One entry per line; flush + fsync before the manifest advances so a
        // crash never yields a manifest ahead of the log.
        writeln!(file, "{line}").map_err(|e| io_at(&log_path, e))?;
        file.sync_all().map_err(|e| io_at(&log_path, e))?;

        self.manifest.entry_count += 1;
        self.manifest.head_hash = entry.entry_hash.clone();
        self.save_manifest()
    }

    fn read_all(&self) -> CliResult<Vec<LedgerEntry>> {
        let log_path = self.root.join(LEDGER_LOG_FILE);
        if !log_path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&log_path).map_err(|e| io_at(&log_path, e))?;
        let mut entries = Vec::new();
        for (i, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: LedgerEntry =
                serde_json::from_str(line).map_err(|e| CliError::LedgerIntegrity {
                    reason: format!("corrupt ledger log line {}: {e}", i + 1),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn len(&self) -> CliResult<u64> {
        Ok(self.manifest.entry_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_entry(seq: u64) -> LedgerEntry {
        use crate::chain::ChainState;
        let mut state = ChainState::new();
        let mut last = None;
        for i in 0..=seq {
            let pos = state.allocate("run-1");
            let mut e = crate::ledger::tests::unsigned_entry_at("run-1", &pos);
            e.ledger_entry_id = format!("entry-{i}");
            e.entry_hash = e.compute_entry_hash().unwrap();
            state.advance(&e);
            last = Some(e);
        }
        last.expect("at least one entry")
    }

    #[test]
    fn file_store_roundtrips_and_counts() {
        let dir = tempdir().unwrap();
        {
            let mut store = FileLedgerStore::open(dir.path()).unwrap();
            store.append(&sample_entry(0)).unwrap();
            store.append(&sample_entry(1)).unwrap();
            assert_eq!(store.len().unwrap(), 2);
        }
        // Reopen: manifest and log agree.
        let store = FileLedgerStore::open(dir.path()).unwrap();
        assert_eq!(store.len().unwrap(), 2);
        let entries = store.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[1].hash_is_valid().unwrap());
    }

    #[test]
    fn corrupt_log_line_is_an_integrity_error() {
        let dir = tempdir().unwrap();
        let mut store = FileLedgerStore::open(dir.path()).unwrap();
        store.append(&sample_entry(0)).unwrap();
        std::fs::write(
            dir.path().join(LEDGER_LOG_FILE),
            "{\"not\": \"an entry\"}\n",
        )
        .unwrap();
        let err = store.read_all().unwrap_err();
        assert!(matches!(err, CliError::LedgerIntegrity { .. }));
    }
}
