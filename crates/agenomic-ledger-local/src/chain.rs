//! Chain state: global (per-store) and per-run hash chains.
//!
//! Every entry links `previous_entry_hash` (global order) and
//! `previous_run_entry_hash` (per-run order). Genesis for both is
//! [`crate::canonical::GENESIS_ENTRY_HASH`]. Per-turn chains are deferred
//! (Q5); `turn_id`/`turn_sequence_number` are recorded so a turn chain can be
//! added additively later.

use crate::canonical::GENESIS_ENTRY_HASH;
use crate::entry::LedgerEntry;
use agenomic_core::{CliError, CliResult};
use std::collections::BTreeMap;

/// Head of one run's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunHead {
    /// Sequence number the next entry in this run will take.
    pub next_run_sequence: u64,
    /// Entry hash of the run's latest entry.
    pub head_hash: String,
}

/// Chain positions allocated for the next entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPositions {
    pub sequence_number: u64,
    pub previous_entry_hash: String,
    pub run_sequence_number: u64,
    pub previous_run_entry_hash: String,
}

/// In-memory head state of a ledger's chains. Rebuilt from the store on open
/// via [`ChainState::from_entries`]; advanced on every append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    next_sequence: u64,
    head_hash: String,
    run_heads: BTreeMap<String, RunHead>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    /// Empty state: the next entry is global genesis.
    ///
    /// ```
    /// # use agenomic_ledger_local::chain::ChainState;
    /// # use agenomic_ledger_local::canonical::GENESIS_ENTRY_HASH;
    /// let s = ChainState::new();
    /// let pos = s.allocate("run-1");
    /// assert_eq!(pos.sequence_number, 0);
    /// assert_eq!(pos.previous_entry_hash, GENESIS_ENTRY_HASH);
    /// ```
    pub fn new() -> Self {
        Self {
            next_sequence: 0,
            head_hash: GENESIS_ENTRY_HASH.to_string(),
            run_heads: BTreeMap::new(),
        }
    }

    /// Rebuild head state from an ordered slice of persisted entries,
    /// validating global contiguity and chain wiring on the way. Fails with
    /// [`CliError::LedgerIntegrity`] on the first inconsistency — an
    /// inconsistent store must not be silently extended.
    pub fn from_entries(entries: &[LedgerEntry]) -> CliResult<Self> {
        let mut state = Self::new();
        for entry in entries {
            let expected = state.allocate(&entry.run_id);
            if entry.sequence_number != expected.sequence_number
                || entry.previous_entry_hash != expected.previous_entry_hash
                || entry.run_sequence_number != expected.run_sequence_number
                || entry.previous_run_entry_hash != expected.previous_run_entry_hash
            {
                return Err(CliError::LedgerIntegrity {
                    reason: format!(
                        "chain break at sequence {}: stored positions do not extend the head \
                         (expected seq {}, prev {})",
                        entry.sequence_number,
                        expected.sequence_number,
                        expected.previous_entry_hash
                    ),
                });
            }
            state.advance(entry);
        }
        Ok(state)
    }

    /// Positions the next entry for `run_id` must take. Pure — does not
    /// mutate; call [`ChainState::advance`] with the sealed entry.
    pub fn allocate(&self, run_id: &str) -> ChainPositions {
        let (run_seq, run_prev) = match self.run_heads.get(run_id) {
            Some(head) => (head.next_run_sequence, head.head_hash.clone()),
            None => (0, GENESIS_ENTRY_HASH.to_string()),
        };
        ChainPositions {
            sequence_number: self.next_sequence,
            previous_entry_hash: self.head_hash.clone(),
            run_sequence_number: run_seq,
            previous_run_entry_hash: run_prev,
        }
    }

    /// Advance the heads past a sealed entry. The entry must occupy the
    /// positions [`ChainState::allocate`] returned for its run.
    pub fn advance(&mut self, entry: &LedgerEntry) {
        self.next_sequence = entry.sequence_number + 1;
        self.head_hash = entry.entry_hash.clone();
        self.run_heads.insert(
            entry.run_id.clone(),
            RunHead {
                next_run_sequence: entry.run_sequence_number + 1,
                head_hash: entry.entry_hash.clone(),
            },
        );
    }

    /// Number of entries in the global chain.
    pub fn len(&self) -> u64 {
        self.next_sequence
    }

    /// Whether the chain has no entries.
    pub fn is_empty(&self) -> bool {
        self.next_sequence == 0
    }

    /// Entry hash of the latest global entry (genesis constant when empty).
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }

    /// Head of `run_id`'s chain, if that run has entries.
    pub fn run_head(&self, run_id: &str) -> Option<&RunHead> {
        self.run_heads.get(run_id)
    }

    /// Run ids with at least one entry, in sorted order.
    pub fn run_ids(&self) -> impl Iterator<Item = &str> {
        self.run_heads.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{DurabilityStatus, IngestionSource, VerificationStatus};

    fn entry_at(run_id: &str, pos: &ChainPositions) -> LedgerEntry {
        let mut e = LedgerEntry {
            schema_version: crate::entry::LEDGER_SCHEMA_VERSION.to_string(),
            ledger_entry_id: format!("entry-{}", pos.sequence_number),
            event_id: format!("event-{}", pos.sequence_number),
            agent_id: "agent://acme/support".into(),
            run_id: run_id.into(),
            turn_id: None,
            session_id: None,
            genome_hash: None,
            release_id: None,
            event_type: "agent.started".into(),
            event_payload_hash: crate::canonical::payload_hash(&serde_json::json!({})),
            redacted_payload_preview: None,
            sequence_number: pos.sequence_number,
            run_sequence_number: pos.run_sequence_number,
            turn_sequence_number: None,
            timestamp: "2026-07-06T12:00:00.000000Z".into(),
            previous_entry_hash: pos.previous_entry_hash.clone(),
            previous_run_entry_hash: pos.previous_run_entry_hash.clone(),
            merkle_root: None,
            hash_algorithm: "blake3".into(),
            signature_algorithm: "ed25519".into(),
            ingestion_source: IngestionSource::Cli,
            entry_hash: String::new(),
            signature: "00".repeat(64),
            signing_key_id: "ed25519:0000000000000000".into(),
            durability_status: DurabilityStatus::LedgerAppended,
            verification_status: VerificationStatus::Unverified,
        };
        e.entry_hash = e.compute_entry_hash().unwrap();
        e
    }

    fn build_chain(runs: &[&str]) -> (ChainState, Vec<LedgerEntry>) {
        let mut state = ChainState::new();
        let mut entries = Vec::new();
        for run in runs {
            let pos = state.allocate(run);
            let e = entry_at(run, &pos);
            state.advance(&e);
            entries.push(e);
        }
        (state, entries)
    }

    #[test]
    fn global_and_run_chains_interleave() {
        let (state, entries) = build_chain(&["run-a", "run-b", "run-a", "run-b", "run-a"]);
        assert_eq!(state.len(), 5);
        // Global chain: each entry links the previous one.
        for pair in entries.windows(2) {
            assert_eq!(pair[1].previous_entry_hash, pair[0].entry_hash);
        }
        // Run chains: run-a entries link only run-a entries.
        let a: Vec<&LedgerEntry> = entries.iter().filter(|e| e.run_id == "run-a").collect();
        assert_eq!(a[0].previous_run_entry_hash, GENESIS_ENTRY_HASH);
        assert_eq!(a[1].previous_run_entry_hash, a[0].entry_hash);
        assert_eq!(a[2].previous_run_entry_hash, a[1].entry_hash);
        assert_eq!(a[2].run_sequence_number, 2);
        assert_eq!(state.run_head("run-a").unwrap().next_run_sequence, 3);
        assert_eq!(state.run_head("run-b").unwrap().next_run_sequence, 2);
    }

    #[test]
    fn from_entries_rebuilds_identical_state() {
        let (state, entries) = build_chain(&["run-a", "run-b", "run-a"]);
        let rebuilt = ChainState::from_entries(&entries).unwrap();
        assert_eq!(state, rebuilt);
    }

    #[test]
    fn from_entries_rejects_gap() {
        let (_, mut entries) = build_chain(&["run-a", "run-a", "run-a"]);
        entries.remove(1);
        let err = ChainState::from_entries(&entries).unwrap_err();
        assert!(matches!(err, CliError::LedgerIntegrity { .. }));
    }

    #[test]
    fn from_entries_rejects_rewired_prev_hash() {
        let (_, mut entries) = build_chain(&["run-a", "run-a", "run-a"]);
        entries[2].previous_entry_hash = GENESIS_ENTRY_HASH.to_string();
        let err = ChainState::from_entries(&entries).unwrap_err();
        assert!(matches!(err, CliError::LedgerIntegrity { .. }));
    }
}
