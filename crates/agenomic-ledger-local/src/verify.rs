//! The verification engine: the full §5.9 check matrix over entries,
//! blocks, keys, and the WAL, producing one structured, serializable
//! report.
//!
//! Checks covered: event payload hash format, canonical entry hash,
//! previous-entry wiring, per-run chains, block Merkle roots, block
//! entries-hash, block hashes and signatures, entry signatures, key
//! validity/rotation/revocation status, sequence gaps, duplicated events,
//! tampering conflicts, missing events, and corrupted WAL segments.
//! (Per-turn chains are deferred per Q5.)
//!
//! The engine is pure over its inputs and needs no network — it runs
//! identically against a live ledger or an exported chain on a clean
//! machine.

use crate::block::LedgerBlock;
use crate::entry::LedgerEntry;
use crate::keystore::{KeyStatus, SigningKeyStore};
use crate::ledger::verify_entries;
use crate::wal::WalHealth;
use agenomic_core::CliResult;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Report format version.
pub const VERIFY_REPORT_VERSION: &str = "agenomic.ledger.verify/v0.1";

/// Block-level findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockVerification {
    pub block_count: u64,
    /// `previous_block_hash` wiring across the block chain is intact.
    pub chain_valid: bool,
    /// First block whose wiring broke, if any.
    pub broken_at_block: Option<String>,
    /// Blocks whose recomputed Merkle root mismatches (block ids).
    pub merkle_mismatches: Vec<String>,
    /// Blocks whose flat entries-hash mismatches.
    pub entries_hash_mismatches: Vec<String>,
    /// Blocks whose own hash fails recomputation.
    pub hash_failures: Vec<String>,
    /// Blocks whose Ed25519 signature fails (or key unresolvable).
    pub signature_failures: Vec<String>,
    /// Blocks covering sequences absent from the provided entry set.
    pub unverifiable_ranges: Vec<String>,
    /// Uncovered ranges between consecutive blocks `(from, to)` inclusive.
    pub coverage_gaps: Vec<(u64, u64)>,
    /// Blocks whose range overlaps its predecessor.
    pub range_overlaps: Vec<String>,
    /// Entries after the last sealed block `(from, to)` — informational,
    /// not a failure (they are WAL-durable and individually signed).
    pub unsealed_tail: Option<(u64, u64)>,
    /// All block checks passed.
    pub valid: bool,
}

/// Per-run head summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub entry_count: u64,
    pub head_hash: String,
}

/// Compact chain overview for humans and downstream proofs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainSummary {
    pub head_hash: String,
    pub run_count: u64,
    pub runs: BTreeMap<String, RunSummary>,
}

/// The full §5.9 verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub report_version: String,
    /// The single verdict: every evaluated check passed and nothing was
    /// missing. Warnings (revoked keys, unsealed tail) do not clear this
    /// on their own but are always surfaced.
    pub passed: bool,
    pub entry_count: u64,
    /// Lowest sequence number with any failure, if any.
    pub first_invalid_sequence: Option<u64>,
    /// Whether the global/run chain wiring could be evaluated (false when
    /// gaps or duplicate sequences make wiring meaningless).
    pub chain_evaluated: bool,
    /// Entry-level results (chain wiring, hashes, signatures, key status).
    pub entries: crate::ledger::LedgerVerification,
    /// Missing sequence ranges `(from, to)` inclusive (§5.3: gaps surface
    /// in verification output; history is never rewritten).
    pub sequence_gaps: Vec<(u64, u64)>,
    /// Sequence numbers appearing more than once.
    pub duplicate_sequences: Vec<u64>,
    /// Event ids appearing on multiple entries with the same payload hash.
    pub duplicate_event_ids: Vec<String>,
    /// Event ids appearing with divergent payload hashes — tampering
    /// warnings.
    pub conflicting_event_ids: Vec<String>,
    /// Entries whose payload hash is not a well-formed `blake3:` commitment.
    pub payload_hash_format_failures: Vec<u64>,
    pub blocks: BlockVerification,
    /// Read-only WAL health (when a WAL directory was provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wal: Option<WalHealth>,
    pub chain_summary: ChainSummary,
    /// Human-actionable next steps derived from the findings.
    pub recommendations: Vec<String>,
}

fn payload_hash_is_well_formed(h: &str) -> bool {
    h.strip_prefix("blake3:")
        .map(|hex_part| hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

/// Run the full check matrix. `entries` may be a complete ledger or an
/// exported subset — gaps and duplicates are findings, not preconditions.
/// Blocks are verified against whatever entries are present; a block whose
/// range is not fully present is reported unverifiable rather than guessed
/// at.
pub fn verify_ledger(
    entries: &[LedgerEntry],
    blocks: &[LedgerBlock],
    keys: &dyn SigningKeyStore,
    wal_dir: Option<&Path>,
) -> CliResult<VerificationReport> {
    // ---- Order, gaps, duplicates -------------------------------------
    let mut sorted: Vec<&LedgerEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.sequence_number);

    let mut duplicate_sequences = Vec::new();
    let mut sequence_gaps = Vec::new();
    for pair in sorted.windows(2) {
        let (a, b) = (pair[0].sequence_number, pair[1].sequence_number);
        if a == b {
            if duplicate_sequences.last() != Some(&a) {
                duplicate_sequences.push(a);
            }
        } else if b > a + 1 {
            sequence_gaps.push((a + 1, b - 1));
        }
    }
    if let Some(first) = sorted.first() {
        if first.sequence_number > 0 {
            sequence_gaps.insert(0, (0, first.sequence_number - 1));
        }
    }

    let mut by_event_id: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut event_id_counts: BTreeMap<&str, u64> = BTreeMap::new();
    for entry in &sorted {
        by_event_id
            .entry(&entry.event_id)
            .or_default()
            .insert(&entry.event_payload_hash);
        *event_id_counts.entry(&entry.event_id).or_default() += 1;
    }
    let conflicting_event_ids: Vec<String> = by_event_id
        .iter()
        .filter(|(_, hashes)| hashes.len() > 1)
        .map(|(id, _)| id.to_string())
        .collect();
    let duplicate_event_ids: Vec<String> = event_id_counts
        .iter()
        .filter(|(id, count)| **count > 1 && !conflicting_event_ids.contains(&id.to_string()))
        .map(|(id, _)| id.to_string())
        .collect();

    let payload_hash_format_failures: Vec<u64> = sorted
        .iter()
        .filter(|e| !payload_hash_is_well_formed(&e.event_payload_hash))
        .map(|e| e.sequence_number)
        .collect();

    // ---- Entry-level checks ------------------------------------------
    // Wiring is only meaningful over a complete, duplicate-free sequence.
    let chain_evaluated = sequence_gaps.is_empty() && duplicate_sequences.is_empty();
    let ordered: Vec<LedgerEntry> = sorted.iter().map(|e| (*e).clone()).collect();
    let mut entry_results = verify_entries(&ordered, keys)?;
    if !chain_evaluated {
        // Wiring verdicts are unreliable across gaps; report the structural
        // findings (gaps/duplicates) instead of a misleading break point.
        entry_results.chain_valid = false;
        entry_results.broken_at_sequence = None;
    }

    // ---- Block checks --------------------------------------------------
    let by_seq: BTreeMap<u64, &LedgerEntry> =
        sorted.iter().map(|e| (e.sequence_number, *e)).collect();
    let mut bv = BlockVerification {
        block_count: blocks.len() as u64,
        chain_valid: true,
        ..BlockVerification::default()
    };
    let mut prev_hash = crate::block::GENESIS_BLOCK_HASH.to_string();
    let mut prev_end: Option<u64> = None;
    for block in blocks {
        if block.previous_block_hash != prev_hash && bv.chain_valid {
            bv.chain_valid = false;
            bv.broken_at_block = Some(block.block_id.clone());
        }
        prev_hash = block.block_hash.clone();

        if let Some(end) = prev_end {
            if block.start_sequence_number > end + 1 {
                bv.coverage_gaps
                    .push((end + 1, block.start_sequence_number - 1));
            } else if block.start_sequence_number <= end {
                bv.range_overlaps.push(block.block_id.clone());
            }
        } else if block.start_sequence_number > 0 {
            bv.coverage_gaps.push((0, block.start_sequence_number - 1));
        }
        prev_end = Some(block.end_sequence_number.max(prev_end.unwrap_or(0)));

        if !block.hash_is_valid()? {
            bv.hash_failures.push(block.block_id.clone());
        }
        match keys.verifying_key(&block.signing_key_id) {
            Ok(vk) => {
                if block.verify_signature(&vk).is_err() {
                    bv.signature_failures.push(block.block_id.clone());
                }
            }
            Err(_) => bv.signature_failures.push(block.block_id.clone()),
        }

        // Content commitments need every covered entry present.
        let range = block.start_sequence_number..=block.end_sequence_number;
        let covered: Vec<String> = range
            .clone()
            .filter_map(|seq| by_seq.get(&seq).map(|e| e.entry_hash.clone()))
            .collect();
        if covered.len() as u64 != block.entry_count
            || block.end_sequence_number < block.start_sequence_number
        {
            bv.unverifiable_ranges.push(block.block_id.clone());
            continue;
        }
        if crate::block::entries_hash(&covered) != block.entries_hash {
            bv.entries_hash_mismatches.push(block.block_id.clone());
        }
        if crate::canonical::merkle_root(&covered)? != block.merkle_root {
            bv.merkle_mismatches.push(block.block_id.clone());
        }
    }
    if let (Some(end), Some(last)) = (prev_end, sorted.last()) {
        if last.sequence_number > end {
            bv.unsealed_tail = Some((end + 1, last.sequence_number));
        }
    } else if let Some(last) = sorted.last() {
        bv.unsealed_tail = Some((0, last.sequence_number));
    }
    bv.valid = bv.chain_valid
        && bv.merkle_mismatches.is_empty()
        && bv.entries_hash_mismatches.is_empty()
        && bv.hash_failures.is_empty()
        && bv.signature_failures.is_empty()
        && bv.unverifiable_ranges.is_empty()
        && bv.coverage_gaps.is_empty()
        && bv.range_overlaps.is_empty();

    // ---- WAL health ------------------------------------------------------
    let wal = match wal_dir {
        Some(dir) => Some(crate::wal::scan_health(dir)?),
        None => None,
    };
    let wal_damaged = wal
        .as_ref()
        .map(|w| !w.damaged_segments.is_empty())
        .unwrap_or(false);

    // ---- Summary + verdict ------------------------------------------------
    let mut runs: BTreeMap<String, RunSummary> = BTreeMap::new();
    for entry in &sorted {
        let summary = runs.entry(entry.run_id.clone()).or_insert(RunSummary {
            entry_count: 0,
            head_hash: String::new(),
        });
        summary.entry_count += 1;
        summary.head_hash = entry.entry_hash.clone();
    }
    let chain_summary = ChainSummary {
        head_hash: entry_results.head_hash.clone(),
        run_count: runs.len() as u64,
        runs,
    };

    let first_invalid_sequence = [
        entry_results.broken_at_sequence,
        entry_results.hash_failures.first().copied(),
        entry_results.signature_failures.first().copied(),
        entry_results.unresolved_key_failures.first().copied(),
        payload_hash_format_failures.first().copied(),
    ]
    .into_iter()
    .flatten()
    .min();

    let passed = entry_results.valid
        && chain_evaluated
        && duplicate_sequences.is_empty()
        && conflicting_event_ids.is_empty()
        && payload_hash_format_failures.is_empty()
        && bv.valid
        && !wal_damaged;

    let mut recommendations = Vec::new();
    if !entry_results.hash_failures.is_empty() || !bv.merkle_mismatches.is_empty() {
        recommendations.push(
            "tampering detected: entry content no longer matches its sealed hash — restore \
             from a trusted export and investigate write access to the ledger files"
                .to_string(),
        );
    }
    if !entry_results.signature_failures.is_empty() || !bv.signature_failures.is_empty() {
        recommendations.push(
            "signature failures present: confirm the key manifest is the one that signed this \
             ledger (agenomic ledger keys list)"
                .to_string(),
        );
    }
    if !sequence_gaps.is_empty() {
        recommendations.push(
            "missing events: request the absent sequence ranges from the producer — the \
             ledger never rewrites history to close gaps"
                .to_string(),
        );
    }
    if !conflicting_event_ids.is_empty() {
        recommendations.push(
            "conflicting event ids carry divergent payload hashes — treat as a tampering \
             warning and audit the producer"
                .to_string(),
        );
    }
    if !entry_results.revoked_key_warnings.is_empty() {
        recommendations.push(
            "entries signed by a revoked key verify cryptographically but need review of the \
             revocation window"
                .to_string(),
        );
    }
    if wal_damaged {
        recommendations.push(
            "damaged WAL segments found: reopen the ledger to quarantine and recover, then \
             inspect the .corrupt files"
                .to_string(),
        );
    }
    if bv.unsealed_tail.is_some() {
        recommendations
            .push("unsealed entries pending: run `agenomic ledger seal` to block them".to_string());
    }

    Ok(VerificationReport {
        report_version: VERIFY_REPORT_VERSION.to_string(),
        passed,
        entry_count: sorted.len() as u64,
        first_invalid_sequence,
        chain_evaluated,
        entries: entry_results,
        sequence_gaps,
        duplicate_sequences,
        duplicate_event_ids,
        conflicting_event_ids,
        payload_hash_format_failures,
        blocks: bv,
        wal,
        chain_summary,
        recommendations,
    })
}

/// Key rotation/revocation posture of a set of entries: how many entries
/// each signing key covers and its current status. Informational — feeds
/// reports and the CLI `keys list` view.
pub fn key_usage(
    entries: &[LedgerEntry],
    keys: &dyn SigningKeyStore,
) -> Vec<(String, KeyStatus, u64)> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for entry in entries {
        *counts.entry(entry.signing_key_id.clone()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(key_id, count)| {
            let status = keys.key_status(&key_id).unwrap_or(KeyStatus::Revoked);
            (key_id, status, count)
        })
        .collect()
}
