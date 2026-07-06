//! Pipeline configuration: latency modes and durability limits.
//!
//! Defaults follow the signed-off Phase 0 plan (§6): `durable_low_latency`
//! is the production default, strict modes fail closed and are never
//! silently downgraded, and every limit produces an *explicit* failure state
//! when hit — silent drops are forbidden.

use agenomic_core::{CliError, CliResult};
use serde::{Deserialize, Serialize};

/// Latency / durability mode of the ingestion pipeline (prompt §5.4).
///
/// The mode is fixed per pipeline (configured per environment), never per
/// call — mixing modes on one ledger would break per-run ordering
/// guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerMode {
    /// `append` returns after the in-memory enqueue. No WAL: a crash loses
    /// queued-but-unprocessed events (dev / non-critical only). A full
    /// queue is an explicit `LedgerBusy` error, never a silent drop.
    BestEffortLowLatency,
    /// **Default.** `append` returns after the local WAL append (fsync'd).
    /// Sealing/signing happens on the background worker; a crash recovers
    /// from the WAL with no loss and no duplicates.
    DurableLowLatency,
    /// `append` returns only after the entry is sealed, signed, and
    /// persisted to the ledger. Synchronous; for high-assurance flows.
    StrictVerified,
    /// `append` returns after cloud persistence. **Not yet available** —
    /// fails closed at pipeline construction (Q6, see
    /// `docs/BACKEND_GAPS.md`). Never downgraded silently.
    StrictCloud,
}

impl LedgerMode {
    /// Stable snake_case label (matches the serde encoding).
    ///
    /// ```
    /// # use agenomic_ledger_local::config::LedgerMode;
    /// assert_eq!(LedgerMode::DurableLowLatency.label(), "durable_low_latency");
    /// ```
    pub fn label(&self) -> &'static str {
        match self {
            Self::BestEffortLowLatency => "best_effort_low_latency",
            Self::DurableLowLatency => "durable_low_latency",
            Self::StrictVerified => "strict_verified",
            Self::StrictCloud => "strict_cloud",
        }
    }

    /// Whether this mode writes a WAL.
    pub fn uses_wal(&self) -> bool {
        matches!(self, Self::DurableLowLatency | Self::StrictVerified)
    }
}

/// Ingestion pipeline configuration (plan §6 subset relevant to Phase 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    /// Latency mode; default [`LedgerMode::DurableLowLatency`].
    pub mode: LedgerMode,
    /// Bounded in-memory queue capacity (events). Overflow spills to the
    /// WAL backlog in durable mode, or errors explicitly in best-effort.
    pub queue_max_memory_events: usize,
    /// Cap on total WAL bytes on disk. Reaching it is an explicit
    /// `LedgerBusy` failure state (the disk-full behavior of §5.7), never
    /// data loss.
    pub queue_max_disk_bytes: u64,
    /// Rotate WAL segments beyond this size.
    pub wal_segment_max_bytes: u64,
    /// Reject payloads whose canonical form exceeds this (oversized-event
    /// rule of §5.7); rejected events surface as explicit errors.
    pub max_payload_bytes: usize,
    /// Transient-failure retry attempts before dead-lettering.
    pub retry_max_attempts: u32,
    /// Base backoff between retries (doubles per attempt).
    pub retry_backoff_ms: u64,
    /// Keep permanently-failed events in the dead-letter store (default
    /// true). Disabling only changes *where* failures are recorded (status
    /// counters + error returns) — never whether.
    pub dead_letter_enabled: bool,
    /// Artificial per-event delay in the sealer worker, for backpressure /
    /// chaos testing of slow consumers. Always 0 in production.
    pub worker_delay_ms: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            mode: LedgerMode::DurableLowLatency,
            queue_max_memory_events: 1024,
            queue_max_disk_bytes: 256 * 1024 * 1024,
            wal_segment_max_bytes: 16 * 1024 * 1024,
            max_payload_bytes: 1024 * 1024,
            retry_max_attempts: 3,
            retry_backoff_ms: 25,
            dead_letter_enabled: true,
            worker_delay_ms: 0,
        }
    }
}

impl LedgerConfig {
    /// Fail closed on modes/limits that cannot be honored. Called at
    /// pipeline construction; a strict mode is never silently downgraded.
    ///
    /// ```
    /// # use agenomic_ledger_local::config::{LedgerConfig, LedgerMode};
    /// let mut config = LedgerConfig::default();
    /// assert!(config.validate().is_ok());
    /// config.mode = LedgerMode::StrictCloud;
    /// assert!(config.validate().is_err()); // NotYetAvailable, fail closed
    /// ```
    pub fn validate(&self) -> CliResult<()> {
        if self.mode == LedgerMode::StrictCloud {
            return Err(CliError::LedgerCloudUnavailable {
                reason: "no cloud ledger ingestion API exists yet".to_string(),
            });
        }
        if self.queue_max_memory_events == 0 {
            return Err(CliError::LedgerBusy {
                reason: "queue_max_memory_events must be at least 1".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_durable_low_latency() {
        assert_eq!(LedgerConfig::default().mode, LedgerMode::DurableLowLatency);
        assert!(LedgerConfig::default().dead_letter_enabled);
        assert!(LedgerConfig::default().validate().is_ok());
    }

    #[test]
    fn strict_cloud_fails_closed_with_stable_code() {
        let config = LedgerConfig {
            mode: LedgerMode::StrictCloud,
            ..LedgerConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            agenomic_core::CliError::LedgerCloudUnavailable { .. }
        ));
    }

    #[test]
    fn mode_labels_are_the_spec_names() {
        assert_eq!(
            LedgerMode::BestEffortLowLatency.label(),
            "best_effort_low_latency"
        );
        assert_eq!(LedgerMode::StrictVerified.label(), "strict_verified");
        assert_eq!(LedgerMode::StrictCloud.label(), "strict_cloud");
        assert!(LedgerMode::DurableLowLatency.uses_wal());
        assert!(!LedgerMode::BestEffortLowLatency.uses_wal());
    }
}
