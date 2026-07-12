//! Cryptographic ledger integration: every RMP lifecycle event is recorded
//! as a hash-committed, signed [`agenomic_ledger_local::LedgerEntry`].
//!
//! The payload itself is committed by hash (`PayloadCommitment::Inline`
//! resolves to a `blake3:` hash before anything touches disk); the ledger
//! adds run/global chain position and an Ed25519 signature. Nothing here
//! re-implements ledger logic — this module only names the RMP event
//! vocabulary and builds drafts.

use agenomic_core::CliResult;
use agenomic_ledger_local::{
    AppendOutcome, IngestionSource, LedgerEntryDraft, LedgerPipeline, PayloadCommitment,
};
use serde::{Deserialize, Serialize};

/// The RMP ledger event vocabulary. Keep in sync with
/// `docs/rmp/monitor.md` and the cloud `LEDGER_EVENT_TYPES` registry.
pub mod event_types {
    pub const RMP_SESSION_STARTED: &str = "rmp.session.started";
    pub const REVIEW_SESSION_STARTED: &str = "review.session.started";
    pub const REVIEW_TEST_SCENARIO_CREATED: &str = "review.test_scenario.created";
    pub const REVIEW_REPLAY_STARTED: &str = "review.replay.started";
    pub const REVIEW_REPLAY_COMPLETED: &str = "review.replay.completed";
    pub const REVIEW_RISK_MATRIX_UPDATED: &str = "review.risk_matrix.updated";
    pub const REVIEW_FINDING_CREATED: &str = "review.finding.created";
    pub const MONITOR_SESSION_STARTED: &str = "monitor.session.started";
    pub const MONITOR_FINDING_CREATED: &str = "monitor.finding.created";
    pub const MONITOR_DRIFT_DETECTED: &str = "monitor.drift.detected";
    pub const MONITOR_LOOP_DETECTED: &str = "monitor.loop.detected";
    pub const MONITOR_INTENT_SHIFTED: &str = "monitor.intent.shifted";
    pub const MONITOR_FAILURE_DETECTED: &str = "monitor.failure.detected";
    pub const PROTECT_ANOMALY_DETECTED: &str = "protect.anomaly.detected";
    pub const PROTECT_ALERT_CREATED: &str = "protect.alert.created";
    pub const PROTECT_NOTIFICATION_ROUTED: &str = "protect.notification.routed";
    pub const PROTECT_RECOMMENDATION_CREATED: &str = "protect.recommendation.created";
    pub const PROTECT_ACTION_PLAN_CREATED: &str = "protect.action_plan.created";
    pub const PROTECT_EVIDENCE_EXPORTED: &str = "protect.evidence.exported";
    pub const RMP_ENRICHMENT_PROPOSED: &str = "rmp.scenario_enrichment.proposed";
    pub const RMP_ENRICHMENT_APPROVED: &str = "rmp.scenario_enrichment.approved";
    pub const RMP_ENRICHMENT_APPLIED: &str = "rmp.scenario_enrichment.applied";
    pub const RMP_REPORT_GENERATED: &str = "rmp.report.generated";

    /// All RMP event types (for registries and validation).
    pub const ALL: &[&str] = &[
        RMP_SESSION_STARTED,
        REVIEW_SESSION_STARTED,
        REVIEW_TEST_SCENARIO_CREATED,
        REVIEW_REPLAY_STARTED,
        REVIEW_REPLAY_COMPLETED,
        REVIEW_RISK_MATRIX_UPDATED,
        REVIEW_FINDING_CREATED,
        MONITOR_SESSION_STARTED,
        MONITOR_FINDING_CREATED,
        MONITOR_DRIFT_DETECTED,
        MONITOR_LOOP_DETECTED,
        MONITOR_INTENT_SHIFTED,
        MONITOR_FAILURE_DETECTED,
        PROTECT_ANOMALY_DETECTED,
        PROTECT_ALERT_CREATED,
        PROTECT_NOTIFICATION_ROUTED,
        PROTECT_RECOMMENDATION_CREATED,
        PROTECT_ACTION_PLAN_CREATED,
        PROTECT_EVIDENCE_EXPORTED,
        RMP_ENRICHMENT_PROPOSED,
        RMP_ENRICHMENT_APPROVED,
        RMP_ENRICHMENT_APPLIED,
        RMP_REPORT_GENERATED,
    ];
}

/// A structured RMP event on its way into the ledger. The ledger commits
/// `payload` by hash; `evidence_refs` ride inside the payload so they are
/// covered by the payload hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmpLedgerEvent {
    /// One of [`event_types`].
    pub event_type: String,
    /// The RMP session id (recorded as the ledger `session_id`).
    pub session_id: String,
    /// Run id for chain placement; RMP lifecycle events use the RMP session
    /// id as their run when no producer run is available.
    pub run_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// Structured, already-redacted payload.
    pub payload: serde_json::Value,
    /// Deterministic references (finding ids, report hashes, event ids).
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl RmpLedgerEvent {
    /// Build an event; `run_id` defaults to the session id.
    pub fn new(
        event_type: &str,
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        let session_id = session_id.into();
        Self {
            event_type: event_type.to_string(),
            run_id: session_id.clone(),
            session_id,
            agent_id: agent_id.into(),
            genome_hash: None,
            release_id: None,
            payload,
            evidence_refs: Vec::new(),
        }
    }

    /// Convert to a ledger draft. The payload (including evidence refs) is
    /// committed by hash; a short redaction-safe preview is attached.
    pub fn to_draft(&self) -> LedgerEntryDraft {
        let mut payload = serde_json::json!({
            "event": self.payload,
            "evidence_refs": self.evidence_refs,
        });
        // Defense in depth: payloads should arrive redacted, but never let
        // an unredacted credential reach even the hash-committed body.
        crate::redact::redact_json(&mut payload);
        let mut draft = LedgerEntryDraft::new(
            self.agent_id.clone(),
            self.run_id.clone(),
            self.event_type.clone(),
            PayloadCommitment::Inline(payload),
            IngestionSource::Governance,
        );
        draft.session_id = Some(self.session_id.clone());
        draft.genome_hash = self.genome_hash.clone();
        draft.release_id = self.release_id.clone();
        draft
    }
}

/// Append one RMP event through the durable pipeline (WAL-backed by
/// default; see [`agenomic_ledger_local::LedgerMode`]). Returns the append
/// outcome — `WalPersisted` on the low-latency path.
pub fn record_rmp_event<S, K>(
    pipeline: &LedgerPipeline<S, K>,
    event: &RmpLedgerEvent,
) -> CliResult<AppendOutcome>
where
    S: agenomic_ledger_local::LedgerStore + Send + 'static,
    K: agenomic_ledger_local::SigningKeyStore + Send + 'static,
{
    pipeline.append(event.to_draft())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenomic_ledger_local::{FileKeyStore, LedgerConfig, MemoryLedgerStore};

    #[test]
    fn event_vocabulary_is_unique() {
        let mut set = std::collections::HashSet::new();
        for t in event_types::ALL {
            assert!(set.insert(*t), "duplicate event type {t}");
        }
    }

    #[test]
    fn draft_commits_payload_by_hash_and_redacts() {
        let mut ev = RmpLedgerEvent::new(
            event_types::PROTECT_ALERT_CREATED,
            "rmp_1",
            "agent://acme/claims",
            serde_json::json!({"api_key": "sk-should-never-leak", "title": "t"}),
        );
        ev.evidence_refs.push("fnd_1".into());
        let draft = ev.to_draft();
        assert_eq!(draft.session_id.as_deref(), Some("rmp_1"));
        match &draft.payload {
            PayloadCommitment::Inline(v) => {
                assert_eq!(v["event"]["api_key"], "[REDACTED]");
                assert_eq!(v["evidence_refs"][0], "fnd_1");
            }
            other => panic!("expected inline commitment, got {other:?}"),
        }
        assert!(draft.payload.resolve().unwrap().starts_with("blake3:"));
    }

    #[test]
    fn record_through_pipeline() {
        let tmp = tempfile::tempdir().unwrap();
        let keys_dir = tmp.path().join("keys");
        let mut keys = FileKeyStore::open(&keys_dir).unwrap();
        keys.generate().unwrap();
        let wal_dir = tmp.path().join("wal");
        let dl_dir = tmp.path().join("dead-letter");
        let (pipeline, _recovery) = LedgerPipeline::start(
            MemoryLedgerStore::new(),
            keys,
            Some(&wal_dir),
            Some(&dl_dir),
            None,
            LedgerConfig {
                mode: agenomic_ledger_local::LedgerMode::StrictVerified,
                ..LedgerConfig::default()
            },
        )
        .unwrap();
        let ev = RmpLedgerEvent::new(
            event_types::RMP_SESSION_STARTED,
            "rmp_1",
            "agent://acme/claims",
            serde_json::json!({"environment": "production"}),
        );
        let outcome = record_rmp_event(&pipeline, &ev).unwrap();
        assert!(matches!(outcome, AppendOutcome::Appended(_)));
        pipeline
            .shutdown(std::time::Duration::from_secs(5))
            .unwrap();
    }
}
