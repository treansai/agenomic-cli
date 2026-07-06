//! Producer-event conversions: existing event types → [`LedgerEntryDraft`].
//!
//! The ledger *extends* producers, it never re-encodes or renames them:
//! payloads already committed by a producer hash (tracking `event_hash`,
//! ATEP `causal_hash`) are referenced by that hash; everything else is
//! committed by the canonical hash of its existing JSON form. No new event
//! universe — `event_type` strings pass through verbatim.

use crate::entry::{IngestionSource, LedgerEntryDraft, PayloadCommitment};
use agenomic_core::{CliError, CliResult};
use agenomic_governance::events::GovernanceEventDescriptor;
use agenomic_track::TrackingEvent;

/// Convert a (sealed) tracking event into a ledger draft.
///
/// Mapping notes: a tracking session is the ledger's run scope
/// (`run_id = session_id`); the payload commitment reuses the tracking
/// chain's own `event_hash` when present (it covers the event minus its
/// signature), else the canonical hash of the full event JSON.
///
/// ```
/// # use agenomic_ledger_local::convert::from_tracking_event;
/// # use agenomic_track::TrackingEvent;
/// let raw = r#"{
///   "event_id": "evt-1", "session_id": "sess-1", "sequence_number": 0,
///   "timestamp": "2026-07-06T12:00:00Z", "type": "agent.started",
///   "agent_id": "agent://acme/support"
/// }"#;
/// let event: TrackingEvent = serde_json::from_str(raw).unwrap();
/// let draft = from_tracking_event(&event).unwrap();
/// assert_eq!(draft.run_id, "sess-1");
/// assert_eq!(draft.event_type, "agent.started");
/// assert_eq!(draft.event_id.as_deref(), Some("evt-1"));
/// ```
pub fn from_tracking_event(event: &TrackingEvent) -> CliResult<LedgerEntryDraft> {
    let event_type = serde_json::to_value(event.event_type)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .ok_or_else(|| CliError::Internal("serialize tracking event type".to_string()))?;
    let payload = match &event.event_hash {
        Some(h) if h.starts_with("blake3:") => PayloadCommitment::Hash(h.clone()),
        _ => PayloadCommitment::Inline(
            serde_json::to_value(event)
                .map_err(|e| CliError::Internal(format!("serialize tracking event: {e}")))?,
        ),
    };
    let mut draft = LedgerEntryDraft::new(
        event.agent_id.clone(),
        event.session_id.clone(),
        event_type,
        payload,
        IngestionSource::Tracking,
    );
    draft.event_id = Some(event.event_id.clone());
    draft.session_id = Some(event.session_id.clone());
    draft.genome_hash = event.genome_hash.clone();
    draft.timestamp = Some(event.timestamp);
    Ok(draft)
}

/// Convert a governance engine descriptor into a ledger draft.
///
/// Governance results are not run-scoped; they chain under the fixed
/// `governance` run. The descriptor's payload is committed by canonical
/// hash; the existing signed ATEP `governance` stream is untouched (the
/// ledger records *alongside*, never instead).
///
/// ```
/// # use agenomic_ledger_local::convert::from_governance_descriptor;
/// # use agenomic_governance::events::GovernanceEventDescriptor;
/// let d = GovernanceEventDescriptor {
///     event_type: "governance.cluster_detected".to_string(),
///     payload: serde_json::json!({ "cluster_id": "c-1" }),
/// };
/// let draft = from_governance_descriptor(&d).unwrap();
/// assert_eq!(draft.run_id, "governance");
/// ```
pub fn from_governance_descriptor(
    descriptor: &GovernanceEventDescriptor,
) -> CliResult<LedgerEntryDraft> {
    Ok(LedgerEntryDraft::new(
        "agenomic:governance",
        "governance",
        descriptor.event_type.clone(),
        PayloadCommitment::Inline(descriptor.payload.clone()),
        IngestionSource::Governance,
    ))
}

/// Convert an ATEP event reference into a ledger draft: the entry commits
/// the event's `causal_hash` (already BLAKE3 over the canonical CBOR body)
/// without ever re-encoding ATEP bytes.
///
/// ```no_run
/// # use agenomic_ledger_local::convert::from_atep_event;
/// # fn demo(event: &agenomic_atep::AtepEvent) {
/// let draft = from_atep_event(event, "run-1").unwrap();
/// assert_eq!(draft.event_type, event.header.event_type);
/// # }
/// ```
pub fn from_atep_event(
    event: &agenomic_atep::AtepEvent,
    run_id: &str,
) -> CliResult<LedgerEntryDraft> {
    let mut draft = LedgerEntryDraft::new(
        event.header.agent_id.clone(),
        run_id,
        event.header.event_type.clone(),
        PayloadCommitment::Hash(format!("blake3:{}", hex::encode(event.causal_hash.0))),
        IngestionSource::Atep,
    );
    draft.event_id = Some(ulid::Ulid::from_bytes(event.header.event_id).to_string());
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_event_with_chain_hash_commits_by_that_hash() {
        let raw = format!(
            r#"{{
              "event_id": "evt-1", "session_id": "sess-1", "sequence_number": 3,
              "timestamp": "2026-07-06T12:00:00Z", "type": "tool.call.completed",
              "agent_id": "agent://acme/support",
              "event_hash": "blake3:{}"
            }}"#,
            "ab".repeat(32)
        );
        let event: TrackingEvent = serde_json::from_str(&raw).unwrap();
        let draft = from_tracking_event(&event).unwrap();
        match &draft.payload {
            PayloadCommitment::Hash(h) => assert_eq!(h, &event.event_hash.clone().unwrap()),
            other => panic!("expected hash commitment, got {other:?}"),
        }
        assert_eq!(draft.event_type, "tool.call.completed");
        // Resolves cleanly through the pipeline's hot path.
        assert!(draft.payload.resolve().is_ok());
    }

    #[test]
    fn unsealed_tracking_event_commits_inline() {
        let raw = r#"{
          "event_id": "evt-2", "session_id": "sess-1", "sequence_number": 0,
          "timestamp": "2026-07-06T12:00:00Z", "type": "agent.started",
          "agent_id": "agent://acme/support"
        }"#;
        let event: TrackingEvent = serde_json::from_str(raw).unwrap();
        let draft = from_tracking_event(&event).unwrap();
        assert!(matches!(draft.payload, PayloadCommitment::Inline(_)));
        assert!(draft.payload.resolve().is_ok());
    }

    #[test]
    fn governance_descriptor_maps_to_the_governance_run() {
        let d = GovernanceEventDescriptor {
            event_type: "governance.proposal_generated".to_string(),
            payload: serde_json::json!({ "proposal_id": "p-1" }),
        };
        let draft = from_governance_descriptor(&d).unwrap();
        assert_eq!(draft.run_id, "governance");
        assert_eq!(draft.event_type, "governance.proposal_generated");
        assert!(matches!(
            draft.ingestion_source,
            IngestionSource::Governance
        ));
    }
}
