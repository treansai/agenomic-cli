//! Pure mapping from governance outputs to ATEP `governance`-stream event
//! descriptors.
//!
//! This module is intentionally crypto- and IO-free: it only decides *what*
//! event each engine result should produce (`event_type` + JSON `payload`).
//! Sealing those descriptors into signed, hash-linked ATEP events and
//! appending them to a store is the embedder's job (the CLI does this via a
//! recorder). Keeping the mapping pure means the event shape is unit-testable
//! without keys or a filesystem, and stays deterministic.

use serde::Serialize;

use crate::types::{Cluster, Critique, Proposal, Verdict};
use crate::AuditReport;

/// Conventional `event_type` strings for the three engines plus the audit
/// summary. Stable identifiers — downstream consumers match on these.
pub const EVENT_CLUSTER_DETECTED: &str = "governance.cluster_detected";
pub const EVENT_PROPOSAL_GENERATED: &str = "governance.proposal_generated";
pub const EVENT_CRITIQUE_RECORDED: &str = "governance.critique_recorded";
pub const EVENT_AUDIT_COMPLETED: &str = "governance.audit_completed";

/// A single governance event ready to be sealed onto the ATEP `governance`
/// stream: its `event_type` and a JSON `payload`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GovernanceEventDescriptor {
    pub event_type: String,
    pub payload: serde_json::Value,
}

impl GovernanceEventDescriptor {
    fn new(event_type: &str, payload: serde_json::Value) -> Self {
        Self {
            event_type: event_type.to_string(),
            payload,
        }
    }

    /// `atep://schemas/v1/<event_type-with-slashes>` — mirrors the convention
    /// used by the `atep append` command.
    pub fn payload_schema_uri(&self) -> String {
        format!("atep://schemas/v1/{}", self.event_type.replace('.', "/"))
    }
}

/// One `governance.cluster_detected` event per cluster (Mode 1 output).
pub fn cluster_descriptor(cluster: &Cluster) -> GovernanceEventDescriptor {
    GovernanceEventDescriptor::new(
        EVENT_CLUSTER_DETECTED,
        serde_json::to_value(cluster).unwrap_or(serde_json::Value::Null),
    )
}

/// One `governance.proposal_generated` event per proposal (Mode 2 output).
pub fn proposal_descriptor(proposal: &Proposal) -> GovernanceEventDescriptor {
    GovernanceEventDescriptor::new(
        EVENT_PROPOSAL_GENERATED,
        serde_json::to_value(proposal).unwrap_or(serde_json::Value::Null),
    )
}

/// One `governance.critique_recorded` event per critique (Mode 3 output).
pub fn critique_descriptor(critique: &Critique) -> GovernanceEventDescriptor {
    GovernanceEventDescriptor::new(
        EVENT_CRITIQUE_RECORDED,
        serde_json::to_value(critique).unwrap_or(serde_json::Value::Null),
    )
}

/// The full descriptor list for an end-to-end audit, in the order the audit
/// trail should record them: every cluster, then every proposal, then every
/// critique, then a single `governance.audit_completed` summary. This order is
/// stable, so the resulting hash-chain is reproducible for a fixed report.
pub fn audit_descriptors(report: &AuditReport) -> Vec<GovernanceEventDescriptor> {
    let mut out = Vec::with_capacity(
        report.clusters.len() + report.proposals.len() + report.critiques.len() + 1,
    );
    out.extend(report.clusters.iter().map(cluster_descriptor));
    out.extend(report.proposals.iter().map(proposal_descriptor));
    out.extend(report.critiques.iter().map(critique_descriptor));
    out.push(audit_summary_descriptor(report));
    out
}

/// The `governance.audit_completed` summary event for a report.
pub fn audit_summary_descriptor(report: &AuditReport) -> GovernanceEventDescriptor {
    let blocking: Vec<&str> = report
        .critiques
        .iter()
        .filter(|c| matches!(c.verdict, Verdict::Block))
        .map(|c| c.proposal_id.as_str())
        .collect();
    let payload = serde_json::json!({
        "cluster_count": report.clusters.len(),
        "proposal_count": report.proposals.len(),
        "critique_count": report.critiques.len(),
        "blocked": report.has_blocking_findings(),
        "blocking_proposal_ids": blocking,
    });
    GovernanceEventDescriptor::new(EVENT_AUDIT_COMPLETED, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit, FailureSignal, FlaggedTrace};

    fn traces(n: usize, signal: FailureSignal, skill: &str) -> Vec<FlaggedTrace> {
        (0..n)
            .map(|i| FlaggedTrace {
                trace_id: format!("t{i}"),
                agent_id: "agent://x/y".into(),
                skill: skill.into(),
                skill_version: Some("@7".into()),
                signal: signal.clone(),
                input_snippet: "refund partial credit".into(),
                output_snippet: String::new(),
            })
            .collect()
    }

    #[test]
    fn audit_descriptors_cover_every_output_plus_summary() {
        let report = audit(&traces(4, FailureSignal::Escalation, "classify"));
        let descriptors = audit_descriptors(&report);
        // 1 cluster + 1 proposal + 1 critique + 1 summary.
        assert_eq!(descriptors.len(), 4);
        assert_eq!(descriptors[0].event_type, EVENT_CLUSTER_DETECTED);
        assert_eq!(descriptors[1].event_type, EVENT_PROPOSAL_GENERATED);
        assert_eq!(descriptors[2].event_type, EVENT_CRITIQUE_RECORDED);
        assert_eq!(descriptors[3].event_type, EVENT_AUDIT_COMPLETED);
    }

    #[test]
    fn summary_payload_reports_blocking_ids() {
        // A single-trace cluster trips the sample-size rule → Block.
        let report = audit(&traces(1, FailureSignal::Escalation, "classify"));
        let summary = audit_summary_descriptor(&report);
        assert_eq!(summary.payload["blocked"], serde_json::Value::Bool(true));
        let blocking = summary.payload["blocking_proposal_ids"].as_array().unwrap();
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0], report.proposals[0].id);
    }

    #[test]
    fn descriptors_are_deterministic() {
        let report = audit(&traces(5, FailureSignal::Escalation, "classify"));
        assert_eq!(audit_descriptors(&report), audit_descriptors(&report));
    }

    #[test]
    fn schema_uri_uses_slash_form() {
        let d = cluster_descriptor(&audit(&traces(3, FailureSignal::Escalation, "s")).clusters[0]);
        assert_eq!(
            d.payload_schema_uri(),
            "atep://schemas/v1/governance/cluster_detected"
        );
    }
}
