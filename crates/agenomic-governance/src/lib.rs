//! Three deterministic governance agents (BACKEND_GAPS Gap 5 / Point 4).
//!
//! - [`DiagnosticAgent`] clusters negatively-flagged traces (Mode 1).
//! - [`HypothesisAgent`] turns a cluster into a textual remediation proposal
//!   (Mode 2). It **never mutates** a bundle.
//! - [`AdversarialReviewer`] critiques a proposal from the opposite side and
//!   produces a typed verdict (Mode 3): `Pass` / `Warn` / `Block`.
//!
//! Modes 4 (human-approval gate) and 5 (shadow / canary deployment) are
//! workflow concerns layered above; this crate stops at producing the
//! reviewable artifacts they consume. None of these engines call an LLM —
//! they are pure functions over typed input, so the same flagged corpus
//! produces byte-identical clusters → proposals → critiques on every run,
//! which is what an attestation downstream needs.
//!
//! ```
//! use agenomic_governance::{
//!     AdversarialReviewer, DiagnosticAgent, FailureSignal, FlaggedTrace, HypothesisAgent,
//! };
//! let traces = vec![FlaggedTrace {
//!     trace_id: "t1".into(),
//!     agent_id: "agent://x/y".into(),
//!     skill: "classify".into(),
//!     skill_version: Some("@7".into()),
//!     signal: FailureSignal::Escalation,
//!     input_snippet: "refund partial credit".into(),
//!     output_snippet: String::new(),
//! }; 3];
//! let clusters = DiagnosticAgent::new().cluster(&traces);
//! let proposals = HypothesisAgent::new().hypothesize_many(&clusters);
//! let critiques = AdversarialReviewer::new().critique_many(&proposals);
//! assert_eq!(critiques.len(), 1);
//! ```

mod adversarial;
mod diagnostic;
mod error;
mod hypothesis;
pub mod io;
mod types;

pub use adversarial::AdversarialReviewer;
pub use diagnostic::DiagnosticAgent;
pub use error::{GovernanceError, GovernanceResult};
pub use hypothesis::HypothesisAgent;
pub use types::{
    Cluster, Critique, FailureSignal, Finding, FlaggedTrace, Proposal, ProposalAction, Severity,
    Verdict,
};

/// Output of an end-to-end `audit`: clusters + their proposals + per-proposal
/// critiques. Useful for one-shot pipelines (CLI `governance audit`) and for
/// tests that need to assert on the whole chain at once.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditReport {
    pub clusters: Vec<Cluster>,
    pub proposals: Vec<Proposal>,
    pub critiques: Vec<Critique>,
}

impl AuditReport {
    /// `true` when at least one critique returned `Verdict::Block`.
    pub fn has_blocking_findings(&self) -> bool {
        self.critiques
            .iter()
            .any(|c| matches!(c.verdict, Verdict::Block))
    }
}

/// Run the full Diagnostic → Hypothesis → Adversarial chain. Deterministic
/// for a fixed `traces` input.
pub fn audit(traces: &[FlaggedTrace]) -> AuditReport {
    let clusters = DiagnosticAgent::new().cluster(traces);
    let proposals = HypothesisAgent::new().hypothesize_many(&clusters);
    let critiques = AdversarialReviewer::new().critique_many(&proposals);
    AuditReport {
        clusters,
        proposals,
        critiques,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_chain_is_deterministic() {
        let make = || FlaggedTrace {
            trace_id: "t1".into(),
            agent_id: "agent://x/y".into(),
            skill: "classify".into(),
            skill_version: None,
            signal: FailureSignal::Escalation,
            input_snippet: "refund partial".into(),
            output_snippet: String::new(),
        };
        let traces: Vec<_> = (0..5)
            .map(|i| FlaggedTrace {
                trace_id: format!("t{i}"),
                ..make()
            })
            .collect();
        let a = audit(&traces);
        let b = audit(&traces);
        assert_eq!(
            serde_json::to_string(&a.proposals).unwrap(),
            serde_json::to_string(&b.proposals).unwrap()
        );
        // 5 escalations on one skill → 1 cluster, 1 proposal, 1 critique.
        assert_eq!(a.clusters.len(), 1);
        assert_eq!(a.proposals.len(), 1);
        assert_eq!(a.critiques.len(), 1);
    }

    #[test]
    fn audit_flags_blocking_findings() {
        let traces = vec![FlaggedTrace {
            trace_id: "lonely".into(),
            agent_id: "agent://x/y".into(),
            skill: "classify".into(),
            skill_version: None,
            signal: FailureSignal::Escalation,
            input_snippet: "refund".into(),
            output_snippet: String::new(),
        }];
        // One-trace cluster → sample-size rule fires → Block.
        assert!(audit(&traces).has_blocking_findings());
    }
}
