//! # agenomic-rmp — Review · Monitor · Protect
//!
//! The continuous safety loop for production AI agents:
//!
//! ```text
//! Review ──▶ Monitor ──▶ Protect ──▶ Review
//! ```
//!
//! * **Review** evaluates an agent before release, after changes, or after
//!   incidents: structured test scenarios, risk matrix, deterministic replay
//!   (via [`agenomic_replay_local`]), behavior-contract and policy validation,
//!   regression detection against evaluation history, and a release
//!   recommendation.
//! * **Monitor** observes live execution: it wraps the online tracking engine
//!   ([`agenomic_track`]) for drift / loop / intent / failure / policy
//!   detection, and appends every event to the cryptographic ledger
//!   ([`agenomic_ledger_local`]) through the durable low-latency WAL pipeline.
//! * **Protect** turns findings into action: anomaly detection, deduplicated
//!   and routed alerts, recommendations, action plans, and audit-ready
//!   evidence export.
//!
//! Every real production issue detected by Monitor or Protect can enrich
//! Review through a [`ScenarioEnrichmentProposal`] — a new replay/test
//! scenario, risk item, contract check, or policy suggestion. High-risk
//! proposals and recommendations always require human approval before they
//! are applied; this crate never mutates a bundle, contract, or policy.
//!
//! Everything here is deterministic and offline-capable by default. LLM-based
//! assistance (intent explanation, scenario drafting, audit narratives) is
//! strictly optional and behind the [`llm::SuggestionProvider`] trait; no
//! provider is wired in by default and deterministic evidence references are
//! always kept alongside any suggestion.

pub mod cards;
pub mod enrich;
pub mod evidence;
pub mod ledger;
pub mod llm;
pub mod monitor;
pub mod protect;
pub mod redact;
pub mod report;
pub mod review;
pub mod risk;
pub mod scenario;
pub mod store;
pub mod types;

pub use cards::{AgentIdCard, UseCaseCard};
pub use enrich::{
    proposals_from_findings, EnrichmentStatus, ScenarioEnrichmentProposal, ENRICHMENT_VERSION,
};
pub use evidence::{
    export_evidence, EvidenceExportOptions, EvidenceFile, EvidenceManifest,
    EVIDENCE_MANIFEST_VERSION,
};
pub use ledger::{event_types, record_rmp_event, RmpLedgerEvent};
pub use llm::{NoopSuggestionProvider, Suggestion, SuggestionKind, SuggestionProvider};
pub use monitor::{LedgerSink, MonitorConfig, MonitorEngine, MonitorOutcome};
pub use protect::{
    AlertRouter, ProtectConfig, ProtectEngine, ProtectOutcome, RouteRule, DEFAULT_THROTTLE_LIMIT,
};
pub use redact::{redact_json, redact_text, SecretScan, REDACTED};
pub use report::{build_rmp_report, render_markdown, RmpReport, RMP_REPORT_VERSION};
pub use review::{
    CoverageReport, ReleaseRecommendation, ReviewConfig, ReviewEngine, ReviewInputs, ReviewOutcome,
};
pub use risk::{
    AgentTypeAssessment, AssociatedRisk, ImpactDriver, RiskItem, RiskMatrix, RISK_MATRIX_VERSION,
};
pub use scenario::{
    parse_scenarios, validate_scenario, ScenarioSource, TestScenario, TestScenarioExpectedOutput,
    TestScenarioInput, SCENARIO_VERSION,
};
pub use store::RmpStore;
pub use types::{
    ActionPlan, ActionPlanStep, Alert, AlertRoute, AlertStatus, AnomalyFinding,
    EvaluationHistoryEntry, EvaluationResult, Finding, FindingKind, MonitorFinding, MonitorSession,
    PolicyViolationFinding, ProtectFinding, ProtectSession, Recommendation, RecommendationKind,
    ReviewFinding, ReviewSession, RmpEvidenceBundle, RmpFeedbackEvent, RmpMode, RmpSession,
    RmpSessionStatus, RMP_SPEC_VERSION,
};

/// Compute the `blake3:`-prefixed canonical hash of any serializable value,
/// matching the ledger's payload-hash convention.
pub fn value_hash<T: serde::Serialize>(value: &T) -> agenomic_core::CliResult<String> {
    let v = serde_json::to_value(value)
        .map_err(|e| agenomic_core::CliError::Internal(format!("serialize for hash: {e}")))?;
    Ok(agenomic_ledger_local::payload_hash(&v))
}
