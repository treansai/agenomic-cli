//! # agenomic-track
//!
//! The **online tracking** engine for Agenomic: real-time monitoring of
//! production agents that detects drift, loops, intent shifts, and runtime
//! harness / policy / behavior-contract violations as live events stream in.
//!
//! It is a deterministic, offline-capable library that reuses the existing
//! Agenomic building blocks rather than inventing parallel ones:
//!
//! * events are a JSON projection of the canonical trace / ATEP event model
//!   ([`event::TrackingEvent`]), with `prev_event_hash`/`event_hash`
//!   hash-linking and an optional detached signature;
//! * the runtime harness reuses [`agenomic_contract`] and [`agenomic_policy`];
//! * content hashing follows the BLAKE3 conventions of [`agenomic_hash`];
//! * the report ([`report::TrackingReport`]) mirrors the replay report.
//!
//! ## End-to-end example
//!
//! ```
//! use agenomic_track::{
//!     DriftBaseline, HarnessInputs, SessionStatus, TrackingEngine, TrackingEvent,
//!     TrackingEventType, TrackingSession, build_report,
//! };
//!
//! // 1. Start a session for a release, tracked against a genome baseline.
//! let mut session = TrackingSession::new("agent://acme/claims", "production");
//! session.tracking_config.loops.max_same_tool_calls = 2;
//! let mut baseline = DriftBaseline::default();
//! baseline.allowed_tools.insert("claims_db.lookup".into());
//!
//! let mut engine = TrackingEngine::new(session, baseline);
//!
//! // 2. Stream live events. An out-of-policy tool raises a critical drift alert.
//! let mut ev = TrackingEvent::new("", "agent://acme/claims", TrackingEventType::ToolCallCompleted, 0);
//! ev.tool = Some(agenomic_track::ToolMeta { name: "shell.exec".into(), ..Default::default() });
//! let alerts = engine.ingest(ev);
//! assert!(!alerts.is_empty());
//!
//! // 3. Finalize: run the harness, stop the session, export the JSON report.
//! let harness = engine.run_harness(&HarnessInputs::default());
//! engine.stop(SessionStatus::Completed);
//! let report = build_report(&engine.session, &engine.events, &harness);
//! assert_eq!(report.final_status, agenomic_track::FinalStatus::Fail);
//! ```

pub mod alert;
pub mod drift;
pub mod engine;
pub mod event;
pub mod harness;
pub mod intent;
pub mod loops;
pub mod report;
pub mod session;
pub mod store;

pub use alert::{Alert, AlertKind, AlertSeverity};
pub use drift::{
    BehavioralDrift, DriftBaseline, DriftConfig, DriftDetector, DriftType, SemanticDriftProvider,
};
pub use engine::TrackingEngine;
pub use event::{
    EventSignature, ModelMeta, PolicyResult, ToolMeta, TrackingEvent, TrackingEventType,
};
pub use harness::{HarnessCheck, HarnessInputs, HarnessResult, RuntimeHarness};
pub use intent::{
    DeterministicIntentClassifier, IntentClassification, IntentConfig, IntentIssue, IntentProvider,
    IntentTracker,
};
pub use loops::{EscalationBehavior, LoopConfig, LoopDetector, LoopType};
pub use report::{
    build_report, AlertCounts, AlertsByKind, FinalStatus, TrackingReport, REPORT_VERSION,
};
pub use session::{
    BaselineKind, BaselineRef, SessionStatus, SessionSummary, TrackingConfig, TrackingSession,
    SESSION_SPEC_VERSION,
};
pub use store::SessionStore;

use agenomic_core::{CliError, CliResult};

/// Parse a [`TrackingConfig`] from YAML or JSON text.
///
/// ```
/// let cfg = agenomic_track::parse_tracking_config(
///     "loops:\n  max_same_tool_calls: 2\nintent:\n  forbidden_intents: [exfiltrate]\n",
/// )
/// .unwrap();
/// assert_eq!(cfg.loops.max_same_tool_calls, 2);
/// assert_eq!(cfg.intent.forbidden_intents, vec!["exfiltrate".to_string()]);
/// ```
pub fn parse_tracking_config(text: &str) -> CliResult<TrackingConfig> {
    serde_yaml::from_str(text).map_err(|e| CliError::Schema(format!("tracking config: {e}")))
}

/// Build a [`DriftBaseline`] from a genome / lockfile document (YAML or JSON).
///
/// Used by the CLI to derive the expected behavioural envelope from a bundle's
/// `genome.yaml` or `agent.lock.yaml`. Tolerant: unknown shapes simply yield an
/// emptier baseline rather than an error.
pub fn baseline_from_genome_text(text: &str) -> CliResult<DriftBaseline> {
    let value: serde_json::Value =
        serde_yaml::from_str(text).map_err(|e| CliError::Schema(format!("genome: {e}")))?;
    Ok(DriftBaseline::from_genome_value(&value))
}
