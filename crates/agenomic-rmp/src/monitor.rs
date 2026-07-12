//! The Monitor engine: continuous observation of live agent execution.
//!
//! Monitor composes the existing building blocks instead of re-implementing
//! them:
//!
//! * detection (drift / loops / intent / failures / harness) is
//!   [`agenomic_track::TrackingEngine`];
//! * durability is the ledger's WAL pipeline
//!   ([`agenomic_ledger_local::LedgerPipeline`]) — the hot path returns
//!   after the WAL append, sealing/signing happens on the background
//!   worker, and crash recovery / dead-lettering come for free.
//!
//! `ingest` is the latency-critical call: one ledger append (mode-dependent
//! cost, `durable_low_latency` = one fsync'd WAL write) plus in-memory
//! detector updates. Heavy work (harness evaluation, report building,
//! enrichment proposals) happens at [`MonitorEngine::stop`].

use chrono::Utc;
use serde::{Deserialize, Serialize};

use agenomic_core::{CliResult, Severity};
use agenomic_ledger_local::{AppendOutcome, LedgerEntryDraft};
use agenomic_track::{
    build_report, Alert, AlertKind, DriftBaseline, HarnessInputs, SessionStatus, TrackingEngine,
    TrackingEvent, TrackingReport, TrackingSession,
};

use crate::enrich::{proposals_from_findings, ScenarioEnrichmentProposal};
use crate::ledger::{event_types, RmpLedgerEvent};
use crate::types::{
    EvaluationHistoryEntry, EvaluationResult, Finding, FindingKind, MonitorSession, RmpMode,
    RmpSessionStatus, RMP_SPEC_VERSION,
};

/// Ledger sink abstraction so the engine can run with any pipeline (file
/// or memory store) or without a ledger at all.
pub trait LedgerSink: Send {
    /// Append a draft through the durable pipeline.
    fn append(&self, draft: LedgerEntryDraft) -> CliResult<AppendOutcome>;
}

impl<S, K> LedgerSink for agenomic_ledger_local::LedgerPipeline<S, K>
where
    S: agenomic_ledger_local::LedgerStore + Send + 'static,
    K: agenomic_ledger_local::SigningKeyStore + Send + 'static,
{
    fn append(&self, draft: LedgerEntryDraft) -> CliResult<AppendOutcome> {
        agenomic_ledger_local::LedgerPipeline::append(self, draft)
    }
}

/// Monitor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub mode: RmpMode,
    /// Alerts at or above this platform severity trigger Protect.
    pub protect_trigger_severity: Severity,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            mode: RmpMode::DurableLowLatency,
            protect_trigger_severity: Severity::High,
        }
    }
}

/// Result of finalizing a monitor session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorOutcome {
    pub spec_version: String,
    pub session: MonitorSession,
    pub report: TrackingReport,
    pub findings: Vec<Finding>,
    /// Proposals feeding back into Review.
    pub scenario_proposals: Vec<ScenarioEnrichmentProposal>,
    /// True when at least one finding crossed the Protect trigger severity.
    pub protect_triggered: bool,
    pub history_entry: EvaluationHistoryEntry,
}

/// The Monitor engine for one live session.
pub struct MonitorEngine {
    session: MonitorSession,
    tracking: TrackingEngine,
    ledger: Option<Box<dyn LedgerSink>>,
    config: MonitorConfig,
    findings: Vec<Finding>,
}

impl MonitorEngine {
    /// Start a monitor session. `baseline` seeds drift detection (usually
    /// derived from the release genome via
    /// [`agenomic_track::baseline_from_genome_text`]).
    pub fn start(
        agent_id: impl Into<String>,
        environment: impl Into<String>,
        baseline: DriftBaseline,
        config: MonitorConfig,
        ledger: Option<Box<dyn LedgerSink>>,
    ) -> CliResult<Self> {
        let agent_id = agent_id.into();
        let environment = environment.into();
        let tracking_session = TrackingSession::new(agent_id.clone(), environment.clone());
        let session = MonitorSession {
            spec_version: RMP_SPEC_VERSION.into(),
            session_id: format!("mon_{}", ulid::Ulid::new()),
            rmp_session_id: None,
            tracking_session_id: tracking_session.session_id.clone(),
            agent_id: agent_id.clone(),
            genome_hash: None,
            release_id: None,
            environment,
            mode: config.mode,
            ledger_enabled: ledger.is_some(),
            status: RmpSessionStatus::Active,
            started_at: Utc::now(),
            ended_at: None,
        };
        let engine = Self {
            tracking: TrackingEngine::new(tracking_session, baseline),
            session,
            ledger,
            config,
            findings: Vec::new(),
        };
        engine.record_lifecycle_event(
            event_types::MONITOR_SESSION_STARTED,
            serde_json::json!({
                "environment": engine.session.environment,
                "mode": engine.session.mode.label(),
            }),
        )?;
        Ok(engine)
    }

    /// Resume a monitor session from persisted tracking state (session +
    /// events + baseline). Findings are re-derived from the tracking
    /// session's recorded alerts, so resume is deterministic. Pass
    /// `ledger: None` on read-only paths (status/report) to avoid
    /// re-recording lifecycle events.
    pub fn resume(
        session: MonitorSession,
        tracking_session: TrackingSession,
        events: Vec<TrackingEvent>,
        baseline: DriftBaseline,
        config: MonitorConfig,
        ledger: Option<Box<dyn LedgerSink>>,
    ) -> Self {
        let mut engine = Self {
            tracking: TrackingEngine::resume(tracking_session, events, baseline),
            session,
            ledger,
            config,
            findings: Vec::new(),
        };
        let alerts: Vec<Alert> = engine.tracking.session.alerts.clone();
        let findings: Vec<Finding> = alerts
            .iter()
            .map(|a| engine.finding_from_alert(a))
            .collect();
        engine.findings = findings;
        engine
    }

    /// Attach genome/release identity after construction.
    pub fn bind_release(
        &mut self,
        genome_hash: Option<String>,
        release_id: Option<String>,
        rmp_session_id: Option<String>,
    ) {
        self.session.genome_hash = genome_hash;
        self.session.release_id = release_id;
        self.session.rmp_session_id = rmp_session_id;
    }

    /// The monitor session descriptor.
    pub fn session(&self) -> &MonitorSession {
        &self.session
    }

    /// Findings emitted so far.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Ingest one live event — the latency-critical path.
    ///
    /// The event is (1) appended to the ledger through the WAL pipeline
    /// (non-blocking beyond the WAL write in the default mode), then
    /// (2) run through the in-memory detectors. Returns the findings this
    /// event raised. Idempotent: an already-seen `event_id` is a no-op.
    pub fn ingest(&mut self, event: TrackingEvent) -> CliResult<Vec<Finding>> {
        if self.tracking.has_event(&event.event_id) {
            return Ok(Vec::new());
        }
        // 1. Durability first: commit the raw event by hash to the ledger.
        if let Some(ledger) = &self.ledger {
            let draft = agenomic_ledger_local::convert::from_tracking_event(&event)?;
            ledger.append(draft)?;
        }
        // 2. In-memory detection.
        let alerts = self.tracking.ingest(event);
        let mut new_findings = Vec::with_capacity(alerts.len());
        for alert in &alerts {
            let finding = self.finding_from_alert(alert);
            self.record_finding_event(&finding)?;
            new_findings.push(finding);
        }
        self.findings.extend(new_findings.clone());
        Ok(new_findings)
    }

    /// Ingest a batch of events, returning all findings raised.
    pub fn ingest_all(
        &mut self,
        events: impl IntoIterator<Item = TrackingEvent>,
    ) -> CliResult<Vec<Finding>> {
        let mut all = Vec::new();
        for event in events {
            all.extend(self.ingest(event)?);
        }
        Ok(all)
    }

    /// Whether Protect should be triggered given the findings so far.
    pub fn protect_triggered(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= self.config.protect_trigger_severity)
    }

    /// Finalize the session: run the harness (behavior contract + policy),
    /// build the tracking report, derive enrichment proposals, and record
    /// the evaluation history entry.
    pub fn stop(
        mut self,
        harness_inputs: &HarnessInputs,
        status: SessionStatus,
    ) -> CliResult<MonitorOutcome> {
        let harness = self.tracking.run_harness(harness_inputs);
        for alert in &harness.alerts {
            let finding = self.finding_from_alert(alert);
            self.record_finding_event(&finding)?;
            self.findings.push(finding);
        }
        self.tracking.stop(status);
        let report = build_report(&self.tracking.session, &self.tracking.events, &harness);

        self.session.status = match status {
            SessionStatus::Completed => RmpSessionStatus::Completed,
            SessionStatus::Cancelled => RmpSessionStatus::Cancelled,
            _ => RmpSessionStatus::Failed,
        };
        self.session.ended_at = Some(Utc::now());

        let scenario_proposals = proposals_from_findings(&self.findings);
        for proposal in &scenario_proposals {
            self.record_lifecycle_event(
                event_types::RMP_ENRICHMENT_PROPOSED,
                serde_json::json!({
                    "proposal_id": proposal.proposal_id,
                    "source_finding_id": proposal.source_finding_id,
                    "severity": proposal.severity,
                }),
            )?;
        }

        let protect_triggered = self.protect_triggered();
        let (result, score) = self.evaluate(&report);
        let mut history_entry = EvaluationHistoryEntry::new(
            &self.session.agent_id,
            "monitor",
            &self.session.session_id,
            result,
            score,
        );
        history_entry.genome_hash = self.session.genome_hash.clone();
        history_entry.release_id = self.session.release_id.clone();
        history_entry.metrics = serde_json::json!({
            "event_count": report.event_count,
            "critical_alerts": report.alert_counts.critical,
            "warning_alerts": report.alert_counts.warning,
        });
        if let Some(hash) = &report.report_hash {
            history_entry.evidence_refs.push(format!("track-report:{hash}"));
        }

        Ok(MonitorOutcome {
            spec_version: RMP_SPEC_VERSION.into(),
            session: self.session,
            report,
            findings: self.findings,
            scenario_proposals,
            protect_triggered,
            history_entry,
        })
    }

    fn evaluate(&self, report: &TrackingReport) -> (EvaluationResult, f64) {
        let critical = report.alert_counts.critical;
        let warning = report.alert_counts.warning;
        let result = if critical > 0 {
            EvaluationResult::Fail
        } else if warning > 0 {
            EvaluationResult::Warn
        } else {
            EvaluationResult::Pass
        };
        let score =
            (1.0 - critical as f64 * 0.25 - warning as f64 * 0.05).clamp(0.0, 1.0);
        (result, score)
    }

    fn finding_from_alert(&self, alert: &Alert) -> Finding {
        let kind = match alert.kind {
            AlertKind::Drift => FindingKind::Drift,
            AlertKind::Loop => FindingKind::Loop,
            AlertKind::Intent => FindingKind::IntentShift,
            AlertKind::Harness => FindingKind::HarnessViolation,
            AlertKind::Policy => FindingKind::PolicyViolation,
            AlertKind::Security => FindingKind::Anomaly,
        };
        let mut finding = Finding::new(
            "monitor",
            &self.session.session_id,
            &self.session.agent_id,
            kind,
            alert.severity.to_platform(),
            alert.title.clone(),
            alert.message.clone(),
        )
        .with_evidence(alert.evidence_event_ids.iter().cloned());
        finding.genome_hash = self.session.genome_hash.clone();
        finding.observed = alert.observed.clone();
        finding.expected = alert.expected.clone();
        finding.recommended_action = alert.recommended_action.clone();
        finding.blocks_release = alert.blocks_release;
        finding.requires_human_review = alert.requires_human_review;
        finding.details = alert.details.clone();
        finding
    }

    fn record_finding_event(&self, finding: &Finding) -> CliResult<()> {
        let event_type = match finding.kind {
            FindingKind::Drift => event_types::MONITOR_DRIFT_DETECTED,
            FindingKind::Loop => event_types::MONITOR_LOOP_DETECTED,
            FindingKind::IntentShift => event_types::MONITOR_INTENT_SHIFTED,
            FindingKind::Failure | FindingKind::RepeatedFailure => {
                event_types::MONITOR_FAILURE_DETECTED
            }
            _ => event_types::MONITOR_FINDING_CREATED,
        };
        self.record_lifecycle_event(
            event_type,
            serde_json::json!({
                "finding_id": finding.finding_id,
                "kind": finding.kind.label(),
                "severity": finding.severity,
                "title": finding.title,
                "evidence_refs": finding.evidence_refs,
            }),
        )
    }

    fn record_lifecycle_event(
        &self,
        event_type: &str,
        payload: serde_json::Value,
    ) -> CliResult<()> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        let mut ev = RmpLedgerEvent::new(
            event_type,
            &self.session.session_id,
            &self.session.agent_id,
            payload,
        );
        ev.genome_hash = self.session.genome_hash.clone();
        ev.release_id = self.session.release_id.clone();
        // Chain monitor lifecycle events onto the tracking session's run so
        // one `ledger verify --run` covers events and findings together.
        ev.run_id = self.session.tracking_session_id.clone();
        ledger.append(ev.to_draft())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenomic_track::{ToolMeta, TrackingEventType};

    fn tool_event(session_id: &str, seq: u64, tool: &str) -> TrackingEvent {
        let mut ev = TrackingEvent::new(
            session_id,
            "agent://acme/claims",
            TrackingEventType::ToolCallCompleted,
            seq,
        );
        ev.tool = Some(ToolMeta {
            name: tool.into(),
            ..Default::default()
        });
        ev
    }

    fn engine() -> MonitorEngine {
        let mut baseline = DriftBaseline::default();
        baseline.allowed_tools.insert("claims_db.lookup".into());
        MonitorEngine::start(
            "agent://acme/claims",
            "production",
            baseline,
            MonitorConfig::default(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn out_of_baseline_tool_raises_drift_finding() {
        let mut m = engine();
        let sid = m.session().tracking_session_id.clone();
        let findings = m.ingest(tool_event(&sid, 0, "shell.exec")).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.kind == FindingKind::Drift));
        assert!(m.protect_triggered());
    }

    #[test]
    fn ingest_is_idempotent() {
        let mut m = engine();
        let sid = m.session().tracking_session_id.clone();
        let ev = tool_event(&sid, 0, "shell.exec");
        let first = m.ingest(ev.clone()).unwrap();
        let second = m.ingest(ev).unwrap();
        assert!(!first.is_empty());
        assert!(second.is_empty());
    }

    #[test]
    fn stop_builds_report_and_proposals() {
        let mut m = engine();
        let sid = m.session().tracking_session_id.clone();
        m.ingest(tool_event(&sid, 0, "shell.exec")).unwrap();
        let outcome = m
            .stop(&HarnessInputs::default(), SessionStatus::Completed)
            .unwrap();
        assert_eq!(outcome.session.status, RmpSessionStatus::Completed);
        assert!(outcome.protect_triggered);
        assert!(!outcome.scenario_proposals.is_empty());
        assert_eq!(outcome.history_entry.source, "monitor");
        assert!(outcome.report.event_count >= 1);
    }
}
