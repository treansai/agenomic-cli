//! The tracking engine: idempotent event ingestion + detector orchestration.
//!
//! The engine folds each live [`TrackingEvent`] through the drift, loop and
//! intent detectors, accumulates the resulting [`Alert`]s onto the
//! [`TrackingSession`], and keeps the rolling [`SessionSummary`] current.
//!
//! Ingestion is **idempotent**: re-ingesting an event with an `event_id` the
//! engine has already seen is a no-op, so producers can retry safely. The
//! engine is also **resumable** ([`TrackingEngine::resume`]) so the stateless
//! CLI can rebuild detector state from a persisted session + event log without
//! double-counting alerts.

use std::collections::HashSet;

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::drift::{DriftBaseline, DriftDetector};
use crate::event::TrackingEvent;
use crate::harness::{HarnessInputs, HarnessResult, RuntimeHarness};
use crate::intent::IntentTracker;
use crate::loops::LoopDetector;
use crate::session::{SessionStatus, TrackingSession};

/// The stateful online-tracking engine for one session.
pub struct TrackingEngine {
    pub session: TrackingSession,
    pub events: Vec<TrackingEvent>,
    seen: HashSet<String>,
    drift: DriftDetector,
    loops: LoopDetector,
    intent: IntentTracker,
    last_event_hash: Option<String>,
}

impl TrackingEngine {
    /// Create a fresh engine for an active session and its drift baseline.
    pub fn new(session: TrackingSession, baseline: DriftBaseline) -> Self {
        let drift = DriftDetector::new(
            session.session_id.clone(),
            session.tracking_config.drift.clone(),
            baseline,
        );
        let loops = LoopDetector::new(
            session.session_id.clone(),
            session.tracking_config.loops.clone(),
            session.started_at,
        );
        let intent = IntentTracker::new(
            session.session_id.clone(),
            session.tracking_config.intent.clone(),
        );
        Self {
            session,
            events: Vec::new(),
            seen: HashSet::new(),
            drift,
            loops,
            intent,
            last_event_hash: None,
        }
    }

    /// Rebuild an engine from a persisted session + event log. Detector state
    /// is warmed by replaying the events, but the already-recorded alerts and
    /// summary on `session` are preserved (the replayed alerts are discarded).
    pub fn resume(
        session: TrackingSession,
        events: Vec<TrackingEvent>,
        baseline: DriftBaseline,
    ) -> Self {
        let mut e = Self::new(session, baseline);
        for ev in &events {
            // Warm detector counters; discard re-emitted alerts.
            let _ = e.drift.observe(ev);
            let _ = e.loops.observe(ev);
            let _ = e.intent.observe(ev);
            e.seen.insert(ev.event_id.clone());
            e.last_event_hash = ev.event_hash.clone().or(e.last_event_hash.take());
        }
        e.events = events;
        e
    }

    /// True if `event_id` has already been ingested.
    pub fn has_event(&self, event_id: &str) -> bool {
        self.seen.contains(event_id)
    }

    /// Ingest one event. Returns the alerts newly raised by this event (empty
    /// on a duplicate / already-seen `event_id`).
    pub fn ingest(&mut self, mut event: TrackingEvent) -> Vec<Alert> {
        if self.seen.contains(&event.event_id) {
            return Vec::new();
        }
        // Bind the event to this session and seal its hash-link if the producer
        // did not already supply one.
        event.session_id = self.session.session_id.clone();
        if event.event_hash.is_none() {
            event.link_after(self.last_event_hash.clone());
        }
        self.last_event_hash = event.event_hash.clone();

        let mut alerts = Vec::new();
        alerts.extend(self.drift.observe(&event));
        alerts.extend(self.loops.observe(&event));
        alerts.extend(self.intent.observe(&event));

        self.seen.insert(event.event_id.clone());
        self.events.push(event);

        self.session.summary.event_count += 1;
        for a in &alerts {
            self.record_alert_in_summary(a);
        }
        self.session.alerts.extend(alerts.clone());
        alerts
    }

    /// Ingest many events in order.
    pub fn ingest_all(&mut self, events: impl IntoIterator<Item = TrackingEvent>) -> Vec<Alert> {
        let mut out = Vec::new();
        for ev in events {
            out.extend(self.ingest(ev));
        }
        out
    }

    fn record_alert_in_summary(&mut self, a: &Alert) {
        let s = &mut self.session.summary;
        s.alert_count += 1;
        match a.kind {
            AlertKind::Drift => s.drift_count += 1,
            AlertKind::Loop => s.loop_count += 1,
            AlertKind::Intent => s.intent_count += 1,
            AlertKind::Harness | AlertKind::Policy | AlertKind::Security => s.harness_failures += 1,
        }
        match a.severity {
            AlertSeverity::Info => s.info += 1,
            AlertSeverity::Warning => s.warning += 1,
            AlertSeverity::Critical => s.critical += 1,
        }
    }

    /// Run the runtime harness over the session.
    ///
    /// This is read-only with respect to the session: harness alerts live in
    /// the returned [`HarnessResult`] and are merged into the report by
    /// [`crate::report::build_report`], not persisted back onto `session.alerts`.
    /// That keeps `track report` idempotent — it can be re-run any number of
    /// times without double-counting harness findings.
    pub fn run_harness(&self, inputs: &HarnessInputs) -> HarnessResult {
        let harness = RuntimeHarness::new(self.session.session_id.clone());
        harness.evaluate(
            &self.session.agent_id,
            &self.events,
            &self.session.alerts,
            inputs,
        )
    }

    /// Transition the session to a terminal status and stamp `ended_at`.
    pub fn stop(&mut self, status: SessionStatus) {
        self.session.status = status;
        self.session.ended_at = Some(chrono::Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ToolMeta, TrackingEventType};
    use crate::session::TrackingSession;

    fn tool_event(name: &str, ih: &str) -> TrackingEvent {
        let mut e = TrackingEvent::new(
            "",
            "agent://acme/claims",
            TrackingEventType::ToolCallCompleted,
            0,
        );
        e.tool = Some(ToolMeta {
            name: name.into(),
            ..Default::default()
        });
        e.input_hash = Some(format!("blake3:{ih}"));
        e
    }

    fn engine() -> TrackingEngine {
        let mut session = TrackingSession::new("agent://acme/claims", "production");
        session.tracking_config.loops.max_same_tool_calls = 2;
        let mut baseline = DriftBaseline::default();
        baseline.allowed_tools.insert("claims_db.lookup".into());
        TrackingEngine::new(session, baseline)
    }

    #[test]
    fn ingest_is_idempotent() {
        let mut e = engine();
        let ev = tool_event("claims_db.lookup", "a");
        let id = ev.event_id.clone();
        let first = e.ingest(ev.clone());
        let again = e.ingest(ev); // same event_id
        assert!(again.is_empty());
        assert_eq!(e.events.len(), 1);
        assert_eq!(e.session.summary.event_count, 1);
        assert!(e.has_event(&id));
        let _ = first;
    }

    #[test]
    fn unauthorized_tool_raises_drift_and_updates_summary() {
        let mut e = engine();
        let alerts = e.ingest(tool_event("shell.exec", "a"));
        assert!(alerts.iter().any(|a| a.kind == AlertKind::Drift));
        assert_eq!(e.session.summary.drift_count, 1);
        assert_eq!(e.session.summary.critical, 1);
    }

    #[test]
    fn events_are_hash_linked() {
        let mut e = engine();
        e.ingest(tool_event("claims_db.lookup", "a"));
        e.ingest(tool_event("claims_db.lookup", "b"));
        assert!(e.events[0].event_hash.is_some());
        assert_eq!(e.events[1].prev_event_hash, e.events[0].event_hash);
        assert!(e.events.iter().all(|ev| ev.hash_is_valid()));
    }

    #[test]
    fn resume_warms_detectors_without_double_counting() {
        let mut e = engine();
        e.ingest(tool_event("claims_db.lookup", "x"));
        e.ingest(tool_event("claims_db.lookup", "x"));
        let session = e.session.clone();
        let events = e.events.clone();
        let summary_before = session.summary.clone();

        // Resume from disk state and ingest a third identical call → loop trips.
        let mut baseline = DriftBaseline::default();
        baseline.allowed_tools.insert("claims_db.lookup".into());
        let mut resumed = TrackingEngine::resume(session, events, baseline);
        assert_eq!(resumed.session.summary, summary_before); // no double count
        let alerts = resumed.ingest(tool_event("claims_db.lookup", "x"));
        assert!(alerts.iter().any(|a| a.kind == AlertKind::Loop));
    }

    #[test]
    fn stop_sets_terminal_status() {
        let mut e = engine();
        e.stop(SessionStatus::Completed);
        assert_eq!(e.session.status, SessionStatus::Completed);
        assert!(e.session.ended_at.is_some());
    }
}
