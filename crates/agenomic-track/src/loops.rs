//! Real-time loop detection.
//!
//! The detector is **deterministic and stateful**: it folds each
//! [`TrackingEvent`] into running counters and raises a [`LoopType`] alert the
//! first time a configured bound is crossed. Each distinct loop signature
//! alerts at most once per session (tracked in `alerted`), so a runaway agent
//! produces one actionable alert per pattern, not a flood.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::event::{TrackingEvent, TrackingEventType};

/// What the escalation engine should do when a loop is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EscalationBehavior {
    /// Emit a `warning` alert (non-blocking).
    #[default]
    Warn,
    /// Emit a `warning` alert that requires human review.
    RequireApproval,
    /// Emit a `critical` alert that blocks release and requires review.
    Block,
}

impl EscalationBehavior {
    fn severity_and_gating(self) -> (AlertSeverity, bool, bool) {
        match self {
            Self::Warn => (AlertSeverity::Warning, false, false),
            Self::RequireApproval => (AlertSeverity::Warning, false, true),
            Self::Block => (AlertSeverity::Critical, true, true),
        }
    }
}

/// Configurable loop-detection bounds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LoopConfig {
    /// Maximum number of agent steps before a `max_iterations` loop is flagged.
    pub max_iterations: u32,
    /// Maximum number of identical (tool, input_hash) calls.
    pub max_same_tool_calls: u32,
    /// Maximum number of repeats of the same state/output hash (no progress).
    pub max_same_state_hash_repeats: u32,
    /// Maximum wall-clock duration of a session before flagging.
    pub max_duration_seconds: u64,
    /// Number of consecutive no-progress events before a `no_progress` loop.
    pub no_progress_window: u32,
    /// Workflow step IDs explicitly permitted to repeat (exempt from cyclic checks).
    #[serde(default)]
    pub allowed_loop_step_ids: Vec<String>,
    /// What to do when a loop is detected.
    #[serde(default)]
    pub escalation: EscalationBehavior,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 50,
            max_same_tool_calls: 3,
            max_same_state_hash_repeats: 3,
            max_duration_seconds: 1800,
            no_progress_window: 5,
            allowed_loop_step_ids: Vec::new(),
            escalation: EscalationBehavior::Warn,
        }
    }
}

/// The kind of loop a [`LoopAlert`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopType {
    RepeatedToolCall,
    RepeatedModelCall,
    RepeatedWorkflowTransition,
    RecursiveHandoff,
    RepeatedFailure,
    MaxIterations,
    MaxDuration,
    NoProgress,
    CyclicWorkflow,
}

impl LoopType {
    fn label(self) -> &'static str {
        match self {
            Self::RepeatedToolCall => "repeated_tool_call",
            Self::RepeatedModelCall => "repeated_model_call",
            Self::RepeatedWorkflowTransition => "repeated_workflow_transition",
            Self::RecursiveHandoff => "recursive_handoff",
            Self::RepeatedFailure => "repeated_failure",
            Self::MaxIterations => "max_iterations",
            Self::MaxDuration => "max_duration",
            Self::NoProgress => "no_progress",
            Self::CyclicWorkflow => "cyclic_workflow",
        }
    }
}

/// Stateful loop detector for a single session.
#[derive(Debug, Clone)]
pub struct LoopDetector {
    session_id: String,
    config: LoopConfig,
    started_at: chrono::DateTime<chrono::Utc>,
    iteration_count: u32,
    tool_calls: HashMap<String, u32>,
    state_hashes: HashMap<String, u32>,
    step_transitions: HashMap<String, u32>,
    step_visits: HashMap<String, u32>,
    failure_streak: u32,
    no_progress_streak: u32,
    last_state_hash: Option<String>,
    last_step: Option<String>,
    alerted: HashSet<String>,
}

impl LoopDetector {
    pub fn new(
        session_id: impl Into<String>,
        config: LoopConfig,
        started_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            started_at,
            iteration_count: 0,
            tool_calls: HashMap::new(),
            state_hashes: HashMap::new(),
            step_transitions: HashMap::new(),
            step_visits: HashMap::new(),
            failure_streak: 0,
            no_progress_streak: 0,
            last_state_hash: None,
            last_step: None,
            alerted: HashSet::new(),
        }
    }

    fn allowed_step(&self, step: &str) -> bool {
        self.config.allowed_loop_step_ids.iter().any(|s| s == step)
    }

    /// Build an alert once per stable `key`; returns `None` on repeats.
    fn raise(
        &mut self,
        key: String,
        loop_type: LoopType,
        message: String,
        evidence: Vec<String>,
        observed: serde_json::Value,
    ) -> Option<Alert> {
        if !self.alerted.insert(key) {
            return None;
        }
        let (severity, blocks, review) = self.config.escalation.severity_and_gating();
        let alert = Alert::new(
            self.session_id.clone(),
            AlertKind::Loop,
            severity,
            format!("Loop detected: {}", loop_type.label()),
            message,
        )
        .with_evidence(evidence)
        .with_gating(blocks, review)
        .with_action("Inspect the repeated pattern; add a termination/guard condition or raise the relevant bound if the repetition is expected.")
        .with_details(serde_json::json!({
            "loop_type": loop_type.label(),
            "observed": observed,
        }));
        Some(alert)
    }

    /// Fold one event into the detector; return any newly-tripped loop alerts.
    pub fn observe(&mut self, ev: &TrackingEvent) -> Vec<Alert> {
        let mut out = Vec::new();
        let eid = ev.event_id.clone();

        // --- max duration --------------------------------------------------
        let elapsed = (ev.timestamp - self.started_at).num_seconds().max(0) as u64;
        if elapsed > self.config.max_duration_seconds {
            if let Some(a) = self.raise(
                "max_duration".into(),
                LoopType::MaxDuration,
                format!(
                    "Session ran for {elapsed}s, exceeding max_duration_seconds={}.",
                    self.config.max_duration_seconds
                ),
                vec![eid.clone()],
                serde_json::json!({ "elapsed_seconds": elapsed }),
            ) {
                out.push(a);
            }
        }

        match ev.event_type {
            // --- iteration / workflow topology ----------------------------
            TrackingEventType::AgentStepStarted => {
                self.iteration_count += 1;
                if self.iteration_count > self.config.max_iterations {
                    if let Some(a) = self.raise(
                        "max_iterations".into(),
                        LoopType::MaxIterations,
                        format!(
                            "Agent executed {} steps, exceeding max_iterations={}.",
                            self.iteration_count, self.config.max_iterations
                        ),
                        vec![eid.clone()],
                        serde_json::json!({ "iterations": self.iteration_count }),
                    ) {
                        out.push(a);
                    }
                }
                if let Some(step) = &ev.workflow_step_id {
                    if !self.allowed_step(step) {
                        let visits = self.step_visits.entry(step.clone()).or_insert(0);
                        *visits += 1;
                        if *visits > self.config.max_same_state_hash_repeats {
                            let visits_now = *visits;
                            if let Some(a) = self.raise(
                                format!("cyclic_step:{step}"),
                                LoopType::CyclicWorkflow,
                                format!(
                                    "Workflow step '{step}' visited {visits_now} times (cyclic path)."
                                ),
                                vec![eid.clone()],
                                serde_json::json!({ "step_id": step, "visits": visits_now }),
                            ) {
                                out.push(a);
                            }
                        }
                        if let Some(prev) = &self.last_step {
                            let key = format!("{prev}->{step}");
                            let n = self.step_transitions.entry(key.clone()).or_insert(0);
                            *n += 1;
                            if *n > self.config.max_same_state_hash_repeats {
                                let n_now = *n;
                                if let Some(a) = self.raise(
                                    format!("transition:{key}"),
                                    LoopType::RepeatedWorkflowTransition,
                                    format!("Workflow transition '{key}' repeated {n_now} times."),
                                    vec![eid.clone()],
                                    serde_json::json!({ "transition": key, "count": n_now }),
                                ) {
                                    out.push(a);
                                }
                            }
                        }
                    }
                    self.last_step = Some(step.clone());
                }
            }

            // --- repeated tool calls --------------------------------------
            TrackingEventType::ToolCallCompleted | TrackingEventType::ToolCallStarted => {
                if let Some(tool) = &ev.tool {
                    let ih = ev.input_hash.clone().unwrap_or_default();
                    let key = format!("{}|{ih}", tool.name);
                    let n = self.tool_calls.entry(key.clone()).or_insert(0);
                    *n += 1;
                    if *n > self.config.max_same_tool_calls {
                        let n_now = *n;
                        let tool_name = tool.name.clone();
                        if let Some(a) = self.raise(
                            format!("tool:{key}"),
                            LoopType::RepeatedToolCall,
                            format!(
                                "Tool '{tool_name}' called {n_now} times with identical input."
                            ),
                            vec![eid.clone()],
                            serde_json::json!({
                                "tool": tool_name,
                                "input_hash": ih,
                                "count": n_now,
                            }),
                        ) {
                            out.push(a);
                        }
                    }
                }
                self.observe_failure(ev, &mut out);
            }

            // --- repeated model calls with no state progress --------------
            TrackingEventType::ModelCallCompleted => {
                if let Some(ih) = &ev.input_hash {
                    let key = format!("model|{ih}");
                    let n = self.state_hashes.entry(key.clone()).or_insert(0);
                    *n += 1;
                    if *n > self.config.max_same_state_hash_repeats {
                        let n_now = *n;
                        if let Some(a) = self.raise(
                            format!("model:{key}"),
                            LoopType::RepeatedModelCall,
                            format!(
                                "Model called {n_now} times with identical input (no progress)."
                            ),
                            vec![eid.clone()],
                            serde_json::json!({ "input_hash": ih, "count": n_now }),
                        ) {
                            out.push(a);
                        }
                    }
                }
                self.observe_progress(ev, &mut out);
            }

            // --- step completions track progress --------------------------
            TrackingEventType::AgentStepCompleted => {
                self.observe_progress(ev, &mut out);
            }

            TrackingEventType::AgentFailed => {
                self.observe_failure(ev, &mut out);
            }

            _ => {}
        }

        out
    }

    /// Detect recursive handoffs across sub-agents: a parent agent revisiting
    /// the same downstream agent id repeatedly is a recursive-handoff loop.
    fn observe_progress(&mut self, ev: &TrackingEvent, out: &mut Vec<Alert>) {
        let state = ev
            .output_hash
            .clone()
            .or_else(|| ev.input_hash.clone())
            .unwrap_or_default();
        if state.is_empty() {
            return;
        }
        if self.last_state_hash.as_deref() == Some(state.as_str()) {
            self.no_progress_streak += 1;
            if self.no_progress_streak >= self.config.no_progress_window {
                let streak = self.no_progress_streak;
                if let Some(a) = self.raise(
                    "no_progress".into(),
                    LoopType::NoProgress,
                    format!(
                        "{streak} consecutive events produced no state change (output hash unchanged)."
                    ),
                    vec![ev.event_id.clone()],
                    serde_json::json!({ "no_progress_window": streak, "state_hash": state }),
                ) {
                    out.push(a);
                }
            }
        } else {
            self.no_progress_streak = 0;
            self.failure_streak = 0;
            self.last_state_hash = Some(state);
        }
    }

    fn observe_failure(&mut self, ev: &TrackingEvent, out: &mut Vec<Alert>) {
        let failed = matches!(ev.event_type, TrackingEventType::AgentFailed)
            || ev
                .metadata
                .as_ref()
                .and_then(|m| m.get("status"))
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("error") || s.eq_ignore_ascii_case("failed"))
                .unwrap_or(false);
        if !failed {
            return;
        }
        self.failure_streak += 1;
        if self.failure_streak > self.config.max_same_tool_calls {
            let streak = self.failure_streak;
            if let Some(a) = self.raise(
                format!("failure_streak:{}", self.failure_streak),
                LoopType::RepeatedFailure,
                format!("{streak} consecutive failed attempts."),
                vec![ev.event_id.clone()],
                serde_json::json!({ "failure_streak": streak }),
            ) {
                out.push(a);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn tool_event(seq: u64, name: &str, input_hash: &str, ts: i64) -> TrackingEvent {
        let mut e = TrackingEvent::new(
            "s1",
            "agent://a/b",
            TrackingEventType::ToolCallCompleted,
            seq,
        );
        e.timestamp = at(ts);
        e.tool = Some(crate::event::ToolMeta {
            name: name.into(),
            ..Default::default()
        });
        e.input_hash = Some(format!("blake3:{input_hash}"));
        e
    }

    #[test]
    fn repeated_tool_call_alerts_once() {
        let mut d = LoopDetector::new("s1", LoopConfig::default(), at(0));
        let mut alerts = Vec::new();
        for i in 0..6 {
            alerts.extend(d.observe(&tool_event(i, "search", "aaaa", i as i64)));
        }
        let loop_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.kind == AlertKind::Loop)
            .collect();
        assert_eq!(loop_alerts.len(), 1, "exactly one loop alert per pattern");
        assert_eq!(
            loop_alerts[0].details.as_ref().unwrap()["loop_type"],
            "repeated_tool_call"
        );
    }

    #[test]
    fn distinct_inputs_do_not_loop() {
        let mut d = LoopDetector::new("s1", LoopConfig::default(), at(0));
        let mut alerts = Vec::new();
        for i in 0..6 {
            alerts.extend(d.observe(&tool_event(i, "search", &format!("h{i}"), i as i64)));
        }
        assert!(alerts.is_empty());
    }

    #[test]
    fn max_iterations_trips() {
        let cfg = LoopConfig {
            max_iterations: 3,
            ..LoopConfig::default()
        };
        let mut d = LoopDetector::new("s1", cfg, at(0));
        let mut alerts = Vec::new();
        for i in 0..5 {
            let mut e =
                TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStepStarted, i);
            e.timestamp = at(i as i64);
            alerts.extend(d.observe(&e));
        }
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["loop_type"] == "max_iterations"));
    }

    #[test]
    fn max_duration_trips() {
        let cfg = LoopConfig {
            max_duration_seconds: 10,
            ..LoopConfig::default()
        };
        let mut d = LoopDetector::new("s1", cfg, at(0));
        let mut e = TrackingEvent::new(
            "s1",
            "agent://a/b",
            TrackingEventType::ModelCallCompleted,
            0,
        );
        e.timestamp = at(30);
        let alerts = d.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["loop_type"] == "max_duration"));
    }

    #[test]
    fn no_progress_window_trips() {
        let cfg = LoopConfig {
            no_progress_window: 3,
            ..LoopConfig::default()
        };
        let mut d = LoopDetector::new("s1", cfg, at(0));
        let mut alerts = Vec::new();
        for i in 0..6 {
            let mut e = TrackingEvent::new(
                "s1",
                "agent://a/b",
                TrackingEventType::AgentStepCompleted,
                i,
            );
            e.timestamp = at(i as i64);
            e.output_hash = Some("blake3:same".into());
            alerts.extend(d.observe(&e));
        }
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["loop_type"] == "no_progress"));
    }

    #[test]
    fn escalation_block_makes_alert_critical() {
        let cfg = LoopConfig {
            max_same_tool_calls: 1,
            escalation: EscalationBehavior::Block,
            ..LoopConfig::default()
        };
        let mut d = LoopDetector::new("s1", cfg, at(0));
        let mut alerts = Vec::new();
        for i in 0..3 {
            alerts.extend(d.observe(&tool_event(i, "x", "h", i as i64)));
        }
        let a = alerts.iter().find(|a| a.kind == AlertKind::Loop).unwrap();
        assert_eq!(a.severity, AlertSeverity::Critical);
        assert!(a.blocks_release);
    }
}
