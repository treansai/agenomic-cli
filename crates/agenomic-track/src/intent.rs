//! Online intent tracking.
//!
//! Intent can arrive **explicitly** (an `intent.detected` event carrying
//! `intent`, emitted by SDK instrumentation) or be **inferred** from the event
//! stream via an [`IntentProvider`]. The default [`DeterministicIntentClassifier`]
//! infers intent from the workflow step / tool usage with no LLM; an optional
//! semantic classifier can be plugged behind the same trait. The tracker then
//! compares the observed intent against the declared allow/forbid sets, the
//! current workflow step's objective, and tool-permission boundaries.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::event::{TrackingEvent, TrackingEventType};

/// The kind of intent problem detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentIssue {
    IntentShift,
    ForbiddenIntent,
    UnclearIntent,
    StepMismatch,
    PermissionMismatch,
    EscalationRequired,
}

impl IntentIssue {
    pub fn label(self) -> &'static str {
        match self {
            Self::IntentShift => "intent_shift",
            Self::ForbiddenIntent => "forbidden_intent",
            Self::UnclearIntent => "unclear_intent",
            Self::StepMismatch => "step_mismatch",
            Self::PermissionMismatch => "permission_mismatch",
            Self::EscalationRequired => "escalation_required",
        }
    }
}

/// Intent-tracking configuration (the agent's declared intent envelope).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct IntentConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The closed set of permitted intents. Empty means "do not constrain".
    #[serde(default)]
    pub allowed_intents: Vec<String>,
    /// Intents that must never occur.
    #[serde(default)]
    pub forbidden_intents: Vec<String>,
    /// Intents that require human escalation when observed.
    #[serde(default)]
    pub escalation_intents: Vec<String>,
    /// Per-step objectives: `workflow_step_id -> allowed intents`.
    #[serde(default)]
    pub step_intents: HashMap<String, Vec<String>>,
    /// Per-intent tool grants: `intent -> tools that intent may use`.
    #[serde(default)]
    pub intent_tools: HashMap<String, Vec<String>>,
}

fn default_true() -> bool {
    true
}

impl Default for IntentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_intents: Vec::new(),
            forbidden_intents: Vec::new(),
            escalation_intents: Vec::new(),
            step_intents: HashMap::new(),
            intent_tools: HashMap::new(),
        }
    }
}

/// Result of classifying an event's intent.
pub struct IntentClassification {
    pub intent: String,
    pub confidence: f64,
}

/// Pluggable intent classifier. The deterministic default works with no LLM;
/// a semantic classifier may be supplied behind the same interface.
pub trait IntentProvider {
    fn classify(&self, ev: &TrackingEvent) -> Option<IntentClassification>;
}

/// Deterministic fallback: infer intent from the workflow step (its objective)
/// or, failing that, the tool being invoked. Never calls an LLM.
pub struct DeterministicIntentClassifier;

impl IntentProvider for DeterministicIntentClassifier {
    fn classify(&self, ev: &TrackingEvent) -> Option<IntentClassification> {
        if let Some(step) = &ev.workflow_step_id {
            return Some(IntentClassification {
                intent: step.clone(),
                confidence: 0.5,
            });
        }
        if let Some(tool) = &ev.tool {
            return Some(IntentClassification {
                intent: format!("use_tool:{}", tool.name),
                confidence: 0.4,
            });
        }
        None
    }
}

/// Stateful intent tracker for one session.
pub struct IntentTracker {
    session_id: String,
    config: IntentConfig,
    provider: Box<dyn IntentProvider + Send>,
    current_intent: Option<String>,
    alerted: HashSet<String>,
}

impl IntentTracker {
    pub fn new(session_id: impl Into<String>, config: IntentConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            provider: Box::new(DeterministicIntentClassifier),
            current_intent: None,
            alerted: HashSet::new(),
        }
    }

    /// Replace the inference provider (e.g. with an LLM classifier).
    pub fn with_provider(mut self, provider: Box<dyn IntentProvider + Send>) -> Self {
        self.provider = provider;
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn raise(
        &mut self,
        key: String,
        issue: IntentIssue,
        severity: AlertSeverity,
        message: String,
        expected: serde_json::Value,
        observed: serde_json::Value,
        confidence: f64,
        evidence: Vec<String>,
        blocks: bool,
        review: bool,
    ) -> Option<Alert> {
        if !self.alerted.insert(key) {
            return None;
        }
        Some(
            Alert::new(
                self.session_id.clone(),
                AlertKind::Intent,
                severity,
                format!("Intent issue: {}", issue.label()),
                message,
            )
            .with_evidence(evidence)
            .with_observed_expected(Some(observed.clone()), Some(expected.clone()))
            .with_gating(blocks, review)
            .with_action(match issue {
                IntentIssue::ForbiddenIntent => {
                    "Halt the agent: a forbidden intent was observed. Review the trajectory before resuming."
                }
                IntentIssue::EscalationRequired => "Route to a human reviewer before the agent proceeds.",
                _ => "Confirm the agent's objective still matches the task and behavior contract.",
            })
            .with_details(serde_json::json!({
                "intent_issue": issue.label(),
                "expected_intent": expected,
                "observed_intent": observed,
                "confidence": confidence,
            })),
        )
    }

    /// Fold one event into the tracker; return any newly-detected intent alerts.
    pub fn observe(&mut self, ev: &TrackingEvent) -> Vec<Alert> {
        let mut out = Vec::new();
        if !self.config.enabled {
            return out;
        }

        // Resolve the observed intent: explicit first, then inferred.
        let (intent, confidence, explicit) = if matches!(
            ev.event_type,
            TrackingEventType::IntentDetected
        ) {
            match &ev.intent {
                Some(i) if !i.trim().is_empty() => (i.clone(), 1.0, true),
                _ => {
                    if let Some(a) = self.raise(
                        format!("unclear:{}", ev.event_id),
                        IntentIssue::UnclearIntent,
                        AlertSeverity::Warning,
                        "An intent.detected event carried no resolvable intent.".into(),
                        serde_json::json!(self.config.allowed_intents),
                        serde_json::Value::Null,
                        0.0,
                        vec![ev.event_id.clone()],
                        false,
                        false,
                    ) {
                        out.push(a);
                    }
                    return out;
                }
            }
        } else {
            match self.provider.classify(ev) {
                Some(c) => (c.intent, c.confidence, false),
                None => return out, // nothing to evaluate
            }
        };

        let eid = ev.event_id.clone();

        // forbidden
        if self.config.forbidden_intents.iter().any(|f| f == &intent) {
            if let Some(a) = self.raise(
                format!("forbidden:{intent}"),
                IntentIssue::ForbiddenIntent,
                AlertSeverity::Critical,
                format!("Observed forbidden intent '{intent}'."),
                serde_json::json!(self.config.forbidden_intents),
                serde_json::json!(intent),
                confidence,
                vec![eid.clone()],
                true,
                true,
            ) {
                out.push(a);
            }
        }

        // Not in the declared allowed set. Only applied to confident intents
        // (explicit, or workflow-step-inferred at confidence >= 0.5). Low
        // confidence tool-usage inferences ("use_tool:*") are not penalised
        // here — they would flag every legitimate tool call as a shift — but
        // they are still checked against the forbidden set above.
        if confidence >= 0.5
            && !self.config.allowed_intents.is_empty()
            && !self.config.allowed_intents.iter().any(|a| a == &intent)
            && !self.config.forbidden_intents.iter().any(|f| f == &intent)
        {
            if let Some(a) = self.raise(
                format!("not_allowed:{intent}"),
                IntentIssue::IntentShift,
                AlertSeverity::Warning,
                format!("Observed intent '{intent}' is outside the declared allowed set."),
                serde_json::json!(self.config.allowed_intents),
                serde_json::json!(intent),
                confidence,
                vec![eid.clone()],
                false,
                true,
            ) {
                out.push(a);
            }
        }

        // escalation required
        if self.config.escalation_intents.iter().any(|e| e == &intent) {
            if let Some(a) = self.raise(
                format!("escalate:{intent}"),
                IntentIssue::EscalationRequired,
                AlertSeverity::Warning,
                format!("Intent '{intent}' requires human escalation."),
                serde_json::json!(self.config.escalation_intents),
                serde_json::json!(intent),
                confidence,
                vec![eid.clone()],
                false,
                true,
            ) {
                out.push(a);
            }
        }

        // step-objective mismatch
        if let Some(step) = &ev.workflow_step_id {
            if let Some(allowed) = self.config.step_intents.get(step) {
                if !allowed.iter().any(|a| a == &intent) {
                    if let Some(a) = self.raise(
                        format!("step:{step}:{intent}"),
                        IntentIssue::StepMismatch,
                        AlertSeverity::Warning,
                        format!("Intent '{intent}' does not match step '{step}' objective."),
                        serde_json::json!(allowed),
                        serde_json::json!(intent),
                        confidence,
                        vec![eid.clone()],
                        false,
                        false,
                    ) {
                        out.push(a);
                    }
                }
            }
        }

        // tool-permission mismatch: an intent driving a tool it isn't granted
        if let Some(tool) = &ev.tool {
            if let Some(grant) = self.config.intent_tools.get(&intent) {
                if !grant.iter().any(|t| t == &tool.name) {
                    let tname = tool.name.clone();
                    if let Some(a) = self.raise(
                        format!("perm:{intent}:{tname}"),
                        IntentIssue::PermissionMismatch,
                        AlertSeverity::Warning,
                        format!("Intent '{intent}' used tool '{tname}' outside its grant."),
                        serde_json::json!(grant),
                        serde_json::json!(tname),
                        confidence,
                        vec![eid.clone()],
                        false,
                        true,
                    ) {
                        out.push(a);
                    }
                }
            }
        }

        // intent shift relative to the prior explicit intent
        if explicit {
            if let Some(prev) = &self.current_intent {
                if prev != &intent {
                    if let Some(a) = self.raise(
                        format!("shift:{prev}->{intent}"),
                        IntentIssue::IntentShift,
                        AlertSeverity::Info,
                        format!("Agent intent shifted from '{prev}' to '{intent}'."),
                        serde_json::json!(prev),
                        serde_json::json!(intent),
                        confidence,
                        vec![eid.clone()],
                        false,
                        false,
                    ) {
                        out.push(a);
                    }
                }
            }
            self.current_intent = Some(intent);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ToolMeta;

    fn cfg() -> IntentConfig {
        IntentConfig {
            enabled: true,
            allowed_intents: vec!["verify_claim_validity".into(), "classify_claim".into()],
            forbidden_intents: vec!["exfiltrate_data".into()],
            ..Default::default()
        }
    }

    fn intent_event(intent: &str, seq: u64) -> TrackingEvent {
        let mut e = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::IntentDetected, seq);
        e.intent = Some(intent.into());
        e
    }

    #[test]
    fn forbidden_intent_is_critical() {
        let mut t = IntentTracker::new("s1", cfg());
        let alerts = t.observe(&intent_event("exfiltrate_data", 0));
        let a = alerts
            .iter()
            .find(|a| a.details.as_ref().unwrap()["intent_issue"] == "forbidden_intent")
            .unwrap();
        assert_eq!(a.severity, AlertSeverity::Critical);
        assert!(a.blocks_release);
    }

    #[test]
    fn allowed_intent_is_clean() {
        let mut t = IntentTracker::new("s1", cfg());
        assert!(t.observe(&intent_event("verify_claim_validity", 0)).is_empty());
    }

    #[test]
    fn out_of_set_intent_shifts() {
        let mut t = IntentTracker::new("s1", cfg());
        let alerts = t.observe(&intent_event("browse_web", 0));
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["intent_issue"] == "intent_shift"));
    }

    #[test]
    fn empty_intent_is_unclear() {
        let mut t = IntentTracker::new("s1", cfg());
        let mut e = intent_event("", 0);
        e.intent = Some("".into());
        let alerts = t.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["intent_issue"] == "unclear_intent"));
    }

    #[test]
    fn deterministic_inference_from_step() {
        // No explicit intent event; inference from a step that is out-of-set.
        let mut t = IntentTracker::new("s1", cfg());
        let mut e =
            TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStepStarted, 0);
        e.workflow_step_id = Some("delete_everything".into());
        let alerts = t.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["intent_issue"] == "intent_shift"));
    }

    #[test]
    fn step_mismatch_detected() {
        let mut c = cfg();
        c.allowed_intents.clear(); // don't trip the allowed-set check
        c.step_intents
            .insert("classify".into(), vec!["classify_claim".into()]);
        let mut t = IntentTracker::new("s1", c);
        let mut e = intent_event("verify_claim_validity", 0);
        e.workflow_step_id = Some("classify".into());
        let alerts = t.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["intent_issue"] == "step_mismatch"));
    }

    #[test]
    fn permission_mismatch_detected() {
        let mut c = IntentConfig {
            enabled: true,
            ..Default::default()
        };
        c.intent_tools
            .insert("read_claim".into(), vec!["claims_db.lookup".into()]);
        let mut t = IntentTracker::new("s1", c);
        let mut e = intent_event("read_claim", 0);
        e.tool = Some(ToolMeta {
            name: "shell.exec".into(),
            ..Default::default()
        });
        let alerts = t.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["intent_issue"] == "permission_mismatch"));
    }
}
