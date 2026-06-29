//! The live runtime event model for online tracking.
//!
//! [`TrackingEvent`] is a JSON projection that deliberately mirrors the
//! canonical v0.3 trace event and the ATEP event header: it carries a
//! `sequence_number`, an optional `parent_event_id`, content `*_hash` fields,
//! a `prev_event_hash`/`event_hash` hash-link, and an optional ed25519
//! [`EventSignature`]. Producers (SDKs, the CLI) emit these; the engine
//! consumes them. Only redacted previews and content hashes ever appear —
//! never raw payloads.

use serde::{Deserialize, Serialize};

/// The runtime event vocabulary for an online-tracking session.
///
/// These are a production-time superset of the canonical v0.3 trace events:
/// `model.call.*`/`tool.call.*`/`memory.*` map onto `llm.*`/`tool.call.*`/
/// `memory.*` from the v0.3 registry, while `intent.detected`,
/// `loop.detected`, `drift.detected`, `harness.violation` and `alert.created`
/// are tracking-native detector events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum TrackingEventType {
    #[serde(rename = "agent.started")]
    AgentStarted,
    #[serde(rename = "agent.step.started")]
    AgentStepStarted,
    #[serde(rename = "agent.step.completed")]
    AgentStepCompleted,
    #[serde(rename = "model.call.started")]
    ModelCallStarted,
    #[serde(rename = "model.call.completed")]
    ModelCallCompleted,
    #[serde(rename = "tool.call.started")]
    ToolCallStarted,
    #[serde(rename = "tool.call.completed")]
    ToolCallCompleted,
    #[serde(rename = "memory.read")]
    MemoryRead,
    #[serde(rename = "memory.write")]
    MemoryWrite,
    #[serde(rename = "policy.evaluated")]
    PolicyEvaluated,
    #[serde(rename = "intent.detected")]
    IntentDetected,
    #[serde(rename = "loop.detected")]
    LoopDetected,
    #[serde(rename = "drift.detected")]
    DriftDetected,
    #[serde(rename = "harness.violation")]
    HarnessViolation,
    #[serde(rename = "alert.created")]
    AlertCreated,
    #[serde(rename = "agent.completed")]
    AgentCompleted,
    #[serde(rename = "agent.failed")]
    AgentFailed,
}

impl TrackingEventType {
    /// The dotted wire name (matches the spec's event-type registry).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentStarted => "agent.started",
            Self::AgentStepStarted => "agent.step.started",
            Self::AgentStepCompleted => "agent.step.completed",
            Self::ModelCallStarted => "model.call.started",
            Self::ModelCallCompleted => "model.call.completed",
            Self::ToolCallStarted => "tool.call.started",
            Self::ToolCallCompleted => "tool.call.completed",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::PolicyEvaluated => "policy.evaluated",
            Self::IntentDetected => "intent.detected",
            Self::LoopDetected => "loop.detected",
            Self::DriftDetected => "drift.detected",
            Self::HarnessViolation => "harness.violation",
            Self::AlertCreated => "alert.created",
            Self::AgentCompleted => "agent.completed",
            Self::AgentFailed => "agent.failed",
        }
    }
}

/// Tool metadata carried on `tool.call.*` events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ToolMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

/// Model metadata carried on `model.call.*` events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ModelMeta {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

/// Inline policy/harness outcome carried on `policy.evaluated` events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// `allow` | `deny` | `review`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denies: Vec<String>,
}

/// Detached ed25519 signature over the event's `event_hash` (ATEP style).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSignature {
    pub signer_key_id: String,
    pub algo: String,
    pub value: String,
}

/// A single live runtime event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackingEvent {
    pub event_id: String,
    pub session_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sequence_number: u64,
    #[serde(rename = "type")]
    pub event_type: TrackingEventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_step_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_preview: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_result: Option<PolicyResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<EventSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Domain separator for the tracking event hash-link.
const EVENT_DOMAIN: &[u8] = b"AGENOMIC-TRACK-EVENT-v1\0";

impl TrackingEvent {
    /// Minimal constructor for a typed event in a session.
    pub fn new(
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        event_type: TrackingEventType,
        sequence_number: u64,
    ) -> Self {
        Self {
            event_id: ulid::Ulid::new().to_string(),
            session_id: session_id.into(),
            timestamp: chrono::Utc::now(),
            sequence_number,
            event_type,
            parent_event_id: None,
            agent_id: agent_id.into(),
            genome_hash: None,
            workflow_step_id: None,
            tool: None,
            model: None,
            input_hash: None,
            output_hash: None,
            redacted_preview: None,
            policy_result: None,
            intent: None,
            prev_event_hash: None,
            event_hash: None,
            signature: None,
            metadata: None,
        }
    }

    /// Compute the deterministic `event_hash` for this event.
    ///
    /// `event_hash = "blake3:" + hex(BLAKE3(DOMAIN || json(event∖{event_hash,
    /// signature}) || prev_event_hash))`. The hash excludes the signature so a
    /// detached signature can be applied over a stable digest, exactly like the
    /// ATEP `causal_hash` design.
    pub fn compute_hash(&self) -> String {
        let mut bare = self.clone();
        bare.event_hash = None;
        bare.signature = None;
        let prev = self.prev_event_hash.clone().unwrap_or_default();
        let body = serde_json::to_vec(&bare).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(EVENT_DOMAIN);
        hasher.update(&body);
        hasher.update(prev.as_bytes());
        format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()))
    }

    /// Link this event onto `prev` and stamp its `event_hash`.
    pub fn link_after(&mut self, prev_event_hash: Option<String>) {
        self.prev_event_hash =
            Some(prev_event_hash.unwrap_or_else(|| format!("blake3:{}", "0".repeat(64))));
        self.event_hash = Some(self.compute_hash());
    }

    /// True when the stored `event_hash` matches a recomputation (tamper check).
    pub fn hash_is_valid(&self) -> bool {
        match &self.event_hash {
            Some(h) => *h == self.compute_hash(),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serializes_dotted() {
        let s = serde_json::to_string(&TrackingEventType::ToolCallCompleted).unwrap();
        assert_eq!(s, "\"tool.call.completed\"");
        let back: TrackingEventType = serde_json::from_str(&s).unwrap();
        assert_eq!(back, TrackingEventType::ToolCallCompleted);
    }

    #[test]
    fn type_field_is_renamed() {
        let ev = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStarted, 0);
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["type"], "agent.started");
        assert!(v.get("event_type").is_none());
    }

    #[test]
    fn hash_link_is_stable_and_detects_tamper() {
        let mut ev = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::MemoryWrite, 3);
        ev.link_after(None);
        assert!(ev.hash_is_valid());
        let h1 = ev.event_hash.clone().unwrap();
        // recompute is identical
        assert_eq!(ev.compute_hash(), h1);
        // tamper: changing a field invalidates the stored hash
        ev.intent = Some("exfiltrate".into());
        assert!(!ev.hash_is_valid());
    }

    #[test]
    fn chaining_threads_prev_hash() {
        let mut a = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStarted, 0);
        a.link_after(None);
        let mut b = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStepStarted, 1);
        b.link_after(a.event_hash.clone());
        assert_eq!(b.prev_event_hash, a.event_hash);
        assert!(b.hash_is_valid());
    }
}
