//! Online drift detection.
//!
//! Drift detection compares live behaviour against a [`DriftBaseline`] derived
//! from the expected genome / lockfile / contract. It has two modes:
//!
//! * **deterministic** — hashes, model/config identifiers, tool names &
//!   permissions, policy IDs, memory schema versions, and workflow step IDs.
//!   This path is pure and always available.
//! * **behavioral** — output shape, intent class, tool-usage patterns. This is
//!   isolated behind the [`SemanticDriftProvider`] trait; when no provider is
//!   configured the detector still works (deterministic only) and emits no
//!   behavioral alerts.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::event::{TrackingEvent, TrackingEventType};

/// Which dimension of behaviour drifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    Prompt,
    ModelConfig,
    ToolPermission,
    Policy,
    MemorySchema,
    WorkflowTopology,
    OutputBehavior,
    Intent,
    ToolUsage,
}

impl DriftType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::ModelConfig => "model_config",
            Self::ToolPermission => "tool_permission",
            Self::Policy => "policy",
            Self::MemorySchema => "memory_schema",
            Self::WorkflowTopology => "workflow_topology",
            Self::OutputBehavior => "output_behavior",
            Self::Intent => "intent",
            Self::ToolUsage => "tool_usage",
        }
    }
}

/// Drift-detection toggles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DriftConfig {
    pub enabled: bool,
    /// Run the deterministic (hash/config/tool/policy) checks.
    pub deterministic: bool,
    /// Run behavioral checks (requires a [`SemanticDriftProvider`]).
    pub behavioral: bool,
    /// Absolute temperature delta tolerated before flagging model_config drift.
    pub temperature_tolerance: f64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deterministic: true,
            behavioral: false,
            temperature_tolerance: 0.0,
        }
    }
}

/// The expected behavioural envelope a session is tracked against.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DriftBaseline {
    #[serde(default)]
    pub genome_hash: Option<String>,
    #[serde(default)]
    pub prompt_hash: Option<String>,
    #[serde(default)]
    pub model_provider: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub allowed_tools: HashSet<String>,
    #[serde(default)]
    pub tool_permissions: HashMap<String, HashSet<String>>,
    #[serde(default)]
    pub policy_ids: HashSet<String>,
    #[serde(default)]
    pub memory_schema_version: Option<String>,
    #[serde(default)]
    pub workflow_steps: HashSet<String>,
}

fn str_field(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

impl DriftBaseline {
    /// Build a tolerant baseline from a genome or lockfile document.
    ///
    /// Recognises the common shapes of `genome.yaml` (`runtime.model_provider`,
    /// `tools[].name`, `policies[]`, `memory.runtime_memory_schema_version`)
    /// and `agent.lock.yaml` (`model.provider`, `model.model_id`,
    /// `tools[].permissions`, `memory.schema_version`). Anything absent stays
    /// `None`/empty and is simply not checked.
    pub fn from_genome_value(doc: &Value) -> Self {
        let mut b = DriftBaseline::default();

        if let Some(model) = doc.get("model") {
            b.model_provider = str_field(model, &["provider", "model_provider"]);
            b.model_id = str_field(model, &["model_id", "model"]);
            b.temperature = model.get("temperature").and_then(|t| t.as_f64());
        }
        if let Some(runtime) = doc.get("runtime") {
            b.model_provider = b
                .model_provider
                .or_else(|| str_field(runtime, &["model_provider", "provider"]));
            b.model_id = b
                .model_id
                .or_else(|| str_field(runtime, &["model_id", "model"]));
        }

        if let Some(tools) = doc.get("tools").and_then(|t| t.as_array()) {
            for t in tools {
                if let Some(name) = t.as_str() {
                    b.allowed_tools.insert(name.to_string());
                } else if let Some(name) = str_field(t, &["name", "id"]) {
                    let perms: HashSet<String> = t
                        .get("permissions")
                        .and_then(|p| p.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    if !perms.is_empty() {
                        b.tool_permissions.insert(name.clone(), perms);
                    }
                    b.allowed_tools.insert(name);
                }
            }
        }

        if let Some(policies) = doc.get("policies").and_then(|p| p.as_array()) {
            for p in policies {
                if let Some(id) = p.as_str() {
                    b.policy_ids.insert(id.to_string());
                } else if let Some(id) = str_field(p, &["id", "name", "policy_id"]) {
                    b.policy_ids.insert(id);
                }
            }
        }

        if let Some(memory) = doc.get("memory") {
            b.memory_schema_version = str_field(
                memory,
                &["runtime_memory_schema_version", "schema_version", "version"],
            );
        }

        for steps_key in ["steps", "workflow_steps"] {
            if let Some(steps) = doc.get(steps_key).and_then(|s| s.as_array()) {
                for s in steps {
                    if let Some(id) = s.as_str() {
                        b.workflow_steps.insert(id.to_string());
                    } else if let Some(id) = str_field(s, &["id", "name"]) {
                        b.workflow_steps.insert(id);
                    }
                }
            }
        }

        b.genome_hash = str_field(doc, &["genome_hash", "genome_version"]);
        b.prompt_hash = str_field(doc, &["prompt_hash", "prompt_version"]);
        b
    }
}

/// A behavioral drift verdict produced by a semantic provider.
pub struct BehavioralDrift {
    pub drift_type: DriftType,
    pub severity: AlertSeverity,
    pub message: String,
    pub observed: Value,
    pub expected: Value,
}

/// Pluggable semantic classifier for behavioral drift. Optional by design.
pub trait SemanticDriftProvider {
    fn classify(&self, ev: &TrackingEvent, baseline: &DriftBaseline) -> Option<BehavioralDrift>;
}

/// Stateful drift detector for one session.
pub struct DriftDetector {
    session_id: String,
    config: DriftConfig,
    baseline: DriftBaseline,
    provider: Option<Box<dyn SemanticDriftProvider + Send>>,
    alerted: HashSet<String>,
}

impl DriftDetector {
    pub fn new(
        session_id: impl Into<String>,
        config: DriftConfig,
        baseline: DriftBaseline,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            baseline,
            provider: None,
            alerted: HashSet::new(),
        }
    }

    /// Attach an optional behavioral classifier.
    pub fn with_provider(mut self, provider: Box<dyn SemanticDriftProvider + Send>) -> Self {
        self.provider = Some(provider);
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn raise(
        &mut self,
        key: String,
        drift_type: DriftType,
        mode: &str,
        severity: AlertSeverity,
        message: String,
        observed: Value,
        expected: Value,
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
                AlertKind::Drift,
                severity,
                format!("Drift detected: {}", drift_type.label()),
                message,
            )
            .with_evidence(evidence)
            .with_observed_expected(Some(observed.clone()), Some(expected.clone()))
            .with_gating(blocks, review)
            .with_action(
                "Compare the running release against the tracked baseline; if the change is intended, cut a new release and re-baseline, otherwise roll back.",
            )
            .with_details(serde_json::json!({
                "drift_type": drift_type.label(),
                "mode": mode,
                "observed": observed,
                "expected": expected,
            })),
        )
    }

    /// Fold one event into the detector; return any newly-detected drift alerts.
    pub fn observe(&mut self, ev: &TrackingEvent) -> Vec<Alert> {
        let mut out = Vec::new();
        if !self.config.enabled {
            return out;
        }
        if self.config.deterministic {
            self.deterministic(ev, &mut out);
        }
        if self.config.behavioral {
            if let Some(provider) = &self.provider {
                if let Some(bd) = provider.classify(ev, &self.baseline) {
                    let key = format!("behav:{}:{}", bd.drift_type.label(), ev.event_id);
                    if let Some(a) = self.raise(
                        key,
                        bd.drift_type,
                        "behavioral",
                        bd.severity,
                        bd.message,
                        bd.observed,
                        bd.expected,
                        vec![ev.event_id.clone()],
                        false,
                        bd.severity == AlertSeverity::Critical,
                    ) {
                        out.push(a);
                    }
                }
            }
        }
        out
    }

    fn deterministic(&mut self, ev: &TrackingEvent, out: &mut Vec<Alert>) {
        let eid = ev.event_id.clone();
        match ev.event_type {
            TrackingEventType::ToolCallStarted | TrackingEventType::ToolCallCompleted => {
                if let Some(tool) = &ev.tool {
                    if !self.baseline.allowed_tools.is_empty()
                        && !self.baseline.allowed_tools.contains(&tool.name)
                    {
                        let name = tool.name.clone();
                        if let Some(a) = self.raise(
                            format!("tool_perm:{name}"),
                            DriftType::ToolPermission,
                            "deterministic",
                            AlertSeverity::Critical,
                            format!("Tool '{name}' is not in the baseline's permitted tool set."),
                            serde_json::json!(name),
                            serde_json::json!(self
                                .baseline
                                .allowed_tools
                                .iter()
                                .collect::<Vec<_>>()),
                            vec![eid.clone()],
                            true,
                            true,
                        ) {
                            out.push(a);
                        }
                    } else if let Some(expected) = self.baseline.tool_permissions.get(&tool.name) {
                        let extra: Vec<String> = tool
                            .permissions
                            .iter()
                            .filter(|p| !expected.contains(*p))
                            .cloned()
                            .collect();
                        if !extra.is_empty() {
                            let name = tool.name.clone();
                            if let Some(a) = self.raise(
                                format!("tool_perm_extra:{name}"),
                                DriftType::ToolPermission,
                                "deterministic",
                                AlertSeverity::Critical,
                                format!(
                                    "Tool '{name}' requested permissions outside its baseline grant: {extra:?}."
                                ),
                                serde_json::json!(extra),
                                serde_json::json!(expected.iter().collect::<Vec<_>>()),
                                vec![eid.clone()],
                                true,
                                true,
                            ) {
                                out.push(a);
                            }
                        }
                    }
                }
            }
            TrackingEventType::ModelCallStarted | TrackingEventType::ModelCallCompleted => {
                if let Some(model) = &ev.model {
                    if let Some(bp) = &self.baseline.model_provider {
                        if !model.provider.is_empty() && &model.provider != bp {
                            if let Some(a) = self.raise(
                                "model_provider".into(),
                                DriftType::ModelConfig,
                                "deterministic",
                                AlertSeverity::Warning,
                                format!(
                                    "Model provider changed from '{bp}' to '{}'.",
                                    model.provider
                                ),
                                serde_json::json!(model.provider),
                                serde_json::json!(bp),
                                vec![eid.clone()],
                                false,
                                true,
                            ) {
                                out.push(a);
                            }
                        }
                    }
                    if let Some(bm) = &self.baseline.model_id {
                        if !model.model.is_empty() && &model.model != bm {
                            if let Some(a) = self.raise(
                                "model_id".into(),
                                DriftType::ModelConfig,
                                "deterministic",
                                AlertSeverity::Warning,
                                format!("Model changed from '{bm}' to '{}'.", model.model),
                                serde_json::json!(model.model),
                                serde_json::json!(bm),
                                vec![eid.clone()],
                                false,
                                true,
                            ) {
                                out.push(a);
                            }
                        }
                    }
                    if let (Some(bt), Some(mt)) = (self.baseline.temperature, model.temperature) {
                        if (bt - mt).abs() > self.config.temperature_tolerance {
                            if let Some(a) = self.raise(
                                "model_temp".into(),
                                DriftType::ModelConfig,
                                "deterministic",
                                AlertSeverity::Warning,
                                format!("Temperature changed from {bt} to {mt}."),
                                serde_json::json!(mt),
                                serde_json::json!(bt),
                                vec![eid.clone()],
                                false,
                                false,
                            ) {
                                out.push(a);
                            }
                        }
                    }
                }
                // prompt drift travels on model events' metadata.prompt_hash
                if let (Some(bp), Some(ph)) = (
                    &self.baseline.prompt_hash,
                    ev.metadata
                        .as_ref()
                        .and_then(|m| m.get("prompt_hash"))
                        .and_then(|p| p.as_str()),
                ) {
                    if bp != ph {
                        if let Some(a) = self.raise(
                            "prompt".into(),
                            DriftType::Prompt,
                            "deterministic",
                            AlertSeverity::Warning,
                            "System prompt hash differs from the tracked baseline.".into(),
                            serde_json::json!(ph),
                            serde_json::json!(bp),
                            vec![eid.clone()],
                            false,
                            true,
                        ) {
                            out.push(a);
                        }
                    }
                }
            }
            TrackingEventType::PolicyEvaluated => {
                if let Some(pr) = &ev.policy_result {
                    if let Some(pid) = &pr.policy_id {
                        if !self.baseline.policy_ids.is_empty()
                            && !self.baseline.policy_ids.contains(pid)
                        {
                            let pid = pid.clone();
                            if let Some(a) = self.raise(
                                format!("policy:{pid}"),
                                DriftType::Policy,
                                "deterministic",
                                AlertSeverity::Warning,
                                format!("Policy '{pid}' is not part of the tracked baseline."),
                                serde_json::json!(pid),
                                serde_json::json!(self
                                    .baseline
                                    .policy_ids
                                    .iter()
                                    .collect::<Vec<_>>()),
                                vec![eid.clone()],
                                false,
                                true,
                            ) {
                                out.push(a);
                            }
                        }
                    }
                }
            }
            TrackingEventType::MemoryRead | TrackingEventType::MemoryWrite => {
                if let (Some(bv), Some(sv)) = (
                    &self.baseline.memory_schema_version,
                    ev.metadata
                        .as_ref()
                        .and_then(|m| m.get("schema_version"))
                        .and_then(|s| s.as_str()),
                ) {
                    if bv != sv {
                        if let Some(a) = self.raise(
                            "memory_schema".into(),
                            DriftType::MemorySchema,
                            "deterministic",
                            AlertSeverity::Warning,
                            format!("Memory schema version changed from '{bv}' to '{sv}'."),
                            serde_json::json!(sv),
                            serde_json::json!(bv),
                            vec![eid.clone()],
                            false,
                            true,
                        ) {
                            out.push(a);
                        }
                    }
                }
            }
            TrackingEventType::AgentStepStarted => {
                if let Some(step) = &ev.workflow_step_id {
                    if !self.baseline.workflow_steps.is_empty()
                        && !self.baseline.workflow_steps.contains(step)
                    {
                        let step = step.clone();
                        if let Some(a) = self.raise(
                            format!("workflow:{step}"),
                            DriftType::WorkflowTopology,
                            "deterministic",
                            AlertSeverity::Warning,
                            format!("Workflow step '{step}' is not in the baseline topology."),
                            serde_json::json!(step),
                            serde_json::json!(self
                                .baseline
                                .workflow_steps
                                .iter()
                                .collect::<Vec<_>>()),
                            vec![eid.clone()],
                            false,
                            false,
                        ) {
                            out.push(a);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ModelMeta, ToolMeta};

    fn baseline() -> DriftBaseline {
        let mut b = DriftBaseline::default();
        b.allowed_tools.insert("claims_db.lookup".into());
        b.model_provider = Some("openai".into());
        b.model_id = Some("gpt-4o".into());
        b.policy_ids.insert("pii_guard".into());
        b
    }

    fn detector() -> DriftDetector {
        DriftDetector::new("s1", DriftConfig::default(), baseline())
    }

    #[test]
    fn from_genome_value_extracts_fields() {
        let doc = serde_json::json!({
            "runtime": { "model_provider": "openai", "model_id": "gpt-4o" },
            "tools": [{ "name": "search", "permissions": ["read"] }],
            "policies": [{ "id": "pii_guard" }],
            "memory": { "runtime_memory_schema_version": "1.2.0" }
        });
        let b = DriftBaseline::from_genome_value(&doc);
        assert_eq!(b.model_provider.as_deref(), Some("openai"));
        assert!(b.allowed_tools.contains("search"));
        assert!(b.policy_ids.contains("pii_guard"));
        assert_eq!(b.memory_schema_version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn unauthorized_tool_is_critical_drift() {
        let mut d = detector();
        let mut e =
            TrackingEvent::new("s1", "agent://a/b", TrackingEventType::ToolCallCompleted, 0);
        e.tool = Some(ToolMeta {
            name: "shell.exec".into(),
            ..Default::default()
        });
        let alerts = d.observe(&e);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(
            alerts[0].details.as_ref().unwrap()["drift_type"],
            "tool_permission"
        );
        assert!(alerts[0].blocks_release);
    }

    #[test]
    fn permitted_tool_does_not_drift() {
        let mut d = detector();
        let mut e =
            TrackingEvent::new("s1", "agent://a/b", TrackingEventType::ToolCallCompleted, 0);
        e.tool = Some(ToolMeta {
            name: "claims_db.lookup".into(),
            ..Default::default()
        });
        assert!(d.observe(&e).is_empty());
    }

    #[test]
    fn model_swap_is_model_config_drift() {
        let mut d = detector();
        let mut e = TrackingEvent::new(
            "s1",
            "agent://a/b",
            TrackingEventType::ModelCallCompleted,
            0,
        );
        e.model = Some(ModelMeta {
            provider: "anthropic".into(),
            model: "claude-3".into(),
            ..Default::default()
        });
        let alerts = d.observe(&e);
        assert!(alerts
            .iter()
            .any(|a| a.details.as_ref().unwrap()["drift_type"] == "model_config"));
    }

    #[test]
    fn empty_baseline_dimension_is_not_checked() {
        // Baseline with no tools => no tool drift even for unknown tools.
        let mut d = DriftDetector::new("s1", DriftConfig::default(), DriftBaseline::default());
        let mut e =
            TrackingEvent::new("s1", "agent://a/b", TrackingEventType::ToolCallCompleted, 0);
        e.tool = Some(ToolMeta {
            name: "anything".into(),
            ..Default::default()
        });
        assert!(d.observe(&e).is_empty());
    }
}
