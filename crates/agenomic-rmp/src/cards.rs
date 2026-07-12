//! Agent ID Card and Use Case Card — the human-authored context Review
//! evaluates an agent against.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::RMP_SPEC_VERSION;

/// A concise identity card for an agent: who it is, what it may do, and how
/// autonomous it is allowed to be. Complements the genome; it never replaces
/// the lockfile as the source of truth for pinned dependencies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentIdCard {
    pub spec_version: String,
    /// Canonical agent URI (`agent://org/name`).
    pub agent_id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    /// Business domain, e.g. `insurance-claims`, `customer-support`.
    #[serde(default)]
    pub domain: String,
    /// `assistant` | `workflow` | `autonomous` | `tool` | `orchestrator`.
    #[serde(default)]
    pub agent_type: String,
    /// `low` | `medium` | `high` | `critical` business criticality.
    #[serde(default)]
    pub criticality: String,
    /// Tools the agent is allowed to call.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Actions that must never happen (feeds forbidden-behavior checks).
    #[serde(default)]
    pub forbidden_actions: Vec<String>,
    /// Whether the agent may act without a human in the loop.
    #[serde(default)]
    pub autonomous: bool,
    /// Steps that always require human approval.
    #[serde(default)]
    pub human_approval_required_for: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_team: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

impl AgentIdCard {
    pub fn new(agent_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            agent_id: agent_id.into(),
            display_name: display_name.into(),
            description: String::new(),
            domain: String::new(),
            agent_type: String::new(),
            criticality: String::new(),
            allowed_tools: Vec::new(),
            forbidden_actions: Vec::new(),
            autonomous: false,
            human_approval_required_for: Vec::new(),
            genome_hash: None,
            owner_team: None,
            created_at: Some(Utc::now()),
        }
    }

    /// Derive a card from a parsed `genome.yaml` value. Best-effort: absent
    /// fields stay empty and can be filled by hand.
    pub fn from_genome_value(agent_id: &str, genome: &serde_json::Value) -> Self {
        let s = |path: &[&str]| -> String {
            let mut v = genome;
            for p in path {
                match v.get(p) {
                    Some(next) => v = next,
                    None => return String::new(),
                }
            }
            v.as_str().unwrap_or_default().to_string()
        };
        let mut card = Self::new(agent_id, s(&["agent", "name"]));
        if card.display_name.is_empty() {
            card.display_name = agent_id.to_string();
        }
        card.description = s(&["agent", "description"]);
        card.domain = s(&["agent", "domain"]);
        card.criticality = s(&["agent", "criticality"]);
        if let Some(tools) = genome
            .get("tools")
            .and_then(|t| t.as_array())
            .or_else(|| genome.pointer("/capabilities/tools").and_then(|t| t.as_array()))
        {
            for t in tools {
                let name = t
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| t.get("name").and_then(|n| n.as_str()).map(str::to_string));
                if let Some(name) = name {
                    card.allowed_tools.push(name);
                }
            }
        }
        card
    }
}

/// A use case the agent is deployed for: what it should achieve, its
/// boundaries, and the outcomes that count as success or failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UseCaseCard {
    pub spec_version: String,
    pub use_case_id: String,
    pub agent_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Intents the agent is expected to serve in this use case.
    #[serde(default)]
    pub expected_intents: Vec<String>,
    /// Intents that must never occur (feeds intent-boundary checks).
    #[serde(default)]
    pub forbidden_intents: Vec<String>,
    /// Workflow steps involved.
    #[serde(default)]
    pub workflow_step_ids: Vec<String>,
    /// What success looks like, in operator terms.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// What failure looks like (each maps naturally to a risk item).
    #[serde(default)]
    pub failure_modes: Vec<String>,
    /// Data sensitivity: `public` | `internal` | `confidential` | `pii`.
    #[serde(default)]
    pub data_sensitivity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

impl UseCaseCard {
    pub fn new(agent_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            spec_version: RMP_SPEC_VERSION.into(),
            use_case_id: format!("uc_{}", ulid::Ulid::new()),
            agent_id: agent_id.into(),
            title: title.into(),
            description: String::new(),
            expected_intents: Vec::new(),
            forbidden_intents: Vec::new(),
            workflow_step_ids: Vec::new(),
            success_criteria: Vec::new(),
            failure_modes: Vec::new(),
            data_sensitivity: String::new(),
            created_at: Some(Utc::now()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_card_from_genome() {
        let genome: serde_json::Value = serde_yaml::from_str(
            r#"
agent:
  name: Claims Agent
  domain: insurance
  criticality: high
tools:
  - name: claims_db.lookup
  - name: payments.refund
"#,
        )
        .unwrap();
        let card = AgentIdCard::from_genome_value("agent://acme/claims", &genome);
        assert_eq!(card.display_name, "Claims Agent");
        assert_eq!(card.domain, "insurance");
        assert_eq!(
            card.allowed_tools,
            vec!["claims_db.lookup".to_string(), "payments.refund".to_string()]
        );
    }
}
