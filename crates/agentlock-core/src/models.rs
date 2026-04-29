use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Genome {
    pub schema_version: u32,
    pub agent: AgentMetadata,
    pub model: ModelConfig,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub knowledge_snapshots: Vec<KnowledgeSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelConfig {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolSpec {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeSnapshot {
    pub id: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentLock {
    pub schema_version: u32,
    pub agent_id: String,
    pub behavior_contract_id: String,
    #[serde(default)]
    pub tracked_files: Vec<TrackedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackedFile {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorContract {
    pub schema_version: u32,
    pub contract: ContractDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractDefinition {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub checks: Vec<DeterministicCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeterministicCheck {
    RequireFinalOutput {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    RequiredToolCalls {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        tools: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_calls: Option<u32>,
    },
    ForbiddenToolCalls {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        tools: Vec<String>,
    },
    RequiredOutputContainsAll {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        values: Vec<String>,
    },
    ForbiddenOutputContainsAny {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        values: Vec<String>,
    },
    MaxToolCalls {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        max: u32,
    },
    MaxTotalEvents {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        max: u32,
    },
}

impl DeterministicCheck {
    pub fn id(&self) -> &str {
        match self {
            Self::RequireFinalOutput { id, .. }
            | Self::RequiredToolCalls { id, .. }
            | Self::ForbiddenToolCalls { id, .. }
            | Self::RequiredOutputContainsAll { id, .. }
            | Self::ForbiddenOutputContainsAny { id, .. }
            | Self::MaxToolCalls { id, .. }
            | Self::MaxTotalEvents { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventKind {
    UserMessage,
    AssistantOutput,
    ToolCall,
    ToolResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub trace_id: String,
    pub step: u32,
    pub event: TraceEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub root: PathBuf,
    pub genome: Genome,
    pub agent_lock: AgentLock,
    pub behavior_contract: BehaviorContract,
    pub prompts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayReport {
    pub report_version: u32,
    pub provider: String,
    pub bundle_hash: String,
    pub contract_id: String,
    pub generated_at: DateTime<Utc>,
    pub summary: ReplaySummary,
    pub runs: Vec<ReplayRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaySummary {
    pub runs_requested: u32,
    pub traces: usize,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub contract_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayRun {
    pub run_index: u32,
    pub trace_id: String,
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub id: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseAttestation {
    pub attestation_version: u32,
    pub bundle_hash: String,
    pub behavior_contract_id: String,
    pub generated_at: DateTime<Utc>,
    pub replay_summary: ReplaySummary,
    pub contract_result: String,
    pub replay_report_path: String,
    pub signature: Option<String>,
}
