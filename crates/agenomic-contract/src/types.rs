//! Shared types: trace envelope, contract, evaluation report.

use std::collections::BTreeMap;

use agenomic_core::Severity;
use serde::{Deserialize, Serialize};

/// One trace (one input → one output, with intermediate tool calls).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEnvelope {
    pub trace_id: String,
    pub agent_id: String,
    pub input: serde_json::Value,
    #[serde(default)]
    pub output: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub human_approval_present: Option<bool>,
}

/// Parsed behavior contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorContract {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    pub rules: Vec<ContractRule>,
}

/// One rule from a behavior contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRule {
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub severity: Severity,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub forbidden_tools: Vec<String>,
    #[serde(default)]
    pub sensitive_tools: Vec<String>,
    #[serde(default)]
    pub output_format: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Result of running a single check on a single trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckResult {
    pub check_id: String,
    pub passed: bool,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_message: Option<String>,
}

/// One violation, scoped to a particular trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceViolation {
    pub trace_id: String,
    pub check_id: String,
    pub severity: Severity,
    pub message: String,
}

/// Aggregated outcome for an entire contract evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractEvaluation {
    pub contract_id: String,
    pub total_traces: usize,
    pub passed: bool,
    pub violations_by_check: BTreeMap<String, Vec<TraceViolation>>,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
}
