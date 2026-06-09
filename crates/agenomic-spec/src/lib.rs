//! Embedded JSON Schemas for the Agenomic spec, plus version negotiation.
//!
//! Schemas live as JSON files under `schemas/` at the workspace root and are
//! `include_str!`'d into the binary so the CLI works fully offline.

use agenomic_core::{CliError, CliResult};

/// Spec versions this CLI build understands.
///
/// `0.2` is additive over `0.1`: it introduces the optional top-level
/// `execution` block (genome) and `execution_hash` field (agent.lock), both
/// consumed by `agenomic-os`, plus the `workflow.yaml` and `system.yaml`
/// manifests for workflows and multi-agent systems (RFC 0009). Documents
/// declaring `spec_version: 0.1` remain valid and unchanged.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["0.1", "0.2"];
/// Default spec version emitted by `agenomic init`.
///
/// Stays at `0.1` until a dedicated migration PR updates fixtures, examples,
/// and snapshots. See `docs/BACKEND_GAPS.md`.
pub const CURRENT_SPEC_VERSION: &str = "0.1";

/// Version stamped into detection provenance as `detector_version`.
///
/// This equals the `agenomic-spec` crate version (not the binary version), so
/// two `agm` builds at the same spec version produce byte-identical detection
/// output (see `docs/init-and-update.md` §2.7).
///
/// ```
/// assert!(!agenomic_spec::DETECTOR_VERSION.is_empty());
/// ```
pub const DETECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Identifier for one of the embedded schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaKind {
    Genome,
    Agenomic,
    BehaviorContract,
    TraceEvent,
    ReplayReport,
    ReleaseAttestation,
    AtepEvent,
    Workflow,
    System,
}

impl SchemaKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Genome => "genome",
            Self::Agenomic => "agenomic",
            Self::BehaviorContract => "behavior-contract",
            Self::TraceEvent => "trace-event",
            Self::ReplayReport => "replay-report",
            Self::ReleaseAttestation => "release-attestation",
            Self::AtepEvent => "atep-event",
            Self::Workflow => "workflow",
            Self::System => "system",
        }
    }

    /// All embedded schema kinds.
    pub const ALL: [Self; 9] = [
        Self::Genome,
        Self::Agenomic,
        Self::BehaviorContract,
        Self::TraceEvent,
        Self::ReplayReport,
        Self::ReleaseAttestation,
        Self::AtepEvent,
        Self::Workflow,
        Self::System,
    ];
}

const GENOME_SCHEMA: &str = include_str!("../../../schemas/genome.schema.json");
const AGENT_LOCK_SCHEMA: &str = include_str!("../../../schemas/agent-lock.schema.json");
const BEHAVIOR_CONTRACT_SCHEMA: &str =
    include_str!("../../../schemas/behavior-contract.schema.json");
const TRACE_EVENT_SCHEMA: &str = include_str!("../../../schemas/trace-event.schema.json");
const REPLAY_REPORT_SCHEMA: &str = include_str!("../../../schemas/replay-report.schema.json");
const RELEASE_ATTESTATION_SCHEMA: &str =
    include_str!("../../../schemas/release-attestation.schema.json");
const ATEP_EVENT_SCHEMA: &str = include_str!("../../../schemas/atep-event.schema.json");
const WORKFLOW_SCHEMA: &str = include_str!("../../../schemas/workflow.schema.json");
const SYSTEM_SCHEMA: &str = include_str!("../../../schemas/system.schema.json");

/// Return the raw JSON text of an embedded schema.
///
/// ```
/// let s = agenomic_spec::embedded_schema(agenomic_spec::SchemaKind::Genome);
/// assert!(s.contains("Agenomic Genome"));
/// ```
pub fn embedded_schema(kind: SchemaKind) -> &'static str {
    match kind {
        SchemaKind::Genome => GENOME_SCHEMA,
        SchemaKind::Agenomic => AGENT_LOCK_SCHEMA,
        SchemaKind::BehaviorContract => BEHAVIOR_CONTRACT_SCHEMA,
        SchemaKind::TraceEvent => TRACE_EVENT_SCHEMA,
        SchemaKind::ReplayReport => REPLAY_REPORT_SCHEMA,
        SchemaKind::ReleaseAttestation => RELEASE_ATTESTATION_SCHEMA,
        SchemaKind::AtepEvent => ATEP_EVENT_SCHEMA,
        SchemaKind::Workflow => WORKFLOW_SCHEMA,
        SchemaKind::System => SYSTEM_SCHEMA,
    }
}

/// Compile and return a JSON Schema validator for the given kind.
///
/// ```no_run
/// let _ = agenomic_spec::validator(agenomic_spec::SchemaKind::Genome).unwrap();
/// ```
pub fn validator(kind: SchemaKind) -> CliResult<jsonschema::JSONSchema> {
    let raw = embedded_schema(kind);
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| CliError::Schema(format!("schema parse: {e}")))?;
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&value)
        .map_err(|e| CliError::Schema(format!("schema compile: {e}")))
}

/// Detect the `spec_version` declared in a YAML genome (or any document with a
/// top-level `spec_version` string).
pub fn detect_spec_version(yaml_text: &str) -> CliResult<String> {
    let v: serde_yaml::Value =
        serde_yaml::from_str(yaml_text).map_err(|e| CliError::Schema(format!("yaml: {e}")))?;
    let spec_version = v
        .get("spec_version")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CliError::Schema("missing top-level `spec_version`".into()))?;
    Ok(spec_version.to_string())
}

/// Returns true if `version` is one of [`SUPPORTED_SPEC_VERSIONS`].
pub fn is_supported(version: &str) -> bool {
    SUPPORTED_SPEC_VERSIONS.contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_schemas_parse() {
        for kind in SchemaKind::ALL {
            let s = embedded_schema(kind);
            let _: serde_json::Value = serde_json::from_str(s)
                .unwrap_or_else(|e| panic!("schema {} not valid JSON: {e}", kind.label()));
        }
    }

    #[test]
    fn all_validators_compile() {
        for kind in SchemaKind::ALL {
            let _ = validator(kind)
                .unwrap_or_else(|e| panic!("compile failed for {}: {e}", kind.label()));
        }
    }

    #[test]
    fn detect_version_basic() {
        let yaml = "spec_version: '0.1'\n";
        assert_eq!(detect_spec_version(yaml).unwrap(), "0.1");
        assert!(is_supported("0.1"));
        assert!(is_supported("0.2"));
        assert!(!is_supported("9.9"));
    }

    #[test]
    fn empty_object_rejected_for_genome() {
        let v = validator(SchemaKind::Genome).unwrap();
        let value: serde_json::Value = serde_json::json!({});
        assert!(v.validate(&value).is_err());
    }

    fn minimal_genome_v2_with_execution() -> serde_json::Value {
        serde_json::json!({
            "spec_version": "0.2",
            "agent": {
                "id": "agent://acme/foo",
                "name": "Foo",
                "domain": "general",
                "criticality": "low"
            },
            "runtime": {
                "model_provider": "openai",
                "model_id": "gpt-4o"
            },
            "tools": [],
            "skills": [],
            "knowledge": [],
            "policies": [],
            "execution": {
                "entrypoint": {
                    "kind": "command",
                    "command": "python",
                    "args": ["-m", "codedrift.agent"]
                },
                "runtime": {
                    "kind": "python",
                    "version": ">=3.11,<3.13"
                },
                "working_directory": ".",
                "env": {
                    "required": ["OPENAI_API_KEY"],
                    "optional": []
                },
                "permissions": {
                    "filesystem": {
                        "read": ["."],
                        "write": ["./.agenomic/runs"]
                    },
                    "network": {
                        "allow": []
                    }
                }
            }
        })
    }

    #[test]
    fn genome_v2_with_execution_block_accepted() {
        let v = validator(SchemaKind::Genome).unwrap();
        let value = minimal_genome_v2_with_execution();
        assert!(
            v.validate(&value).is_ok(),
            "0.2 genome with execution block should validate"
        );
    }

    #[test]
    fn genome_v01_without_execution_still_accepted() {
        let v = validator(SchemaKind::Genome).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.1",
            "agent": {
                "id": "agent://acme/foo",
                "name": "Foo",
                "domain": "general",
                "criticality": "low"
            },
            "runtime": { "model_provider": "openai", "model_id": "gpt-4o" },
            "tools": [],
            "skills": [],
            "knowledge": [],
            "policies": []
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn genome_execution_requires_entrypoint_and_runtime() {
        let v = validator(SchemaKind::Genome).unwrap();
        let mut value = minimal_genome_v2_with_execution();
        value["execution"]
            .as_object_mut()
            .unwrap()
            .remove("entrypoint");
        assert!(
            v.validate(&value).is_err(),
            "execution missing entrypoint must be rejected"
        );
    }

    #[test]
    fn genome_execution_entrypoint_kind_accepts_docker_and_wasm() {
        let v = validator(SchemaKind::Genome).unwrap();
        for kind in ["docker", "wasm"] {
            let mut value = minimal_genome_v2_with_execution();
            value["execution"]["entrypoint"]["kind"] = serde_json::json!(kind);
            assert!(
                v.validate(&value).is_ok(),
                "{kind} must be a valid entrypoint kind"
            );
        }
    }

    #[test]
    fn genome_execution_entrypoint_kind_rejects_unknown_values() {
        let v = validator(SchemaKind::Genome).unwrap();
        let mut value = minimal_genome_v2_with_execution();
        value["execution"]["entrypoint"]["kind"] = serde_json::json!("haskell");
        assert!(v.validate(&value).is_err());
    }

    #[test]
    fn genome_execution_runtime_kind_restricted() {
        let v = validator(SchemaKind::Genome).unwrap();
        let mut value = minimal_genome_v2_with_execution();
        value["execution"]["runtime"]["kind"] = serde_json::json!("haskell");
        assert!(v.validate(&value).is_err());
    }

    #[test]
    fn agent_lock_v2_with_execution_hash_accepted() {
        let v = validator(SchemaKind::Agenomic).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "agent_id": "agent://acme/foo",
            "model": { "provider": "openai", "model_id": "gpt-4o" },
            "tools": [],
            "knowledge": [],
            "execution_hash": "blake3:abc123def456"
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn agent_lock_v01_without_execution_hash_still_accepted() {
        let v = validator(SchemaKind::Agenomic).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.1",
            "agent_id": "agent://acme/foo",
            "model": { "provider": "openai", "model_id": "gpt-4o" },
            "tools": [],
            "knowledge": []
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn minimal_workflow_accepted() {
        let v = validator(SchemaKind::Workflow).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "workflow": { "id": "workflow://acme/flow", "name": "Flow" },
            "steps": [
                { "id": "answer", "type": "agent", "agent": "agent://acme/foo" }
            ]
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn workflow_spec_repo_version_string_accepted() {
        let v = validator(SchemaKind::Workflow).unwrap();
        let value = serde_json::json!({
            "spec_version": "agenomic/v0.2",
            "workflow": { "id": "workflow://acme/flow", "name": "Flow" },
            "steps": [
                { "id": "gate", "type": "human", "gate": { "role": "handler" } }
            ]
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn workflow_agent_step_requires_agent_ref() {
        let v = validator(SchemaKind::Workflow).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "workflow": { "id": "workflow://acme/flow", "name": "Flow" },
            "steps": [ { "id": "answer", "type": "agent" } ]
        });
        assert!(v.validate(&value).is_err());
    }

    #[test]
    fn workflow_missing_steps_rejected() {
        let v = validator(SchemaKind::Workflow).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "workflow": { "id": "workflow://acme/flow", "name": "Flow" }
        });
        assert!(v.validate(&value).is_err());
    }

    #[test]
    fn minimal_system_accepted() {
        let v = validator(SchemaKind::System).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "system": { "id": "system://acme/orchestra", "name": "Orchestra" },
            "agents": [ { "role": "solo", "id": "agent://acme/foo" } ],
            "orchestration": { "style": "pipeline", "entrypoint": "solo" }
        });
        assert!(v.validate(&value).is_ok());
    }

    #[test]
    fn system_unknown_orchestration_style_rejected() {
        let v = validator(SchemaKind::System).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "system": { "id": "system://acme/orchestra", "name": "Orchestra" },
            "agents": [ { "role": "solo", "id": "agent://acme/foo" } ],
            "orchestration": { "style": "anarchy" }
        });
        assert!(v.validate(&value).is_err());
    }

    #[test]
    fn system_missing_agents_rejected() {
        let v = validator(SchemaKind::System).unwrap();
        let value = serde_json::json!({
            "spec_version": "0.2",
            "system": { "id": "system://acme/orchestra", "name": "Orchestra" },
            "orchestration": { "style": "graph" }
        });
        assert!(v.validate(&value).is_err());
    }
}
