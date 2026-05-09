//! Embedded JSON Schemas for the Agenomic spec, plus version negotiation.
//!
//! Schemas live as JSON files under `schemas/` at the workspace root and are
//! `include_str!`'d into the binary so the CLI works fully offline.

use agenomic_core::{CliError, CliResult};

/// Spec versions this CLI build understands.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["0.1"];
/// Default spec version emitted by `agenomic init`.
pub const CURRENT_SPEC_VERSION: &str = "0.1";

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
        }
    }

    /// All embedded schema kinds.
    pub const ALL: [Self; 7] = [
        Self::Genome,
        Self::Agenomic,
        Self::BehaviorContract,
        Self::TraceEvent,
        Self::ReplayReport,
        Self::ReleaseAttestation,
        Self::AtepEvent,
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
    SUPPORTED_SPEC_VERSIONS.iter().any(|v| *v == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_schemas_parse() {
        for kind in SchemaKind::ALL {
            let s = embedded_schema(kind);
            let _: serde_json::Value =
                serde_json::from_str(s).expect(&format!("schema {} not valid JSON", kind.label()));
        }
    }

    #[test]
    fn all_validators_compile() {
        for kind in SchemaKind::ALL {
            let _ = validator(kind).expect(&format!("compile failed for {}", kind.label()));
        }
    }

    #[test]
    fn detect_version_basic() {
        let yaml = "spec_version: '0.1'\n";
        assert_eq!(detect_spec_version(yaml).unwrap(), "0.1");
        assert!(is_supported("0.1"));
        assert!(!is_supported("9.9"));
    }

    #[test]
    fn empty_object_rejected_for_genome() {
        let v = validator(SchemaKind::Genome).unwrap();
        let value: serde_json::Value = serde_json::json!({});
        assert!(v.validate(&value).is_err());
    }
}
