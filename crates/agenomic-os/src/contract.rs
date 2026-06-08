//! Rust mapping of the `execution:` block introduced in spec 0.2.
//!
//! [`ExecutionContract::from_genome_yaml`] parses a YAML genome string and
//! extracts the execution block. Bundles without an `execution:` block
//! produce [`OsError::ContractMissing`]; malformed blocks produce
//! [`OsError::ContractInvalid`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{OsError, OsResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContract {
    pub entrypoint: Entrypoint,
    pub runtime: RuntimeSpec,
    #[serde(default = "default_working_directory")]
    pub working_directory: String,
    #[serde(default)]
    pub env: EnvSpec,
    #[serde(default)]
    pub permissions: PermissionsSpec,
}

fn default_working_directory() -> String {
    ".".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entrypoint {
    pub kind: EntrypointKind,
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointKind {
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSpec {
    pub kind: RuntimeKind,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Python,
    Node,
    Rust,
    Binary,
}

impl RuntimeKind {
    pub fn label(self) -> &'static str {
        match self {
            RuntimeKind::Python => "python",
            RuntimeKind::Node => "node",
            RuntimeKind::Rust => "rust",
            RuntimeKind::Binary => "binary",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSpec {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionsSpec {
    #[serde(default)]
    pub filesystem: FilesystemPermissions,
    #[serde(default)]
    pub network: NetworkPermissions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPermissions {
    #[serde(default)]
    pub read: Vec<PathBuf>,
    #[serde(default)]
    pub write: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
}

impl ExecutionContract {
    /// Parse a genome YAML document and extract the `execution:` block.
    ///
    /// Returns [`OsError::ContractMissing`] when no block is present, and
    /// [`OsError::ContractInvalid`] when present but malformed.
    pub fn from_genome_yaml(yaml: &str) -> OsResult<Self> {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| {
            OsError::ContractInvalid {
                reason: format!("genome.yaml is not valid YAML: {e}"),
            }
        })?;
        let exec = v
            .get("execution")
            .ok_or(OsError::ContractMissing)?
            .clone();
        let contract: ExecutionContract = serde_yaml::from_value(exec).map_err(|e| {
            OsError::ContractInvalid {
                reason: format!("execution block: {e}"),
            }
        })?;
        contract.validate()?;
        Ok(contract)
    }

    /// Cross-field validation beyond what serde enforces.
    fn validate(&self) -> OsResult<()> {
        if matches!(self.entrypoint.kind, EntrypointKind::Command)
            && self.entrypoint.command.as_deref().unwrap_or("").is_empty()
        {
            return Err(OsError::ContractInvalid {
                reason: "entrypoint.command must be set when kind = command".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_GENOME: &str = r#"
spec_version: '0.2'
agent:
  id: 'agent://acme/foo'
  name: 'Foo'
  domain: 'general'
  criticality: 'low'
runtime:
  model_provider: 'openai'
  model_id: 'gpt-4o'
tools: []
skills: []
knowledge: []
policies: []
execution:
  entrypoint:
    kind: command
    command: python
    args: ["-m", "codedrift.agent"]
  runtime:
    kind: python
    version: ">=3.11,<3.13"
  working_directory: "."
  env:
    required: [OPENAI_API_KEY]
    optional: []
  permissions:
    filesystem:
      read: ["."]
      write: ["./.agenomic/runs"]
    network:
      allow: []
"#;

    #[test]
    fn parses_full_contract() {
        let c = ExecutionContract::from_genome_yaml(FULL_GENOME).unwrap();
        assert_eq!(c.entrypoint.kind, EntrypointKind::Command);
        assert_eq!(c.entrypoint.command.as_deref(), Some("python"));
        assert_eq!(c.entrypoint.args, vec!["-m", "codedrift.agent"]);
        assert_eq!(c.runtime.kind, RuntimeKind::Python);
        assert_eq!(c.runtime.version.as_deref(), Some(">=3.11,<3.13"));
        assert_eq!(c.working_directory, ".");
        assert_eq!(c.env.required, vec!["OPENAI_API_KEY"]);
        assert!(c.permissions.network.allow.is_empty());
    }

    #[test]
    fn missing_block_yields_contract_missing() {
        let yaml = "spec_version: '0.1'\nagent: {id: 'agent://a/b'}\n";
        let err = ExecutionContract::from_genome_yaml(yaml).unwrap_err();
        assert!(matches!(err, OsError::ContractMissing));
    }

    #[test]
    fn missing_entrypoint_yields_invalid() {
        let yaml = r#"
execution:
  runtime:
    kind: python
"#;
        let err = ExecutionContract::from_genome_yaml(yaml).unwrap_err();
        assert!(matches!(err, OsError::ContractInvalid { .. }));
    }

    #[test]
    fn unsupported_runtime_kind_rejected() {
        let yaml = r#"
execution:
  entrypoint:
    kind: command
    command: foo
  runtime:
    kind: haskell
"#;
        let err = ExecutionContract::from_genome_yaml(yaml).unwrap_err();
        assert!(matches!(err, OsError::ContractInvalid { .. }));
    }

    #[test]
    fn defaults_apply() {
        let yaml = r#"
execution:
  entrypoint:
    kind: command
    command: python
  runtime:
    kind: python
"#;
        let c = ExecutionContract::from_genome_yaml(yaml).unwrap();
        assert_eq!(c.working_directory, ".");
        assert!(c.env.required.is_empty());
        assert!(c.permissions.filesystem.read.is_empty());
        assert!(c.permissions.network.allow.is_empty());
    }

    #[test]
    fn empty_command_rejected() {
        let yaml = r#"
execution:
  entrypoint:
    kind: command
    command: ""
  runtime:
    kind: python
"#;
        let err = ExecutionContract::from_genome_yaml(yaml).unwrap_err();
        assert!(matches!(err, OsError::ContractInvalid { .. }));
    }
}
