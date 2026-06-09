//! Runtime policy derived from an [`ExecutionContract`].
//!
//! At MVP, the policy is enforced at the spec level (env filtering, working
//! directory, declared permissions in the trace) — there is no kernel-level
//! sandbox. See `docs/BACKEND_GAPS.md` "Sandbox hardening".
//!
//! What is enforced today:
//! - **Required env**: every `execution.env.required` entry MUST be present
//!   in the parent process or in `additional_env`. Missing entries fail
//!   with [`OsError::MissingRequiredEnv`] before the child is spawned.
//! - **Env filtering**: only declared (required ∪ optional) env vars plus
//!   `additional_env` overrides reach the child. The parent's full
//!   environment is NOT propagated.
//! - **Working directory**: the launcher uses
//!   `bundle_path.join(contract.working_directory)`, never the caller's
//!   `cwd`.
//!
//! What is recorded but NOT enforced at MVP (advisory only):
//! - filesystem allow-lists
//! - network allow-lists, including any `--allow-network HOST` overrides
//!
//! These appear in the trace so a reviewer can see what was declared, but
//! the kernel does not prevent the child from accessing other resources.

use std::collections::BTreeMap;

use crate::contract::ExecutionContract;
use crate::error::{OsError, OsResult};

/// Materialized policy ready to feed the launcher.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Network allow-list (declared + `--allow-network` overrides). Advisory
    /// at MVP.
    pub allow_network: Vec<String>,
    /// Filesystem read allow-list (advisory at MVP).
    pub allow_fs_read: Vec<std::path::PathBuf>,
    /// Filesystem write allow-list (advisory at MVP).
    pub allow_fs_write: Vec<std::path::PathBuf>,
    /// Extra environment variables merged into the child. Wins over the
    /// parent process when a key collides.
    pub additional_env: BTreeMap<String, String>,
}

impl Policy {
    /// Build a default policy that mirrors what the contract declares.
    pub fn from_contract(contract: &ExecutionContract) -> Self {
        Self {
            allow_network: contract.permissions.network.allow.clone(),
            allow_fs_read: contract.permissions.filesystem.read.clone(),
            allow_fs_write: contract.permissions.filesystem.write.clone(),
            additional_env: BTreeMap::new(),
        }
    }

    /// Append explicit `--allow-network` overrides. Duplicates are dropped.
    #[must_use]
    pub fn with_network_overrides<I>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        for host in hosts {
            if !self.allow_network.contains(&host) {
                self.allow_network.push(host);
            }
        }
        self
    }

    /// Merge extra env overrides (later calls win).
    #[must_use]
    pub fn with_env_overrides(mut self, env: BTreeMap<String, String>) -> Self {
        self.additional_env.extend(env);
        self
    }

    /// Build the child process env from declared vars + overrides, after
    /// verifying all `required` entries are present.
    ///
    /// `parent_lookup` mirrors `std::env::var`'s contract: `Some(value)` if
    /// set, `None` otherwise.
    pub fn build_child_env<F>(
        &self,
        contract: &ExecutionContract,
        parent_lookup: F,
    ) -> OsResult<BTreeMap<String, String>>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        // Required first: an override here satisfies the requirement.
        for name in &contract.env.required {
            let value = self
                .additional_env
                .get(name)
                .cloned()
                .or_else(|| parent_lookup(name))
                .ok_or_else(|| OsError::MissingRequiredEnv { name: name.clone() })?;
            env.insert(name.clone(), value);
        }
        // Optional: pulled through when set; absence is fine.
        for name in &contract.env.optional {
            if let Some(v) = self
                .additional_env
                .get(name)
                .cloned()
                .or_else(|| parent_lookup(name))
            {
                env.insert(name.clone(), v);
            }
        }
        // Overrides that aren't part of the declared sets pass through too
        // — profiles use these for ad-hoc test/runtime values. The launcher
        // is the only consumer; nothing leaks elsewhere.
        for (k, v) in &self.additional_env {
            env.entry(k.clone()).or_insert_with(|| v.clone());
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EntrypointKind, EnvSpec, ExecutionContract, FilesystemPermissions,
        NetworkPermissions, PermissionsSpec, RuntimeKind, RuntimeSpec,
    };

    fn contract_with(env: EnvSpec) -> ExecutionContract {
        ExecutionContract {
            entrypoint: Entrypoint {
                kind: EntrypointKind::Command,
                command: Some("python".into()),
                args: vec![],
            },
            runtime: RuntimeSpec {
                kind: RuntimeKind::Python,
                version: None,
            },
            working_directory: ".".into(),
            env,
            permissions: PermissionsSpec {
                filesystem: FilesystemPermissions::default(),
                network: NetworkPermissions::default(),
            },
        }
    }

    #[test]
    fn required_env_satisfied_by_parent() {
        let c = contract_with(EnvSpec {
            required: vec!["OPENAI_API_KEY".into()],
            optional: vec![],
        });
        let p = Policy::from_contract(&c);
        let env = p
            .build_child_env(&c, |k| {
                if k == "OPENAI_API_KEY" {
                    Some("sk-test".into())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            env.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );
    }

    #[test]
    fn required_env_satisfied_by_override() {
        let c = contract_with(EnvSpec {
            required: vec!["OPENAI_API_KEY".into()],
            optional: vec![],
        });
        let mut overrides = BTreeMap::new();
        overrides.insert("OPENAI_API_KEY".into(), "sk-override".into());
        let p = Policy::from_contract(&c).with_env_overrides(overrides);
        let env = p.build_child_env(&c, |_| None).unwrap();
        assert_eq!(
            env.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-override")
        );
    }

    #[test]
    fn missing_required_env_fails_closed() {
        let c = contract_with(EnvSpec {
            required: vec!["MISSING".into()],
            optional: vec![],
        });
        let p = Policy::from_contract(&c);
        let err = p.build_child_env(&c, |_| None).unwrap_err();
        assert!(matches!(err, OsError::MissingRequiredEnv { ref name } if name == "MISSING"));
    }

    #[test]
    fn undeclared_parent_var_not_propagated() {
        let c = contract_with(EnvSpec::default());
        let p = Policy::from_contract(&c);
        let env = p
            .build_child_env(&c, |k| match k {
                "SECRET" => Some("leak".into()),
                _ => None,
            })
            .unwrap();
        assert!(
            !env.contains_key("SECRET"),
            "undeclared parent vars must NOT reach the child"
        );
    }

    #[test]
    fn optional_env_passthrough_when_set() {
        let c = contract_with(EnvSpec {
            required: vec![],
            optional: vec!["LANGCHAIN_TRACING_V2".into()],
        });
        let p = Policy::from_contract(&c);
        let env = p
            .build_child_env(&c, |k| {
                if k == "LANGCHAIN_TRACING_V2" {
                    Some("1".into())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            env.get("LANGCHAIN_TRACING_V2").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn optional_env_absent_silently_ignored() {
        let c = contract_with(EnvSpec {
            required: vec![],
            optional: vec!["NEVER_SET".into()],
        });
        let p = Policy::from_contract(&c);
        let env = p.build_child_env(&c, |_| None).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn network_overrides_dedupe() {
        let c = contract_with(EnvSpec::default());
        let p = Policy::from_contract(&c)
            .with_network_overrides(["api.openai.com".into(), "api.openai.com".into()]);
        assert_eq!(p.allow_network, vec!["api.openai.com"]);
    }
}
