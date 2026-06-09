//! `command` launcher: spawns a sub-process with the declared contract.
//!
//! Behaviour (shared by every launcher via [`super::spawn_planned`]):
//! - working directory = `bundle_path.join(contract.working_directory)`,
//!   never the caller's `cwd`.
//! - environment = exactly what [`crate::policy::Policy::build_child_env`]
//!   returns; `env_clear()` is called first so undeclared parent vars never
//!   leak.
//! - stdin is closed; stdout and stderr are captured to memory and split
//!   into lines for the trace.
//! - filesystem and network permissions are recorded into the trace but
//!   not kernel-enforced (see `docs/BACKEND_GAPS.md`).

use async_trait::async_trait;

use crate::contract::{EntrypointKind, ExecutionContract};
use crate::error::{OsError, OsResult};
use crate::launcher::{spawn_planned, LaunchPlan, Launcher, RunHandle};

/// Runs the bundle's declared `command` entrypoint.
#[derive(Debug, Default, Clone)]
pub struct CommandLauncher;

impl CommandLauncher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Launcher for CommandLauncher {
    async fn launch(&self, plan: LaunchPlan) -> OsResult<RunHandle> {
        let (program, args) = resolve_entrypoint(&plan.contract)?;
        spawn_planned(&plan, program, args).await
    }
}

fn resolve_entrypoint(contract: &ExecutionContract) -> OsResult<(String, Vec<String>)> {
    match contract.entrypoint.kind {
        EntrypointKind::Command => {
            let program =
                contract
                    .entrypoint
                    .command
                    .clone()
                    .ok_or_else(|| OsError::ContractInvalid {
                        reason: "entrypoint.command is missing".into(),
                    })?;
            Ok((program, contract.entrypoint.args.clone()))
        }
        other => Err(OsError::ContractInvalid {
            reason: format!(
                "CommandLauncher only handles kind=command (got {})",
                other.label()
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EnvSpec, FilesystemPermissions, NetworkPermissions, PermissionsSpec,
        RuntimeKind, RuntimeSpec,
    };
    use crate::policy::Policy;
    #[cfg(unix)]
    use crate::trace::TraceEvent;
    #[cfg(unix)]
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn contract(command: &str, args: Vec<String>) -> ExecutionContract {
        ExecutionContract {
            entrypoint: Entrypoint {
                kind: EntrypointKind::Command,
                command: Some(command.into()),
                args,
                image: None,
                module: None,
            },
            runtime: RuntimeSpec {
                kind: RuntimeKind::Binary,
                version: None,
            },
            working_directory: ".".into(),
            env: EnvSpec::default(),
            permissions: PermissionsSpec {
                filesystem: FilesystemPermissions::default(),
                network: NetworkPermissions::default(),
            },
        }
    }

    fn plan(td: &TempDir, c: ExecutionContract, policy: Policy) -> LaunchPlan {
        LaunchPlan {
            reference: "agent://test/run".parse().unwrap(),
            bundle_path: td.path().to_path_buf(),
            contract: c,
            policy,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn echoes_stdout_and_captures_exit_zero() {
        let td = TempDir::new().unwrap();
        let c = contract("/bin/sh", vec!["-c".into(), "echo hello".into()]);
        let policy = Policy::from_contract(&c);
        let handle = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap();
        assert_eq!(handle.exit_code, 0);
        assert!(handle.stdout.contains("hello"));
        assert!(handle
            .trace
            .events
            .iter()
            .any(|e| matches!(e, TraceEvent::ProcessExited { code: 0, .. })));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_zero_exit_surfaces_to_handle() {
        let td = TempDir::new().unwrap();
        let c = contract("/bin/sh", vec!["-c".into(), "exit 7".into()]);
        let policy = Policy::from_contract(&c);
        let handle = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap();
        assert_eq!(handle.exit_code, 7);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn undeclared_parent_env_does_not_leak_to_child() {
        let td = TempDir::new().unwrap();
        // Set a var the parent has but the contract does NOT declare.
        std::env::set_var("AGENOMIC_OS_TEST_SECRET", "leak");
        let c = contract(
            "/bin/sh",
            vec![
                "-c".into(),
                "echo \"${AGENOMIC_OS_TEST_SECRET:-clean}\"".into(),
            ],
        );
        let policy = Policy::from_contract(&c);
        let handle = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap();
        std::env::remove_var("AGENOMIC_OS_TEST_SECRET");
        assert!(
            handle.stdout.contains("clean"),
            "parent env must NOT propagate; got {:?}",
            handle.stdout
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn declared_env_does_reach_child() {
        let td = TempDir::new().unwrap();
        let mut c = contract("/bin/sh", vec!["-c".into(), "echo \"${MY_TOKEN}\"".into()]);
        c.env.required = vec!["MY_TOKEN".into()];
        let mut overrides = BTreeMap::new();
        overrides.insert("MY_TOKEN".into(), "ok".into());
        let policy = Policy::from_contract(&c).with_env_overrides(overrides);
        let handle = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap();
        assert!(handle.stdout.contains("ok"));
    }

    #[tokio::test]
    async fn missing_required_env_fails_before_spawn() {
        let td = TempDir::new().unwrap();
        let mut c = contract("/bin/sh", vec!["-c".into(), "echo unreachable".into()]);
        c.env.required = vec!["NEVER_SET_OS_OS_OS".into()];
        let policy = Policy::from_contract(&c);
        let err = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::MissingRequiredEnv { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_absolute_working_directory() {
        let td = TempDir::new().unwrap();
        let mut c = contract("/bin/true", vec![]);
        c.working_directory = "/etc".into();
        let policy = Policy::from_contract(&c);
        let err = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn rejects_parent_dir_traversal() {
        let td = TempDir::new().unwrap();
        let mut c = contract("/bin/true", vec![]);
        c.working_directory = "../outside".into();
        let policy = Policy::from_contract(&c);
        let err = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn spawn_failure_surfaces_as_launcher_failed() {
        let td = TempDir::new().unwrap();
        let c = contract("/no/such/binary/agenomic-os-test", vec![]);
        let policy = Policy::from_contract(&c);
        let err = CommandLauncher::new()
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::LauncherFailed { .. }));
    }
}
