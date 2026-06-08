//! `command` launcher: spawns a sub-process with the declared contract.
//!
//! The contract restricts the entrypoint to `kind: command` at MVP, so this
//! launcher is the only one wired in. Behaviour:
//!
//! - working directory = `bundle_path.join(contract.working_directory)`,
//!   never the caller's `cwd`.
//! - environment = exactly what [`Policy::build_child_env`] returns;
//!   `env_clear()` is called first so undeclared parent vars never leak.
//! - stdin is closed; stdout and stderr are captured to memory and split
//!   into lines for the trace.
//! - filesystem and network permissions are recorded into the trace but
//!   not kernel-enforced (see `docs/BACKEND_GAPS.md`).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tokio::process::Command;

use crate::contract::{EntrypointKind, ExecutionContract};
use crate::error::{OsError, OsResult};
use crate::launcher::{LaunchPlan, Launcher, RunHandle};
use crate::trace::{Trace, TraceEvent};

/// Default launcher: runs the bundle's declared `command` entrypoint.
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
        let started_at = Utc::now();
        let started_instant = Instant::now();
        let mut trace = Trace::new(started_at);

        let (program, args) = resolve_entrypoint(&plan.contract)?;
        let working_directory = resolve_working_directory(&plan)?;

        let env = plan
            .policy
            .build_child_env(&plan.contract, |k| std::env::var(k).ok())?;
        let optional_env_set: Vec<String> = plan
            .contract
            .env
            .optional
            .iter()
            .filter(|n| env.contains_key(n.as_str()))
            .cloned()
            .collect();

        trace.push(TraceEvent::PolicyApplied {
            at: Utc::now(),
            required_env: plan.contract.env.required.clone(),
            optional_env_set,
            allow_network: plan.policy.allow_network.clone(),
            allow_fs_read: plan.policy.allow_fs_read.clone(),
            allow_fs_write: plan.policy.allow_fs_write.clone(),
        });

        let mut cmd = Command::new(&program);
        cmd.args(&args)
            .current_dir(&working_directory)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        trace.push(TraceEvent::ProcessStarted {
            at: Utc::now(),
            command: program.clone(),
            args: args.clone(),
            working_directory: working_directory.clone(),
        });

        let output = cmd.output().await.map_err(|e| OsError::LauncherFailed {
            command: program.clone(),
            reason: format!("spawn: {e}"),
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exited_at = Utc::now();

        for line in stdout.lines() {
            trace.push(TraceEvent::StdoutLine {
                at: exited_at,
                line: line.to_string(),
            });
        }
        for line in stderr.lines() {
            trace.push(TraceEvent::StderrLine {
                at: exited_at,
                line: line.to_string(),
            });
        }

        let exit_code = output.status.code().unwrap_or(-1);
        let duration_ms = started_instant.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        trace.push(TraceEvent::ProcessExited {
            at: exited_at,
            code: exit_code,
            duration_ms,
        });

        Ok(RunHandle {
            exit_code,
            stdout,
            stderr,
            trace,
        })
    }
}

fn resolve_entrypoint(contract: &ExecutionContract) -> OsResult<(String, Vec<String>)> {
    match contract.entrypoint.kind {
        EntrypointKind::Command => {
            let program = contract
                .entrypoint
                .command
                .clone()
                .ok_or_else(|| OsError::ContractInvalid {
                    reason: "entrypoint.command is missing".into(),
                })?;
            Ok((program, contract.entrypoint.args.clone()))
        }
    }
}

fn resolve_working_directory(plan: &LaunchPlan) -> OsResult<PathBuf> {
    let wd = &plan.contract.working_directory;
    // Refuse absolute paths and any `..` segment: the working directory
    // must stay inside the bundle.
    let candidate = std::path::Path::new(wd);
    if candidate.is_absolute() {
        return Err(OsError::PolicyViolation {
            reason: format!("working_directory must be relative to the bundle (got {wd:?})"),
        });
    }
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(OsError::PolicyViolation {
            reason: format!("working_directory may not contain '..' (got {wd:?})"),
        });
    }
    Ok(plan.bundle_path.join(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EnvSpec, FilesystemPermissions, NetworkPermissions, PermissionsSpec,
        RuntimeKind, RuntimeSpec,
    };
    use crate::policy::Policy;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn contract(command: &str, args: Vec<String>) -> ExecutionContract {
        ExecutionContract {
            entrypoint: Entrypoint {
                kind: EntrypointKind::Command,
                command: Some(command.into()),
                args,
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

    #[tokio::test]
    async fn echoes_stdout_and_captures_exit_zero() {
        let td = TempDir::new().unwrap();
        let c = contract("/bin/sh", vec!["-c".into(), "echo hello".into()]);
        let policy = Policy::from_contract(&c);
        let handle = CommandLauncher::new().launch(plan(&td, c, policy)).await.unwrap();
        assert_eq!(handle.exit_code, 0);
        assert!(handle.stdout.contains("hello"));
        assert!(handle
            .trace
            .events
            .iter()
            .any(|e| matches!(e, TraceEvent::ProcessExited { code: 0, .. })));
    }

    #[tokio::test]
    async fn non_zero_exit_surfaces_to_handle() {
        let td = TempDir::new().unwrap();
        let c = contract("/bin/sh", vec!["-c".into(), "exit 7".into()]);
        let policy = Policy::from_contract(&c);
        let handle = CommandLauncher::new().launch(plan(&td, c, policy)).await.unwrap();
        assert_eq!(handle.exit_code, 7);
    }

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
        let handle = CommandLauncher::new().launch(plan(&td, c, policy)).await.unwrap();
        std::env::remove_var("AGENOMIC_OS_TEST_SECRET");
        assert!(
            handle.stdout.contains("clean"),
            "parent env must NOT propagate; got {:?}",
            handle.stdout
        );
    }

    #[tokio::test]
    async fn declared_env_does_reach_child() {
        let td = TempDir::new().unwrap();
        let mut c = contract(
            "/bin/sh",
            vec!["-c".into(), "echo \"${MY_TOKEN}\"".into()],
        );
        c.env.required = vec!["MY_TOKEN".into()];
        let mut overrides = BTreeMap::new();
        overrides.insert("MY_TOKEN".into(), "ok".into());
        let policy = Policy::from_contract(&c).with_env_overrides(overrides);
        let handle = CommandLauncher::new().launch(plan(&td, c, policy)).await.unwrap();
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
