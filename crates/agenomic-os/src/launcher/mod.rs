//! Launcher layer.
//!
//! A [`Launcher`] takes a [`LaunchPlan`] — bundle, contract, policy — and
//! produces a [`RunHandle`] that captures the child process's exit code,
//! stdout/stderr, and the [`Trace`] of policy + lifecycle events. Streaming
//! and concurrent runs are out of scope at MVP; each launcher waits for the
//! child to exit and returns everything at once.
//!
//! All launchers share the same spawn pipeline (env filtering, working
//! directory, trace emission); the difference is how `(program, args)` is
//! resolved from `entrypoint`. Use [`launch_for_kind`] to dispatch to the
//! right launcher for a given contract.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tokio::process::Command;

use crate::contract::{EntrypointKind, ExecutionContract};
use crate::error::{OsError, OsResult};
use crate::policy::Policy;
use crate::trace::{Trace, TraceEvent};
use crate::uri::AgentReference;

mod command;
mod docker;
mod wasm;

pub use command::CommandLauncher;
pub use docker::DockerLauncher;
pub use wasm::WasmLauncher;

/// All inputs the launcher needs to spawn the child.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub reference: AgentReference,
    pub bundle_path: PathBuf,
    pub contract: ExecutionContract,
    pub policy: Policy,
}

/// Outcome of a completed run.
#[derive(Debug, Clone)]
pub struct RunHandle {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub trace: Trace,
}

#[async_trait]
pub trait Launcher: Send + Sync {
    async fn launch(&self, plan: LaunchPlan) -> OsResult<RunHandle>;
}

/// Dispatch on the contract's `entrypoint.kind` and run the appropriate
/// launcher. CLI integration uses this so the call site doesn't have to know
/// which launcher implements a given kind.
pub async fn launch_for_kind(plan: LaunchPlan) -> OsResult<RunHandle> {
    match plan.contract.entrypoint.kind {
        EntrypointKind::Command => CommandLauncher::new().launch(plan).await,
        EntrypointKind::Docker => DockerLauncher::new().launch(plan).await,
        EntrypointKind::Wasm => WasmLauncher::new().launch(plan).await,
    }
}

/// Shared spawn pipeline used by every launcher.
///
/// Given a resolved `(program, args)` and the launch plan, this applies the
/// policy (env filtering, working directory containment), emits the
/// `PolicyApplied` / `ProcessStarted` / stdout/stderr / `ProcessExited` trace
/// events, and waits for the child to exit. Per-launcher logic only needs to
/// decide what program to invoke.
pub(crate) async fn spawn_planned(
    plan: &LaunchPlan,
    program: String,
    args: Vec<String>,
) -> OsResult<RunHandle> {
    let started_at = Utc::now();
    let started_instant = Instant::now();
    let mut trace = Trace::new(started_at);

    let working_directory = resolve_working_directory(plan)?;

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
    let duration_ms = started_instant
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
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

/// `bundle_path.join(contract.working_directory)`, refusing absolute paths and
/// any `..` segment so the working directory stays inside the bundle.
pub(crate) fn resolve_working_directory(plan: &LaunchPlan) -> OsResult<PathBuf> {
    let wd = &plan.contract.working_directory;
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
mod dispatch_tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EnvSpec, FilesystemPermissions, NetworkPermissions, PermissionsSpec,
        RuntimeKind, RuntimeSpec,
    };
    use tempfile::TempDir;

    fn make_plan(td: &TempDir, kind: EntrypointKind) -> LaunchPlan {
        let entrypoint = match kind {
            EntrypointKind::Command => Entrypoint {
                kind,
                command: Some("/bin/sh".into()),
                args: vec!["-c".into(), "exit 0".into()],
                image: None,
                module: None,
            },
            EntrypointKind::Docker => Entrypoint {
                kind,
                command: None,
                args: vec![],
                image: Some("img:1".into()),
                module: None,
            },
            EntrypointKind::Wasm => Entrypoint {
                kind,
                command: None,
                args: vec![],
                image: None,
                module: Some("agent.wasm".into()),
            },
        };
        let contract = ExecutionContract {
            entrypoint,
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
        };
        let policy = Policy::from_contract(&contract);
        LaunchPlan {
            reference: "agent://test/dispatch".parse().unwrap(),
            bundle_path: td.path().to_path_buf(),
            contract,
            policy,
        }
    }

    /// `launch_for_kind` picks the right launcher for each kind. For docker
    /// and wasm we expect a `LauncherFailed` (the host binary is not installed
    /// in CI) — which is exactly the path that proves dispatch happened: a
    /// wrong-kind dispatch would have hit `ContractInvalid` instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn command_kind_runs_through_command_launcher() {
        let td = TempDir::new().unwrap();
        let handle = launch_for_kind(make_plan(&td, EntrypointKind::Command))
            .await
            .unwrap();
        assert_eq!(handle.exit_code, 0);
    }

    #[tokio::test]
    async fn docker_kind_routes_to_docker_launcher() {
        let td = TempDir::new().unwrap();
        // We can't guarantee `docker` is on PATH in CI, so we expect either a
        // LauncherFailed (binary missing) or a non-zero RunHandle (image
        // unreachable). Both prove the docker path was taken.
        match launch_for_kind(make_plan(&td, EntrypointKind::Docker)).await {
            Err(OsError::LauncherFailed { .. }) => {}
            Ok(h) => assert!(h.exit_code != 0, "expected nonzero from `docker run img:1`"),
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wasm_kind_routes_to_wasm_launcher() {
        let td = TempDir::new().unwrap();
        match launch_for_kind(make_plan(&td, EntrypointKind::Wasm)).await {
            Err(OsError::LauncherFailed { .. }) => {}
            Ok(h) => assert!(h.exit_code != 0, "expected nonzero from `wasmtime run`"),
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }
    }
}
