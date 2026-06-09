//! `wasm` launcher: runs a WASI component with the declared contract via `wasmtime run`.
//!
//! Like the docker launcher, this composes a `(program, args)` pair for the
//! host runtime and delegates the spawn pipeline to
//! [`super::spawn_planned`]. Filesystem and network capabilities are forwarded
//! via `--dir` and `-S http`/`--allow-network` flags so the declared contract
//! is reflected in what the WASI host actually grants.

use async_trait::async_trait;

use crate::contract::{EntrypointKind, ExecutionContract};
use crate::error::{OsError, OsResult};
use crate::launcher::{spawn_planned, LaunchPlan, Launcher, RunHandle};

/// Runs the bundle's declared `wasm` entrypoint via the `wasmtime` CLI.
#[derive(Debug, Default, Clone)]
pub struct WasmLauncher {
    /// Path to the `wasmtime` binary. Defaults to `"wasmtime"` (resolved on `PATH`).
    wasmtime_binary: Option<String>,
}

impl WasmLauncher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the path to the `wasmtime` CLI (used by tests).
    pub fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.wasmtime_binary = Some(path.into());
        self
    }

    fn binary(&self) -> String {
        self.wasmtime_binary
            .clone()
            .unwrap_or_else(|| "wasmtime".to_string())
    }
}

#[async_trait]
impl Launcher for WasmLauncher {
    async fn launch(&self, plan: LaunchPlan) -> OsResult<RunHandle> {
        let args = build_wasmtime_args(&plan.contract)?;
        spawn_planned(&plan, self.binary(), args).await
    }
}

fn build_wasmtime_args(contract: &ExecutionContract) -> OsResult<Vec<String>> {
    if !matches!(contract.entrypoint.kind, EntrypointKind::Wasm) {
        return Err(OsError::ContractInvalid {
            reason: format!(
                "WasmLauncher only handles kind=wasm (got {})",
                contract.entrypoint.kind.label()
            ),
        });
    }
    let module = contract
        .entrypoint
        .module
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OsError::ContractInvalid {
            reason: "entrypoint.module must be set when kind = wasm".into(),
        })?;

    // The module path must be relative to the bundle and not escape it. The
    // working directory is already constrained by `spawn_planned`; here we
    // refuse traversal in the module path itself.
    let mp = std::path::Path::new(&module);
    if mp.is_absolute() {
        return Err(OsError::PolicyViolation {
            reason: format!("entrypoint.module must be relative to the bundle (got {module:?})"),
        });
    }
    if mp
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(OsError::PolicyViolation {
            reason: format!("entrypoint.module may not contain '..' (got {module:?})"),
        });
    }

    let mut args: Vec<String> = vec!["run".into()];

    // Forward declared filesystem read paths to wasmtime as preopens. Writes
    // are advisory at this layer too — wasmtime's `--dir` grants read+write,
    // so the policy crate's split is preserved only in the trace.
    for dir in &contract.permissions.filesystem.read {
        args.push("--dir".into());
        args.push(dir.to_string_lossy().into_owned());
    }
    // Network is granted at the WASI-HTTP level when explicitly declared.
    if !contract.permissions.network.allow.is_empty() {
        args.push("-S".into());
        args.push("http".into());
    }

    args.push(module);
    args.extend(contract.entrypoint.args.iter().cloned());
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EnvSpec, FilesystemPermissions, NetworkPermissions, PermissionsSpec,
        RuntimeKind, RuntimeSpec,
    };
    use crate::policy::Policy;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn contract(module: Option<&str>, args: Vec<String>) -> ExecutionContract {
        ExecutionContract {
            entrypoint: Entrypoint {
                kind: EntrypointKind::Wasm,
                command: None,
                args,
                image: None,
                module: module.map(str::to_string),
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

    #[test]
    fn minimal_args_have_module_last() {
        let c = contract(Some("agent.wasm"), vec![]);
        let args = build_wasmtime_args(&c).unwrap();
        assert_eq!(args.first().map(String::as_str), Some("run"));
        assert_eq!(args.last().map(String::as_str), Some("agent.wasm"));
    }

    #[test]
    fn fs_read_paths_become_dir_preopens() {
        let mut c = contract(Some("agent.wasm"), vec![]);
        c.permissions.filesystem.read = vec![PathBuf::from("./data")];
        let args = build_wasmtime_args(&c).unwrap();
        let pairs: Vec<_> = args
            .windows(2)
            .filter(|w| w[0] == "--dir")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(pairs, vec!["./data".to_string()]);
    }

    #[test]
    fn network_allow_enables_wasi_http() {
        let mut c = contract(Some("agent.wasm"), vec![]);
        c.permissions.network.allow = vec!["api.example.com".into()];
        let args = build_wasmtime_args(&c).unwrap();
        assert!(args.windows(2).any(|w| w[0] == "-S" && w[1] == "http"));
    }

    #[test]
    fn missing_module_rejected() {
        let c = contract(None, vec![]);
        let err = build_wasmtime_args(&c).unwrap_err();
        assert!(matches!(err, OsError::ContractInvalid { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn absolute_module_rejected() {
        let c = contract(Some("/etc/passwd"), vec![]);
        let err = build_wasmtime_args(&c).unwrap_err();
        assert!(matches!(err, OsError::PolicyViolation { .. }));
    }

    #[test]
    fn traversal_in_module_rejected() {
        let c = contract(Some("../outside.wasm"), vec![]);
        let err = build_wasmtime_args(&c).unwrap_err();
        assert!(matches!(err, OsError::PolicyViolation { .. }));
    }

    #[tokio::test]
    async fn surfaces_launcher_failed_when_wasmtime_missing() {
        let td = TempDir::new().unwrap();
        let c = contract(Some("agent.wasm"), vec![]);
        let policy = Policy::from_contract(&c);
        let err = WasmLauncher::new()
            .with_binary("/no/such/binary/agenomic-os-test-wasmtime")
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::LauncherFailed { .. }));
    }
}
