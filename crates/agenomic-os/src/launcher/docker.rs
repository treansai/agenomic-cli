//! `docker` launcher: runs an OCI image with the declared contract via `docker run`.
//!
//! `docker` is treated as an out-of-process executor: we resolve `entrypoint`
//! to `docker run --rm -i [<network-flags>] [-e <KEY>] <image>` and let
//! [`super::spawn_planned`] apply env filtering, capture stdout/stderr, and
//! emit the trace events. The declared env vars are forwarded as `-e KEY` (no
//! values: `docker` reads them from the spawned-process environment, which is
//! exactly the filtered child env this crate builds), so we never embed
//! secrets in `argv`.
//!
//! Network policy: an empty `permissions.network.allow` produces
//! `--network=none`; any declared host produces `--network=bridge` (advisory —
//! granular host allow-listing belongs in the sandbox-hardening track).

use async_trait::async_trait;

use crate::contract::{EntrypointKind, ExecutionContract};
use crate::error::{OsError, OsResult};
use crate::launcher::{spawn_planned, LaunchPlan, Launcher, RunHandle};

/// Runs the bundle's declared `docker` entrypoint via the `docker` CLI.
#[derive(Debug, Default, Clone)]
pub struct DockerLauncher {
    /// Path to the `docker` binary. Defaults to `"docker"` (resolved on `PATH`).
    docker_binary: Option<String>,
}

impl DockerLauncher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the path to the `docker` CLI (used by tests).
    pub fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.docker_binary = Some(path.into());
        self
    }

    fn binary(&self) -> String {
        self.docker_binary
            .clone()
            .unwrap_or_else(|| "docker".to_string())
    }
}

#[async_trait]
impl Launcher for DockerLauncher {
    async fn launch(&self, plan: LaunchPlan) -> OsResult<RunHandle> {
        let args = build_docker_args(&plan.contract)?;
        spawn_planned(&plan, self.binary(), args).await
    }
}

fn build_docker_args(contract: &ExecutionContract) -> OsResult<Vec<String>> {
    if !matches!(contract.entrypoint.kind, EntrypointKind::Docker) {
        return Err(OsError::ContractInvalid {
            reason: format!(
                "DockerLauncher only handles kind=docker (got {})",
                contract.entrypoint.kind.label()
            ),
        });
    }
    let image = contract
        .entrypoint
        .image
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OsError::ContractInvalid {
            reason: "entrypoint.image must be set when kind = docker".into(),
        })?;

    let mut args: Vec<String> = vec!["run".into(), "--rm".into(), "-i".into()];

    // Network: deny by default. Declared hosts → bridge (advisory). Per-host
    // egress filtering belongs to the sandbox-hardening track.
    if contract.permissions.network.allow.is_empty() {
        args.push("--network=none".into());
    } else {
        args.push("--network=bridge".into());
    }

    // Forward declared env vars *by name only*; values come from the filtered
    // child env that `spawn_planned` materialises. This keeps secrets out of
    // `argv` and out of `ps`.
    for name in declared_env_names(contract) {
        args.push("-e".into());
        args.push(name);
    }

    args.push(image);
    args.extend(contract.entrypoint.args.iter().cloned());
    Ok(args)
}

/// Required + optional env names, in declaration order (required first), with
/// duplicates removed. Used to pass `-e NAME` flags without values.
fn declared_env_names(contract: &ExecutionContract) -> Vec<String> {
    let mut out: Vec<String> = contract.env.required.clone();
    for n in &contract.env.optional {
        if !out.contains(n) {
            out.push(n.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        Entrypoint, EnvSpec, FilesystemPermissions, NetworkPermissions, PermissionsSpec,
        RuntimeKind, RuntimeSpec,
    };
    use crate::policy::Policy;
    use tempfile::TempDir;

    fn contract(image: Option<&str>, args: Vec<String>) -> ExecutionContract {
        ExecutionContract {
            entrypoint: Entrypoint {
                kind: EntrypointKind::Docker,
                command: None,
                args,
                image: image.map(str::to_string),
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

    #[test]
    fn empty_network_yields_network_none() {
        let c = contract(Some("img:1"), vec![]);
        let args = build_docker_args(&c).unwrap();
        assert!(args.contains(&"--network=none".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("img:1"));
    }

    #[test]
    fn declared_network_yields_bridge() {
        let mut c = contract(Some("img:1"), vec![]);
        c.permissions.network.allow = vec!["api.example.com".into()];
        let args = build_docker_args(&c).unwrap();
        assert!(args.contains(&"--network=bridge".to_string()));
    }

    #[test]
    fn declared_env_forwarded_as_flag_names_only() {
        let mut c = contract(Some("img:1"), vec![]);
        c.env.required = vec!["OPENAI_API_KEY".into()];
        c.env.optional = vec!["LANGCHAIN_TRACING_V2".into()];
        let args = build_docker_args(&c).unwrap();
        // -e <NAME> pairs without values
        let mut iter = args.iter();
        let mut seen = Vec::new();
        while let Some(a) = iter.next() {
            if a == "-e" {
                seen.push(iter.next().cloned().unwrap_or_default());
            }
        }
        assert_eq!(
            seen,
            vec![
                "OPENAI_API_KEY".to_string(),
                "LANGCHAIN_TRACING_V2".to_string()
            ]
        );
        // Never embed values in argv.
        assert!(!args
            .iter()
            .any(|a| a.contains('=') && a != "--network=none"));
    }

    #[test]
    fn entrypoint_args_appended_after_image() {
        let c = contract(Some("img:1"), vec!["--mode".into(), "fast".into()]);
        let args = build_docker_args(&c).unwrap();
        let img_idx = args.iter().position(|a| a == "img:1").unwrap();
        assert_eq!(args[img_idx + 1..], ["--mode", "fast"]);
    }

    #[test]
    fn missing_image_rejected() {
        let c = contract(None, vec![]);
        let err = build_docker_args(&c).unwrap_err();
        assert!(matches!(err, OsError::ContractInvalid { .. }));
    }

    #[tokio::test]
    async fn surfaces_launcher_failed_when_docker_missing() {
        let td = TempDir::new().unwrap();
        let c = contract(Some("img:1"), vec![]);
        let policy = Policy::from_contract(&c);
        let err = DockerLauncher::new()
            .with_binary("/no/such/binary/agenomic-os-test-docker")
            .launch(plan(&td, c, policy))
            .await
            .unwrap_err();
        assert!(matches!(err, OsError::LauncherFailed { .. }));
    }
}
