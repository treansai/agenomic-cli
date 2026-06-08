//! Launcher layer.
//!
//! A [`Launcher`] takes a [`LaunchPlan`] — bundle, contract, policy — and
//! produces a [`RunHandle`] that captures the child process's exit code,
//! stdout/stderr, and the [`Trace`] of policy + lifecycle events. Streaming
//! and concurrent runs are out of scope at MVP; the command launcher waits
//! for the child to exit and returns everything at once.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::contract::ExecutionContract;
use crate::error::OsResult;
use crate::policy::Policy;
use crate::trace::Trace;
use crate::uri::AgentReference;

mod command;

pub use command::CommandLauncher;

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
