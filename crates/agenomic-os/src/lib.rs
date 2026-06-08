//! Agent Genome Orchestration Substrate.
//!
//! `agenomic-os` resolves `agent://<org>/<slug>` references to runnable
//! Agenomic agent bundles, validates their portable execution contract, and
//! prepares them for launch under policy. This crate provides the
//! resolver-side primitives (URI parsing, local resolution, cache, contract
//! mapping) and the `port` proposal helper. Launchers, policy enforcement,
//! tracing, and CLI integration are layered in by downstream PRs and stay out
//! of this crate.
//!
//! Design invariants:
//! - **Offline-first.** The MVP resolver only resolves bundles already
//!   present in the local cache. Remote resolution is tracked in
//!   `docs/BACKEND_GAPS.md`.
//! - **Fail-closed.** Unknown URI shapes, missing bundles, malformed
//!   execution contracts, and unsupported runtime kinds surface as
//!   [`error::OsError`] — never panics.
//! - **Additive over spec 0.1.** The `execution` block and `execution_hash`
//!   were introduced in spec 0.2; bundles without them remain valid for
//!   resolution but cannot be launched.
//!
//! See `docs/agent-uri.md` for the URI grammar and `schemas/genome.schema.json`
//! for the `execution` block shape.

pub mod cache;
pub mod contract;
pub mod error;
pub mod launcher;
pub mod policy;
pub mod port;
pub mod resolver;
pub mod trace;
pub mod uri;

pub use cache::CacheLocation;
pub use contract::{
    Entrypoint, EntrypointKind, EnvSpec, ExecutionContract, FilesystemPermissions,
    NetworkPermissions, PermissionsSpec, RuntimeKind, RuntimeSpec,
};
pub use error::{OsError, OsResult};
pub use launcher::{CommandLauncher, LaunchPlan, Launcher, RunHandle};
pub use policy::Policy;
pub use port::{Gap, GapSeverity, PortProposal};
pub use resolver::{AgentResolver, LocalResolver, ResolvedAgent};
pub use trace::{Trace, TraceEvent};
pub use uri::{AgentReference, Qualifier, Query};
