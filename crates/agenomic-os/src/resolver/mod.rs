//! Resolver layer.
//!
//! The [`AgentResolver`] trait defines how an [`AgentReference`] turns into
//! a local on-disk bundle ready for inspection or (eventually) launch. The
//! only implementation shipped in this crate is [`LocalResolver`], which
//! never talks to the network — remote resolution is tracked in
//! `docs/BACKEND_GAPS.md` and will be added by a future PR.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::OsResult;
use crate::uri::AgentReference;

mod local;

pub use local::LocalResolver;

/// The outcome of resolving an `agent://` reference. The bundle is
/// guaranteed to exist on disk at `bundle_path` and contain at least a
/// `genome.yaml` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgent {
    pub reference: AgentReference,
    pub bundle_path: PathBuf,
    /// Signature material when the bundle was retrieved with a trust
    /// envelope. Always `None` for [`LocalResolver`] until signature
    /// verification is integrated (see `docs/BACKEND_GAPS.md`).
    pub signature: Option<Signature>,
}

/// Opaque signature placeholder. The concrete envelope (Ed25519 over a
/// canonical manifest) is owned by `agenomic-attestation` and will be wired
/// in when remote resolution lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: String,
    pub signer: String,
}

#[async_trait]
pub trait AgentResolver: Send + Sync {
    async fn resolve(&self, reference: &AgentReference) -> OsResult<ResolvedAgent>;
}
