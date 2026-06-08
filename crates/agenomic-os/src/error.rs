//! Internal error type for `agenomic-os`.
//!
//! These variants are not yet wired into `agenomic_core::CliError` or the
//! workspace exit-code catalog — that conversion lands with the CLI
//! integration in a subsequent PR. Until then, callers of this crate consume
//! `OsError` directly.

use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

/// All fallible operations in `agenomic-os` return this type.
#[derive(Debug, Error, Diagnostic)]
pub enum OsError {
    #[error("invalid agent:// URI: {reason}")]
    #[diagnostic(
        code(agenomic::os::uri::invalid),
        help("see docs/agent-uri.md for the accepted grammar")
    )]
    UriInvalid { reason: String },

    #[error("bundle not found for {reference} (looked up at {location})")]
    #[diagnostic(
        code(agenomic::os::resolver::bundle_not_found),
        help("materialize the bundle into the cache or pass --local to point at an in-repo path")
    )]
    BundleNotFound {
        reference: String,
        location: String,
    },

    #[error("bundle at {path} is malformed: {reason}")]
    #[diagnostic(code(agenomic::os::resolver::bundle_malformed))]
    BundleMalformed { path: PathBuf, reason: String },

    #[error("execution contract is invalid: {reason}")]
    #[diagnostic(
        code(agenomic::os::contract::invalid),
        help("verify the `execution:` block in genome.yaml against schemas/genome.schema.json")
    )]
    ContractInvalid { reason: String },

    #[error("execution contract is missing in genome.yaml")]
    #[diagnostic(
        code(agenomic::os::contract::missing),
        help("add an `execution:` block (introduced in spec 0.2) or run `agenomic port` to scaffold one")
    )]
    ContractMissing,

    #[error("unsupported runtime kind: {kind}")]
    #[diagnostic(code(agenomic::os::contract::unsupported_runtime))]
    UnsupportedRuntime { kind: String },

    #[error("port proposal failed: {reason}")]
    #[diagnostic(code(agenomic::os::port::failed))]
    PortFailed { reason: String },

    #[error("home directory not available; cannot resolve global cache root")]
    #[diagnostic(
        code(agenomic::os::cache::no_home),
        help("set HOME (or use --local <path>) to make the global cache accessible")
    )]
    NoHomeDirectory,

    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agenomic::os::io))]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("yaml error in {path}: {source}")]
    #[diagnostic(code(agenomic::os::yaml))]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
}

pub type OsResult<T> = Result<T, OsError>;
