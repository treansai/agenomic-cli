//! Internal error type for `agenomic-os`.
//!
//! `OsError` is the rich diagnostic form used inside this crate. CLI
//! integration converts it to [`agenomic_core::CliError`] via the
//! [`From`] impl at the bottom of this module so the existing exit-code
//! catalog (exit codes 11–17) drives process termination.

use std::path::PathBuf;

use agenomic_core::CliError;
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

    #[error("policy violation: {reason}")]
    #[diagnostic(
        code(agenomic::os::policy::violation),
        help("review the `execution.permissions` block and any --allow-* overrides")
    )]
    PolicyViolation { reason: String },

    #[error("required environment variable {name} is not set")]
    #[diagnostic(
        code(agenomic::os::policy::missing_required_env),
        help("set the variable in the parent process, in the profile, or via --env")
    )]
    MissingRequiredEnv { name: String },

    #[error("launcher failed for {command}: {reason}")]
    #[diagnostic(code(agenomic::os::launcher::failed))]
    LauncherFailed { command: String, reason: String },

    #[error("refusing unsigned remote bundle {reference}")]
    #[diagnostic(
        code(agenomic::os::resolver::unsigned_remote),
        help("unsigned remote bundles are refused by default; add the publisher to the trust list or pass --allow-unsigned to override (not recommended)")
    )]
    UnsignedRemoteBundle { reference: String },

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

impl From<OsError> for CliError {
    fn from(e: OsError) -> Self {
        match e {
            OsError::UriInvalid { ref reason } => CliError::OsUriInvalid(reason.clone()),
            OsError::BundleNotFound { .. }
            | OsError::BundleMalformed { .. }
            | OsError::NoHomeDirectory => CliError::OsResolverFailed(e.to_string()),
            OsError::UnsignedRemoteBundle { ref reference } => {
                CliError::OsBundleUnsigned(reference.clone())
            }
            OsError::ContractInvalid { .. }
            | OsError::ContractMissing
            | OsError::UnsupportedRuntime { .. } => CliError::OsContractInvalid(e.to_string()),
            OsError::LauncherFailed { .. } => CliError::OsLauncherFailed(e.to_string()),
            OsError::PolicyViolation { .. } | OsError::MissingRequiredEnv { .. } => {
                CliError::OsPolicyViolation(e.to_string())
            }
            OsError::PortFailed { ref reason } => CliError::OsPortFailed(reason.clone()),
            OsError::Io { .. } | OsError::Yaml { .. } => CliError::Internal(e.to_string()),
        }
    }
}
