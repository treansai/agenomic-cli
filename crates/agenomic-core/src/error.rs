//! Diagnostic error type for the CLI.
//!
//! All errors returned by `agenomic-cli` crates ultimately surface as
//! [`CliError`], which implements [`miette::Diagnostic`] for rich human output
//! and maps to a stable [`ExitCode`].

use miette::Diagnostic;
use thiserror::Error;

use crate::exit::ExitCode;
use crate::report::ValidationIssue;

/// Top-level error type. Each variant carries a stable diagnostic `code(...)`
/// and maps to a fixed exit code via [`CliError::exit_code`].
#[derive(Debug, Error, Diagnostic)]
pub enum CliError {
    #[error("validation failed ({} issue(s))", .reports.len())]
    #[diagnostic(
        code(agenomic::validation::failed),
        help("run with --output json for machine-readable output")
    )]
    ValidationFailed { reports: Vec<ValidationIssue> },

    #[error("bundle is missing required file: {path}")]
    #[diagnostic(
        code(agenomic::bundle::missing_required_file),
        help("run `agenomic init` or add the missing file")
    )]
    MissingRequiredFile { path: String },

    #[error("path traversal detected: {path}")]
    #[diagnostic(code(agenomic::security::path_traversal), severity(Error))]
    PathTraversal { path: String },

    #[error("symlink rejected: {path}")]
    #[diagnostic(
        code(agenomic::security::symlink),
        help("use --allow-symlinks to override (not recommended)")
    )]
    SymlinkRejected { path: String },

    #[error("genome.yaml already exists at {path}")]
    #[diagnostic(
        code(agenomic::init::would_overwrite),
        help("run `agm update` to merge changes into the existing bundle, or pass --force to overwrite")
    )]
    InitWouldOverwrite { path: String },

    #[error("update refused: {reason}")]
    #[diagnostic(
        code(agenomic::update::refused),
        help("pass --allow-dirty / run on a feature branch, or use --no-commit")
    )]
    UpdateRefused { reason: String },

    #[error("ATEP integrity check failed: {reason}")]
    #[diagnostic(code(agenomic::atep::integrity), severity(Error))]
    AtepIntegrity { reason: String },

    #[error("ATEP signature verification failed for event {event_id}")]
    #[diagnostic(code(agenomic::atep::signature_invalid))]
    AtepSignatureInvalid { event_id: String },

    #[error("hash mismatch — expected {expected}, got {actual}")]
    #[diagnostic(code(agenomic::hash::mismatch))]
    HashMismatch { expected: String, actual: String },

    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agenomic::io))]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("schema error: {0}")]
    #[diagnostic(code(agenomic::spec::schema))]
    Schema(String),

    #[error("internal error: {0}")]
    #[diagnostic(code(agenomic::internal))]
    Internal(String),

    #[error("network error: {0}")]
    #[diagnostic(code(agenomic::cloud::network))]
    Network(String),

    #[error("authentication failed")]
    #[diagnostic(code(agenomic::cloud::auth_failed))]
    AuthFailed,

    #[error("attestation verification failed: {0}")]
    #[diagnostic(code(agenomic::attestation::verification_failed))]
    AttestationVerificationFailed(String),

    #[error("contract failed: {0}")]
    #[diagnostic(code(agenomic::contract::failed))]
    ContractFailed(String),

    #[error("diff risk exceeded threshold: {0}")]
    #[diagnostic(code(agenomic::diff::risk_exceeded))]
    DiffRiskExceeded(String),

    #[error("invalid agent:// URI: {0}")]
    #[diagnostic(
        code(agenomic::os::uri_invalid),
        help("see docs/agent-uri.md for the accepted grammar")
    )]
    OsUriInvalid(String),

    #[error("agent resolution failed: {0}")]
    #[diagnostic(
        code(agenomic::os::resolver_failed),
        help("materialize the bundle into the cache, pass --local for an in-repo path, or pass --bundle-path explicitly")
    )]
    OsResolverFailed(String),

    #[error("refusing unsigned remote bundle: {0}")]
    #[diagnostic(
        code(agenomic::os::bundle_unsigned),
        help("unsigned remote bundles are refused by default; add the publisher to the trust list or use --allow-unsigned for an explicit override")
    )]
    OsBundleUnsigned(String),

    #[error("execution contract invalid: {0}")]
    #[diagnostic(
        code(agenomic::os::contract_invalid),
        help("verify the `execution:` block in genome.yaml against schemas/genome.schema.json")
    )]
    OsContractInvalid(String),

    #[error("launcher failed: {0}")]
    #[diagnostic(code(agenomic::os::launcher_failed))]
    OsLauncherFailed(String),

    #[error("policy violation: {0}")]
    #[diagnostic(
        code(agenomic::os::policy_violation),
        help("review the `execution.permissions` block and any --allow-* overrides")
    )]
    OsPolicyViolation(String),

    #[error("port proposal failed: {0}")]
    #[diagnostic(code(agenomic::os::port_failed))]
    OsPortFailed(String),
}

impl CliError {
    /// Returns the canonical exit code associated with this error.
    ///
    /// ```
    /// # use agenomic_core::error::CliError;
    /// # use agenomic_core::exit::ExitCode;
    /// let e = CliError::AuthFailed;
    /// assert_eq!(e.exit_code(), ExitCode::CloudAuthFailed);
    /// ```
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::ValidationFailed { .. } => ExitCode::ValidationFailed,
            Self::MissingRequiredFile { .. } => ExitCode::ValidationFailed,
            Self::PathTraversal { .. } | Self::SymlinkRejected { .. } => {
                ExitCode::SecurityViolation
            }
            Self::InitWouldOverwrite { .. } | Self::UpdateRefused { .. } => ExitCode::InvalidUsage,
            Self::AtepIntegrity { .. } | Self::AtepSignatureInvalid { .. } => {
                ExitCode::AtepIntegrityFailed
            }
            Self::HashMismatch { .. } => ExitCode::ValidationFailed,
            Self::Io { .. } | Self::Schema(_) | Self::Internal(_) => ExitCode::InternalError,
            Self::Network(_) => ExitCode::NetworkError,
            Self::AuthFailed => ExitCode::CloudAuthFailed,
            Self::AttestationVerificationFailed(_) => ExitCode::AttestationVerificationFailed,
            Self::ContractFailed(_) => ExitCode::ContractFailed,
            Self::DiffRiskExceeded(_) => ExitCode::DiffRiskExceeded,
            Self::OsUriInvalid(_) => ExitCode::OsUriInvalid,
            Self::OsResolverFailed(_) => ExitCode::OsResolverFailed,
            Self::OsBundleUnsigned(_) => ExitCode::OsBundleUnsigned,
            Self::OsContractInvalid(_) => ExitCode::OsContractInvalid,
            Self::OsLauncherFailed(_) => ExitCode::OsLauncherFailed,
            Self::OsPolicyViolation(_) => ExitCode::OsPolicyViolation,
            Self::OsPortFailed(_) => ExitCode::OsPortFailed,
        }
    }
}

/// Convenience alias.
pub type CliResult<T> = Result<T, CliError>;

/// Convert a `(path, std::io::Error)` pair into [`CliError::Io`].
pub fn io_at<P: AsRef<std::path::Path>>(path: P, source: std::io::Error) -> CliError {
    CliError::Io {
        path: path.as_ref().display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failed_maps_to_5() {
        assert_eq!(CliError::AuthFailed.exit_code().as_i32(), 5);
    }

    #[test]
    fn path_traversal_maps_to_4() {
        let e = CliError::PathTraversal { path: "x".into() };
        assert_eq!(e.exit_code().as_i32(), 4);
    }

    #[test]
    fn atep_integrity_maps_to_10() {
        let e = CliError::AtepIntegrity { reason: "x".into() };
        assert_eq!(e.exit_code().as_i32(), 10);
    }

    #[test]
    fn os_variants_map_to_their_codes() {
        assert_eq!(CliError::OsUriInvalid("x".into()).exit_code().as_i32(), 11);
        assert_eq!(
            CliError::OsResolverFailed("x".into()).exit_code().as_i32(),
            12
        );
        assert_eq!(
            CliError::OsBundleUnsigned("x".into()).exit_code().as_i32(),
            13
        );
        assert_eq!(
            CliError::OsContractInvalid("x".into()).exit_code().as_i32(),
            14
        );
        assert_eq!(
            CliError::OsLauncherFailed("x".into()).exit_code().as_i32(),
            15
        );
        assert_eq!(
            CliError::OsPolicyViolation("x".into()).exit_code().as_i32(),
            16
        );
        assert_eq!(CliError::OsPortFailed("x".into()).exit_code().as_i32(), 17);
    }
}
