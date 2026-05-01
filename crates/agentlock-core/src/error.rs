//! Diagnostic error type for the CLI.
//!
//! All errors returned by `agentlock-cli` crates ultimately surface as
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
        code(agentlock::validation::failed),
        help("run with --output json for machine-readable output")
    )]
    ValidationFailed { reports: Vec<ValidationIssue> },

    #[error("bundle is missing required file: {path}")]
    #[diagnostic(
        code(agentlock::bundle::missing_required_file),
        help("run `agentlock init` or add the missing file")
    )]
    MissingRequiredFile { path: String },

    #[error("path traversal detected: {path}")]
    #[diagnostic(code(agentlock::security::path_traversal), severity(Error))]
    PathTraversal { path: String },

    #[error("symlink rejected: {path}")]
    #[diagnostic(
        code(agentlock::security::symlink),
        help("use --allow-symlinks to override (not recommended)")
    )]
    SymlinkRejected { path: String },

    #[error("ATEP integrity check failed: {reason}")]
    #[diagnostic(code(agentlock::atep::integrity), severity(Error))]
    AtepIntegrity { reason: String },

    #[error("ATEP signature verification failed for event {event_id}")]
    #[diagnostic(code(agentlock::atep::signature_invalid))]
    AtepSignatureInvalid { event_id: String },

    #[error("hash mismatch — expected {expected}, got {actual}")]
    #[diagnostic(code(agentlock::hash::mismatch))]
    HashMismatch { expected: String, actual: String },

    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agentlock::io))]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("schema error: {0}")]
    #[diagnostic(code(agentlock::spec::schema))]
    Schema(String),

    #[error("internal error: {0}")]
    #[diagnostic(code(agentlock::internal))]
    Internal(String),

    #[error("network error: {0}")]
    #[diagnostic(code(agentlock::cloud::network))]
    Network(String),

    #[error("authentication failed")]
    #[diagnostic(code(agentlock::cloud::auth_failed))]
    AuthFailed,

    #[error("attestation verification failed: {0}")]
    #[diagnostic(code(agentlock::attestation::verification_failed))]
    AttestationVerificationFailed(String),

    #[error("contract failed: {0}")]
    #[diagnostic(code(agentlock::contract::failed))]
    ContractFailed(String),

    #[error("diff risk exceeded threshold: {0}")]
    #[diagnostic(code(agentlock::diff::risk_exceeded))]
    DiffRiskExceeded(String),
}

impl CliError {
    /// Returns the canonical exit code associated with this error.
    ///
    /// ```
    /// # use agentlock_core::error::CliError;
    /// # use agentlock_core::exit::ExitCode;
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
        let e = CliError::PathTraversal {
            path: "x".into(),
        };
        assert_eq!(e.exit_code().as_i32(), 4);
    }

    #[test]
    fn atep_integrity_maps_to_10() {
        let e = CliError::AtepIntegrity {
            reason: "x".into(),
        };
        assert_eq!(e.exit_code().as_i32(), 10);
    }
}
