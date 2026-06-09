//! Error type for `agenomic-policy`, bridged to [`agenomic_core::CliError`] so
//! a policy denial surfaces on the existing exit-code taxonomy.

use std::path::PathBuf;

use agenomic_core::CliError;
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum PolicyError {
    #[error("failed to load policies: {0}")]
    #[diagnostic(code(agenomic::policy::load))]
    Load(String),

    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agenomic::policy::io))]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("policy {policy} failed to compile: {reason}")]
    #[diagnostic(
        code(agenomic::policy::compile),
        help("a malformed .rego policy is treated as a hard failure, never an implicit allow")
    )]
    Compile { policy: String, reason: String },

    #[error("policy input is not valid JSON: {0}")]
    #[diagnostic(code(agenomic::policy::input))]
    Input(String),

    #[error("policy evaluation failed: {0}")]
    #[diagnostic(code(agenomic::policy::eval))]
    Eval(String),
}

pub type PolicyResult<T> = Result<T, PolicyError>;

impl From<PolicyError> for CliError {
    fn from(e: PolicyError) -> Self {
        match e {
            // A compile/eval failure or denial maps to the security-violation
            // class so it is clearly distinct from a successful run.
            PolicyError::Compile { .. } => CliError::OsPolicyViolation(e.to_string()),
            PolicyError::Load(_)
            | PolicyError::Io { .. }
            | PolicyError::Input(_)
            | PolicyError::Eval(_) => CliError::Internal(e.to_string()),
        }
    }
}
