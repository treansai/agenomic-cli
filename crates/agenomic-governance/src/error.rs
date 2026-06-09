//! Error type for `agenomic-governance`, bridged to [`agenomic_core::CliError`].

use std::path::PathBuf;

use agenomic_core::CliError;
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum GovernanceError {
    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agenomic::governance::io))]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed trace at {path}{line}: {reason}", line = .line.map(|n| format!(" line {n}")).unwrap_or_default())]
    #[diagnostic(
        code(agenomic::governance::trace_parse),
        help("each line of the trace JSONL must be an object with `trace_id`, `agent_id`, `skill`, `signal`")
    )]
    TraceParse {
        path: PathBuf,
        line: Option<usize>,
        reason: String,
    },

    #[error("malformed governance document: {0}")]
    #[diagnostic(code(agenomic::governance::doc))]
    Doc(String),
}

pub type GovernanceResult<T> = Result<T, GovernanceError>;

impl From<GovernanceError> for CliError {
    fn from(e: GovernanceError) -> Self {
        // Parse / shape errors are usage-level; io is internal.
        match e {
            GovernanceError::TraceParse { .. } | GovernanceError::Doc(_) => {
                CliError::Schema(e.to_string())
            }
            GovernanceError::Io { .. } => CliError::Internal(e.to_string()),
        }
    }
}
