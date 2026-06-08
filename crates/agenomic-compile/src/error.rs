//! Error type for `agenomic-compile`, with a `From` bridge to the CLI's
//! shared [`agenomic_core::CliError`] so exit codes stay consistent.

use std::path::PathBuf;

use agenomic_core::CliError;
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum CompileError {
    #[error("genome error: {0}")]
    #[diagnostic(code(agenomic::compile::genome))]
    Genome(String),

    #[error("unknown compile target: {0}")]
    #[diagnostic(
        code(agenomic::compile::unknown_target),
        help("supported targets: plain, langgraph, crewai, docker, wasm")
    )]
    UnknownTarget(String),

    #[error("io error at {path}: {source}")]
    #[diagnostic(code(agenomic::compile::io))]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    #[diagnostic(code(agenomic::compile::serialize))]
    Serialize(String),
}

pub type CompileResult<T> = Result<T, CompileError>;

impl From<CompileError> for CliError {
    fn from(e: CompileError) -> Self {
        match e {
            CompileError::Genome(_) | CompileError::UnknownTarget(_) => {
                // A bad genome or target is a usage/validation problem.
                CliError::Schema(e.to_string())
            }
            CompileError::Io { .. } | CompileError::Serialize(_) => {
                CliError::Internal(e.to_string())
            }
        }
    }
}
