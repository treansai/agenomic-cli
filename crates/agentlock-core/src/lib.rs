//! Core types for `agentlock-cli`: identifiers, severity, exit codes,
//! the diagnostic [`error::CliError`] type, and the shared
//! [`report::ValidationReport`].
//!
//! This crate has no I/O and no async; it is the dependency-light foundation
//! every other crate builds on.

pub mod error;
pub mod exit;
pub mod ids;
pub mod report;
pub mod severity;

pub use error::{io_at, CliError, CliResult};
pub use exit::ExitCode;
pub use ids::{AgentId, BundleHash, ReleaseId, RunId, SchemaId, TraceId};
pub use report::{ValidationIssue, ValidationReport};
pub use severity::{OutputFormat, Severity, ValidationLevel};
