use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentlockError {
    #[error("bundle path `{0}` does not exist")]
    MissingPath(String),
    #[error("bundle path `{0}` is not a directory")]
    NotADirectory(String),
    #[error("required file missing: {0}")]
    MissingRequiredFile(String),
    #[error("tracked file missing: {0}")]
    MissingTrackedFile(String),
    #[error("invalid UTF-8 in `{0}`")]
    InvalidUtf8(String),
    #[error("unsupported bundle source `{0}`")]
    UnsupportedBundleSource(String),
    #[error("trace file `{0}` is empty")]
    EmptyTraceFile(String),
    #[error("path escapes bundle root: {0}")]
    EscapingPath(String),
}
