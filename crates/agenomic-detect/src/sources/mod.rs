//! Detection sources (§2.3), each applied to a mutable [`DetectedGenome`].
//!
//! The orchestrator in [`crate::detect`] runs them in ascending precedence
//! order so that a higher-precedence source naturally overwrites a lower one;
//! each source only writes a field when it found a non-empty value
//! ("empty fields never overwrite").

use std::path::Path;

use agenomic_core::{io_at, CliError, CliResult};

pub(crate) mod agenomic_yaml;
pub(crate) mod dockerfile;
pub(crate) mod git;
pub(crate) mod manifest;
pub(crate) mod pyproject;
pub(crate) mod readme;

/// Read a single manifest file, returning `None` when it does not exist.
///
/// Rejects symlinks with [`CliError::SymlinkRejected`] (exit 4) — the same
/// error `agenomic-fs` raises during a bundle walk — so detection cannot be
/// induced into following a link out of the workspace (pitfall: security
/// reuse). Real I/O errors surface as [`CliError::Io`].
pub(crate) fn read_file_opt(path: &Path) -> CliResult<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(CliError::SymlinkRejected {
                    path: path.display().to_string(),
                });
            }
            if !meta.is_file() {
                return Ok(None);
            }
            let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_at(path, e)),
    }
}
