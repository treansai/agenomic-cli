//! Extract a bundle archive to a destination directory.

use std::path::PathBuf;

use agenomic_core::{io_at, CliError, CliResult};

use crate::build::read_archive_to_pairs;

/// Options for [`extract_bundle`].
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub archive: PathBuf,
    pub destination: PathBuf,
}

/// Extract `archive` into `destination`, creating the destination if needed.
///
/// Path traversal in archive entries is rejected.
pub fn extract_bundle(options: ExtractOptions) -> CliResult<()> {
    let pairs = read_archive_to_pairs(&options.archive)?;
    std::fs::create_dir_all(&options.destination).map_err(|e| io_at(&options.destination, e))?;
    for (rel, content) in pairs {
        if rel.split('/').any(|s| s == "..") {
            return Err(CliError::PathTraversal { path: rel });
        }
        let dest = options.destination.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
        }
        agenomic_fs::write_atomic(&dest, &content)?;
    }
    Ok(())
}
