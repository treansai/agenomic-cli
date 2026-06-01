//! Local-only git access via `gix`.
//!
//! Every function here reads the on-disk repository and performs **no network
//! I/O** (no fetch, no remote resolution over the wire), honouring the
//! offline product invariant. Detection treats git as best-effort: a missing
//! repo or remote yields `None`, never an error.

use std::path::Path;

use agenomic_core::CliResult;

/// Read `remote.origin.url` from the git repository at `path`, if present.
///
/// Returns `Ok(None)` when `path` is not a git repository or has no `origin`
/// remote. Local-only; never contacts the network.
pub(crate) fn origin_url(path: &Path) -> CliResult<Option<String>> {
    // A missing `.git` entry means "not a repository" — avoid matching on
    // gix's open-error taxonomy. `.git` may be a dir (normal repo) or a file
    // (worktree/submodule); both `exists()`.
    if !path.join(".git").exists() {
        return Ok(None);
    }
    let repo = match gix::open(path) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    match repo.try_find_remote("origin") {
        Some(Ok(remote)) => Ok(remote
            .url(gix::remote::Direction::Fetch)
            .map(|u| u.to_bstring().to_string())),
        _ => Ok(None),
    }
}
