//! Local-only git access via `gix`.
//!
//! Every function reads or writes the on-disk repository and performs **no
//! network I/O** (no fetch, no remote resolution over the wire), honouring the
//! offline product invariant. Detection treats reads as best-effort; the commit
//! path surfaces clear errors.

use std::path::Path;

use agenomic_core::{io_at, CliError, CliResult};

/// The four canonical bundle files, as POSIX-relative paths.
pub const BUNDLE_FILES: [&str; 4] = [
    "genome.yaml",
    "agent.lock.yaml",
    "behavior.contract.yaml",
    "prompts/system.md",
];

/// Read `remote.origin.url` from the git repository at `path`, if present.
///
/// Returns `Ok(None)` when `path` is not a git repository or has no `origin`
/// remote. Local-only; never contacts the network.
pub(crate) fn origin_url(path: &Path) -> CliResult<Option<String>> {
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

/// The repository state relevant to `agm update`'s refusal checks (§3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub is_repo: bool,
    /// Current branch short name, or `None` when detached/unborn.
    pub branch: Option<String>,
    /// HEAD is detached (points directly at a commit).
    pub detached: bool,
    /// All changed paths (staged or unstaged), POSIX-relative, sorted. The
    /// caller decides which of these count as "dirty outside the bundle".
    pub changed: Vec<String>,
}

/// Inspect the repository at `path`: branch, detached-HEAD, and the set of
/// changed paths (staged or unstaged).
pub fn repo_state(path: &Path) -> CliResult<RepoState> {
    if !path.join(".git").exists() {
        return Ok(RepoState {
            is_repo: false,
            branch: None,
            detached: false,
            changed: Vec::new(),
        });
    }
    let repo = gix::open(path).map_err(|e| CliError::Internal(format!("open git repo: {e}")))?;

    let head_name = repo.head_name().ok().flatten();
    let branch = head_name.as_ref().map(|n| n.shorten().to_string());
    let detached = branch.is_none() && repo.head_id().is_ok();

    let mut changed = Vec::new();
    let platform = repo
        .status(gix::progress::Discard)
        .map_err(|e| CliError::Internal(format!("git status: {e}")))?;
    let iter = platform
        .into_iter(Vec::<gix::bstr::BString>::new())
        .map_err(|e| CliError::Internal(format!("git status: {e}")))?;
    for item in iter {
        let item = item.map_err(|e| CliError::Internal(format!("git status item: {e}")))?;
        changed.push(item.location().to_string());
    }
    changed.sort();
    changed.dedup();

    Ok(RepoState {
        is_repo: true,
        branch,
        detached,
        changed,
    })
}

/// Stage the given bundle `files` (read from disk under `path`) and create a
/// commit with `message`, returning the new commit's hex id.
///
/// The commit is built by overlaying the files onto HEAD's tree, so only the
/// bundle files are committed; the index is then reset to the new tree so the
/// post-commit `git status` is clean. Requires `user.name`/`user.email` to be
/// configured. Local-only; never contacts the network.
pub fn commit_bundle(path: &Path, files: &[&str], message: &str) -> CliResult<String> {
    let repo = gix::open(path).map_err(|e| CliError::Internal(format!("open git repo: {e}")))?;

    let (start_tree, parents) = match repo.head_commit() {
        Ok(commit) => {
            let tree = commit
                .tree_id()
                .map_err(|e| CliError::Internal(format!("head tree: {e}")))?
                .detach();
            (tree, vec![commit.id().detach()])
        }
        Err(_) => (gix::ObjectId::empty_tree(repo.object_hash()), Vec::new()),
    };

    let mut editor = repo
        .edit_tree(start_tree)
        .map_err(|e| CliError::Internal(format!("edit tree: {e}")))?;
    for rela in files {
        let abs = path.join(rela);
        let content = std::fs::read(&abs).map_err(|e| io_at(&abs, e))?;
        let blob = repo
            .write_blob(&content)
            .map_err(|e| CliError::Internal(format!("write blob: {e}")))?;
        editor
            .upsert(*rela, gix::object::tree::EntryKind::Blob, blob.detach())
            .map_err(|e| CliError::Internal(format!("tree upsert {rela}: {e}")))?;
    }
    let tree_id = editor
        .write()
        .map_err(|e| CliError::Internal(format!("write tree: {e}")))?
        .detach();

    let commit_id = repo
        .commit("HEAD", message, tree_id, parents)
        .map_err(|e| {
            CliError::Internal(format!(
                "git commit failed (is user.name/user.email configured?): {e}"
            ))
        })?
        .detach();

    // Reset the index to the committed tree so the working tree shows clean.
    let mut index = repo
        .index_from_tree(&tree_id)
        .map_err(|e| CliError::Internal(format!("index from tree: {e}")))?;
    index
        .write(gix::index::write::Options::default())
        .map_err(|e| CliError::Internal(format!("write index: {e}")))?;

    Ok(commit_id.to_hex().to_string())
}
