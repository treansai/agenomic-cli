//! Deterministic recursive directory walk.

use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult};
use walkdir::WalkDir;

use crate::ignore::IgnoreFile;

/// Default user-content excludes (build artifacts, VCS, OS metadata).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".git/",
    ".git",
    ".hg/",
    ".svn/",
    ".DS_Store",
    "Thumbs.db",
    "target/",
    "node_modules/",
    "__pycache__/",
    ".pytest_cache/",
    ".venv/",
    ".tox/",
    "dist/",
    ".agenomic/",
];

/// Always-on security excludes — credentials, keys, dotenvs.
pub const SECURITY_EXCLUDES: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*.p12",
    "*.pfx",
];

/// Walk options.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub allow_symlinks: bool,
    pub follow_ignore_file: bool,
    pub default_excludes: Vec<String>,
    pub security_excludes: Vec<String>,
    pub max_file_size_bytes: u64,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            allow_symlinks: false,
            follow_ignore_file: true,
            default_excludes: DEFAULT_EXCLUDES.iter().map(|s| (*s).to_string()).collect(),
            security_excludes: SECURITY_EXCLUDES.iter().map(|s| (*s).to_string()).collect(),
            max_file_size_bytes: 50 * 1024 * 1024,
        }
    }
}

/// What kind of entry the walk produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Directory,
}

/// One entry from the walk.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    /// POSIX-style relative path with `/` separators.
    pub relative_path: String,
    pub absolute_path: PathBuf,
    pub size: u64,
    pub kind: EntryKind,
}

/// Walk a directory deterministically.
///
/// * Paths are returned sorted lexicographically (UTF-8 byte order on the
///   POSIX-normalized relative path).
/// * Symlinks are rejected with [`CliError::SymlinkRejected`] unless
///   `options.allow_symlinks` is `true`.
/// * Path traversal (any `..` segment) returns [`CliError::PathTraversal`].
/// * Default and security excludes are honored. A `.agenomicignore` at the
///   root is honored when `follow_ignore_file = true`.
///
/// Only **files** are returned (directories are walked but not yielded).
///
/// ```no_run
/// use agenomic_fs::{walk_bundle, WalkOptions};
/// let entries = walk_bundle(std::path::Path::new("./examples/claims-agent"),
///                           &WalkOptions::default()).unwrap();
/// for e in entries { println!("{}", e.relative_path); }
/// ```
pub fn walk_bundle(root: &Path, options: &WalkOptions) -> CliResult<Vec<WalkEntry>> {
    if !root.exists() {
        return Err(io_at(
            root,
            std::io::Error::new(std::io::ErrorKind::NotFound, "directory does not exist"),
        ));
    }
    if !root.is_dir() {
        return Err(io_at(
            root,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a directory"),
        ));
    }

    let ignore_file = if options.follow_ignore_file {
        let path = root.join(".agenomicignore");
        if path.exists() {
            Some(IgnoreFile::load_from(&path)?)
        } else {
            None
        }
    } else {
        None
    };

    let mut entries: Vec<WalkEntry> = Vec::new();

    for dirent in WalkDir::new(root).follow_links(false).into_iter() {
        let dirent = dirent.map_err(|e| CliError::Internal(format!("walkdir: {e}")))?;
        let path = dirent.path();

        if path == root {
            continue;
        }

        let file_type = dirent.file_type();
        if file_type.is_symlink() && !options.allow_symlinks {
            return Err(CliError::SymlinkRejected {
                path: path.display().to_string(),
            });
        }

        let rel = path.strip_prefix(root).map_err(|_| {
            CliError::Internal(format!("strip_prefix failed for {}", path.display()))
        })?;

        let rel_str = posix_relative(rel)?;

        if rel_str.split('/').any(|seg| seg == "..") {
            return Err(CliError::PathTraversal { path: rel_str });
        }

        if matches_any(&rel_str, &options.default_excludes)
            || matches_any(&rel_str, &options.security_excludes)
        {
            continue;
        }
        if ignore_file
            .as_ref()
            .map(|ig| ig.matches(&rel_str))
            .unwrap_or(false)
        {
            continue;
        }

        if file_type.is_dir() {
            // walk into it; don't emit
            continue;
        }
        if !file_type.is_file() {
            // sockets, fifos, etc. — skip silently
            continue;
        }

        let meta = dirent
            .metadata()
            .map_err(|e| CliError::Internal(format!("metadata: {e}")))?;
        if meta.len() > options.max_file_size_bytes {
            return Err(CliError::Internal(format!(
                "file {} exceeds max size {}",
                rel_str, options.max_file_size_bytes
            )));
        }

        entries.push(WalkEntry {
            relative_path: rel_str,
            absolute_path: path.to_path_buf(),
            size: meta.len(),
            kind: EntryKind::File,
        });
    }

    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(entries)
}

fn posix_relative(rel: &Path) -> CliResult<String> {
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        use std::path::Component;
        match comp {
            Component::Normal(s) => {
                let s = s.to_str().ok_or_else(|| {
                    CliError::Internal(format!("non-UTF8 path component in {}", rel.display()))
                })?;
                parts.push(s.to_string());
            }
            Component::ParentDir => {
                return Err(CliError::PathTraversal {
                    path: rel.display().to_string(),
                });
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Internal(format!(
                    "unexpected absolute component in relative path {}",
                    rel.display()
                )));
            }
        }
    }
    Ok(parts.join("/"))
}

fn matches_any(rel: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if pattern_matches(rel, pat) {
            return true;
        }
    }
    false
}

fn pattern_matches(rel: &str, pat: &str) -> bool {
    // Strip a trailing slash for directory-style patterns; treat them as
    // matching the directory itself or any descendant.
    let (clean, dir_only) = if let Some(stripped) = pat.strip_suffix('/') {
        (stripped, true)
    } else {
        (pat, false)
    };
    let glob_pat = match glob::Pattern::new(clean) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Match the full rel as-is.
    if glob_pat.matches(rel) {
        return true;
    }
    // For patterns without `/` (or directory-only patterns), match any path
    // segment of `rel`. This is what makes e.g. `__pycache__/` exclude
    // `a/b/__pycache__/c.pyc`.
    if dir_only || !clean.contains('/') {
        for seg in rel.split('/') {
            if glob_pat.matches(seg) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn matches_default_excludes() {
        assert!(pattern_matches(".git/HEAD", ".git/"));
        assert!(pattern_matches("target/foo.bin", "target/"));
        assert!(pattern_matches("a/b/__pycache__/c.pyc", "__pycache__/"));
        assert!(!pattern_matches("src/main.rs", "target/"));
    }

    #[test]
    fn matches_security_globs() {
        assert!(pattern_matches(".env", ".env"));
        assert!(pattern_matches(".env.local", ".env.*"));
        assert!(pattern_matches("keys/private.pem", "*.pem"));
        assert!(pattern_matches("id_ed25519", "id_ed25519"));
    }

    #[test]
    fn rejects_missing_dir() {
        let r = walk_bundle(
            Path::new("/nonexistent/agenomic/test"),
            &WalkOptions::default(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn deterministic_order() {
        let d = tempdir().unwrap();
        // Create in shuffled order
        for name in ["c.txt", "a.txt", "b.txt"] {
            fs::write(d.path().join(name), b"hi").unwrap();
        }
        fs::create_dir_all(d.path().join("z/y")).unwrap();
        fs::write(d.path().join("z/y/x.txt"), b"hi").unwrap();
        fs::write(d.path().join("z/m.txt"), b"hi").unwrap();

        let entries = walk_bundle(d.path(), &WalkOptions::default()).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.relative_path.clone()).collect();
        assert_eq!(
            names,
            vec!["a.txt", "b.txt", "c.txt", "z/m.txt", "z/y/x.txt"]
        );
    }

    #[test]
    fn excludes_dotgit_and_target() {
        let d = tempdir().unwrap();
        fs::create_dir_all(d.path().join(".git")).unwrap();
        fs::write(d.path().join(".git/HEAD"), b"ref").unwrap();
        fs::create_dir_all(d.path().join("target")).unwrap();
        fs::write(d.path().join("target/x"), b"x").unwrap();
        fs::write(d.path().join("keep.txt"), b"k").unwrap();

        let entries = walk_bundle(d.path(), &WalkOptions::default()).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.relative_path.clone()).collect();
        assert_eq!(names, vec!["keep.txt"]);
    }

    #[test]
    fn excludes_dotenv_and_pem() {
        let d = tempdir().unwrap();
        fs::write(d.path().join(".env"), b"SECRET=1").unwrap();
        fs::write(d.path().join("private.pem"), b"---").unwrap();
        fs::write(d.path().join("id_ed25519"), b"k").unwrap();
        fs::write(d.path().join("ok.txt"), b"o").unwrap();

        let entries = walk_bundle(d.path(), &WalkOptions::default()).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.relative_path.clone()).collect();
        assert_eq!(names, vec!["ok.txt"]);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_by_default() {
        use std::os::unix::fs::symlink;
        let d = tempdir().unwrap();
        fs::write(d.path().join("real.txt"), b"r").unwrap();
        symlink(d.path().join("real.txt"), d.path().join("link.txt")).unwrap();
        let res = walk_bundle(d.path(), &WalkOptions::default());
        assert!(matches!(res, Err(CliError::SymlinkRejected { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn allows_symlink_when_opted_in() {
        use std::os::unix::fs::symlink;
        let d = tempdir().unwrap();
        fs::write(d.path().join("real.txt"), b"r").unwrap();
        symlink(d.path().join("real.txt"), d.path().join("link.txt")).unwrap();
        let mut opts = WalkOptions::default();
        opts.allow_symlinks = true;
        // Directory-iteration traverses; symlink to a regular file is reported as a "symlink"
        // by walkdir. We just want NOT to fail — entries should be a non-empty list.
        let entries = walk_bundle(d.path(), &opts).unwrap();
        assert!(!entries.is_empty());
    }
}
