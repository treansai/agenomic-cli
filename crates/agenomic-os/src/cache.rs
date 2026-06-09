//! Bundle cache location resolution.
//!
//! Two layouts are supported:
//! - [`CacheLocation::Global`] — `$XDG_DATA_HOME/agenomic/bundles` (or the
//!   platform-equivalent data dir on macOS/Windows). Default unless
//!   `--local` is requested.
//! - [`CacheLocation::ProjectLocal`] — `<project_root>/.agenomic/bundles`.
//!   Used when the caller pins the bundle to a specific project for
//!   reproducibility.
//!
//! Layout under either root:
//!
//! ```text
//! <root>/<org>/<slug>/<version-or-channel-or-digest>/
//! ```
//!
//! The unqualified case (no `@`) collapses to a single segment called
//! `unversioned`, kept distinct from any real qualifier so a later push of a
//! qualified bundle never silently replaces an unqualified one.

use std::path::{Path, PathBuf};

use crate::error::{OsError, OsResult};
use crate::uri::AgentReference;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLocation {
    Global,
    ProjectLocal(PathBuf),
}

impl CacheLocation {
    /// Resolve the root directory for this cache location.
    ///
    /// Returns [`OsError::NoHomeDirectory`] when the global cache is
    /// requested but no home directory is discoverable.
    pub fn root(&self) -> OsResult<PathBuf> {
        match self {
            CacheLocation::Global => {
                let dirs = directories::ProjectDirs::from("io", "agenomic", "agenomic")
                    .ok_or(OsError::NoHomeDirectory)?;
                Ok(dirs.data_dir().join("bundles"))
            }
            CacheLocation::ProjectLocal(root) => Ok(root.join(".agenomic").join("bundles")),
        }
    }

    /// Compute the on-disk directory for a specific reference under this
    /// location. Does not create the directory.
    pub fn bundle_path(&self, reference: &AgentReference) -> OsResult<PathBuf> {
        let root = self.root()?;
        let qualifier_segment = reference
            .qualifier
            .as_ref()
            .map(|q| q.cache_segment())
            .unwrap_or_else(|| "unversioned".to_string());
        Ok(root
            .join(&reference.org)
            .join(&reference.slug)
            .join(qualifier_segment))
    }

    /// Construct a project-local cache at `project_root`.
    pub fn project_local<P: AsRef<Path>>(project_root: P) -> Self {
        CacheLocation::ProjectLocal(project_root.as_ref().to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::Qualifier;

    #[test]
    fn project_local_root_is_under_dot_agenomic() {
        let loc = CacheLocation::project_local("/tmp/proj");
        let root = loc.root().unwrap();
        assert!(root.ends_with(".agenomic/bundles"));
        assert!(root.starts_with("/tmp/proj"));
    }

    #[test]
    fn bundle_path_unqualified_collapses_to_unversioned() {
        let loc = CacheLocation::project_local("/tmp/proj");
        let r: AgentReference = "agent://org/slug".parse().unwrap();
        let p = loc.bundle_path(&r).unwrap();
        assert!(p.ends_with("org/slug/unversioned"));
    }

    #[test]
    fn bundle_path_versioned_differs_from_unqualified() {
        let loc = CacheLocation::project_local("/tmp/proj");
        let unq: AgentReference = "agent://org/slug".parse().unwrap();
        let ver: AgentReference = "agent://org/slug@1.2.0".parse().unwrap();
        assert_ne!(
            loc.bundle_path(&unq).unwrap(),
            loc.bundle_path(&ver).unwrap()
        );
    }

    #[test]
    fn bundle_path_channel_versus_version_disambiguated() {
        let loc = CacheLocation::project_local("/tmp/proj");
        let ch: AgentReference = "agent://org/slug@prod".parse().unwrap();
        let ver: AgentReference = "agent://org/slug@1.0.0".parse().unwrap();
        let p_ch = loc.bundle_path(&ch).unwrap();
        let p_ver = loc.bundle_path(&ver).unwrap();
        assert_ne!(p_ch, p_ver);
        // Sanity: cache_segment prefixes survive on disk.
        assert!(p_ch
            .components()
            .next_back()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .starts_with("ch-"));
        assert!(p_ver
            .components()
            .next_back()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .starts_with("v-"));
    }

    #[test]
    fn digest_segment_uses_lowered_hex() {
        let loc = CacheLocation::project_local("/tmp/proj");
        let r = AgentReference {
            org: "o".into(),
            slug: "s".into(),
            qualifier: Some(Qualifier::Digest {
                algorithm: "sha256".into(),
                hex: "abc123".into(),
            }),
            query: Default::default(),
        };
        let p = loc.bundle_path(&r).unwrap();
        assert!(p
            .components()
            .next_back()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .contains("abc123"));
    }
}
