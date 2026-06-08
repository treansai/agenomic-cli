//! Local resolver: looks up an already-materialized bundle in a cache.
//!
//! This implementation is the MVP. It never performs network I/O. A bundle
//! is "resolved" when the cache directory exists *and* contains a top-level
//! `genome.yaml`. Anything else fails closed.

use async_trait::async_trait;

use crate::cache::CacheLocation;
use crate::error::{OsError, OsResult};
use crate::resolver::{AgentResolver, ResolvedAgent};
use crate::uri::AgentReference;

/// Resolves references to bundles already present in a cache.
#[derive(Debug, Clone)]
pub struct LocalResolver {
    cache: CacheLocation,
}

impl LocalResolver {
    pub fn new(cache: CacheLocation) -> Self {
        Self { cache }
    }

    pub fn cache(&self) -> &CacheLocation {
        &self.cache
    }
}

#[async_trait]
impl AgentResolver for LocalResolver {
    async fn resolve(&self, reference: &AgentReference) -> OsResult<ResolvedAgent> {
        let path = self.cache.bundle_path(reference)?;
        if !path.is_dir() {
            return Err(OsError::BundleNotFound {
                reference: reference.canonical(),
                location: path.display().to_string(),
            });
        }
        let genome = path.join("genome.yaml");
        if !genome.is_file() {
            return Err(OsError::BundleMalformed {
                path: path.clone(),
                reason: "missing genome.yaml at bundle root".into(),
            });
        }
        Ok(ResolvedAgent {
            reference: reference.clone(),
            bundle_path: path,
            signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn cache_with(td: &TempDir) -> CacheLocation {
        CacheLocation::project_local(td.path())
    }

    #[tokio::test]
    async fn resolves_existing_bundle() {
        let td = TempDir::new().unwrap();
        let cache = cache_with(&td);
        let reference: AgentReference = "agent://acme/foo@1.0.0".parse().unwrap();
        let dir = cache.bundle_path(&reference).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("genome.yaml"), "spec_version: '0.1'\n").unwrap();

        let resolver = LocalResolver::new(cache);
        let resolved = resolver.resolve(&reference).await.unwrap();
        assert_eq!(resolved.bundle_path, dir);
        assert!(resolved.signature.is_none());
    }

    #[tokio::test]
    async fn missing_bundle_is_not_found() {
        let td = TempDir::new().unwrap();
        let resolver = LocalResolver::new(cache_with(&td));
        let reference: AgentReference = "agent://acme/nope".parse().unwrap();
        let err = resolver.resolve(&reference).await.unwrap_err();
        assert!(matches!(err, OsError::BundleNotFound { .. }));
    }

    #[tokio::test]
    async fn bundle_directory_without_genome_is_malformed() {
        let td = TempDir::new().unwrap();
        let cache = cache_with(&td);
        let reference: AgentReference = "agent://acme/foo".parse().unwrap();
        fs::create_dir_all(cache.bundle_path(&reference).unwrap()).unwrap();

        let resolver = LocalResolver::new(cache);
        let err = resolver.resolve(&reference).await.unwrap_err();
        assert!(matches!(err, OsError::BundleMalformed { .. }));
    }

    #[tokio::test]
    async fn version_and_unqualified_resolve_independently() {
        let td = TempDir::new().unwrap();
        let cache = cache_with(&td);
        let unq: AgentReference = "agent://acme/foo".parse().unwrap();
        let ver: AgentReference = "agent://acme/foo@1.0.0".parse().unwrap();

        let dir_unq = cache.bundle_path(&unq).unwrap();
        fs::create_dir_all(&dir_unq).unwrap();
        fs::write(dir_unq.join("genome.yaml"), "x").unwrap();

        let resolver = LocalResolver::new(cache);
        assert!(resolver.resolve(&unq).await.is_ok());
        // Versioned ref must NOT shadow into the unqualified slot.
        assert!(matches!(
            resolver.resolve(&ver).await.unwrap_err(),
            OsError::BundleNotFound { .. }
        ));
    }
}
