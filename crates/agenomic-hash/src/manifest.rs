//! Bundle manifest types.

use serde::{Deserialize, Serialize};

use agenomic_fs::EntryKind;

/// Manifest version string. Burned into the manifest and verified on read.
pub const MANIFEST_VERSION: &str = "agenomic.manifest/v0.1";
/// Identifier of the canonical hashing algorithm.
pub const HASH_ALGORITHM: &str = "blake3-merkle-v1";

/// One entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// POSIX-style relative path with `/` separators. Sorted across the
    /// manifest.
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Hex-encoded BLAKE3 leaf hash.
    pub hash: String,
}

/// Full bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub manifest_version: String,
    pub algorithm: String,
    /// Hex-encoded BLAKE3 Merkle root (64 chars, no prefix).
    pub root_hash: String,
    pub file_count: usize,
    pub total_size: u64,
    pub entries: Vec<ManifestEntry>,
}
