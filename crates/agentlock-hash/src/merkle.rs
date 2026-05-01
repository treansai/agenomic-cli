//! Canonical BLAKE3 Merkle hashing.
//!
//! ## Algorithm
//!
//! 1. Walk the bundle directory deterministically (lexicographic POSIX path
//!    order) using [`agentlock_fs::walk_bundle`] with default options.
//! 2. For each file, compute a leaf hash:
//!    `leaf = BLAKE3(LEAF_DOMAIN || path_bytes || 0x00 || file_content)`
//! 3. Build a binary Merkle tree. At each layer, an odd trailing node is
//!    duplicated (i.e. paired with itself) before hashing.
//!    `parent = BLAKE3(NODE_DOMAIN || left || right)`
//! 4. The single remaining node is the root.

use std::io::Read;
use std::path::Path;

use agentlock_core::{io_at, CliError, CliResult};
use agentlock_fs::{walk_bundle, WalkOptions};
use blake3::Hasher;

use crate::manifest::{BundleManifest, ManifestEntry, HASH_ALGORITHM, MANIFEST_VERSION};

/// Domain separator for leaf hashes.
pub const LEAF_DOMAIN: &[u8] = b"AGENTLOCK-LEAF-v1\0";
/// Domain separator for internal node hashes.
pub const NODE_DOMAIN: &[u8] = b"AGENTLOCK-NODE-v1\0";

/// Compute the BLAKE3 leaf hash for a single (path, content) pair.
///
/// `leaf = BLAKE3(LEAF_DOMAIN || path_bytes || 0x00 || content)`
pub fn leaf_hash(path: &str, content: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(LEAF_DOMAIN);
    h.update(path.as_bytes());
    h.update(&[0u8]);
    h.update(content);
    *h.finalize().as_bytes()
}

/// Compute a parent node hash from two child hashes.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Compute the Merkle root from an ordered slice of leaf hashes.
///
/// Returns the leaf itself if there is only one. Returns the BLAKE3 hash of
/// `LEAF_DOMAIN || empty_marker` for an empty slice (so an empty bundle still
/// has a stable hash).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Hasher::new();
        h.update(LEAF_DOMAIN);
        h.update(b"<empty>");
        return *h.finalize().as_bytes();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left
            };
            next.push(node_hash(&left, &right));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Compute the manifest for a directory.
///
/// Walks via [`agentlock_fs::walk_bundle`] with [`WalkOptions::default`],
/// reads each file, hashes it as a Merkle leaf, then builds the tree.
///
/// ```no_run
/// let m = agentlock_hash::compute_manifest(std::path::Path::new("./examples/claims-agent")).unwrap();
/// assert_eq!(m.algorithm, "blake3-merkle-v1");
/// ```
pub fn compute_manifest(root: &Path) -> CliResult<BundleManifest> {
    let entries = walk_bundle(root, &WalkOptions::default())?;

    let mut manifest_entries: Vec<ManifestEntry> = Vec::with_capacity(entries.len());
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
    let mut total_size: u64 = 0;

    for e in &entries {
        let mut file = std::fs::File::open(&e.absolute_path).map_err(|err| io_at(&e.absolute_path, err))?;
        let mut buf = Vec::with_capacity(e.size as usize);
        file.read_to_end(&mut buf).map_err(|err| io_at(&e.absolute_path, err))?;
        let leaf = leaf_hash(&e.relative_path, &buf);
        leaves.push(leaf);
        total_size = total_size.saturating_add(e.size);
        manifest_entries.push(ManifestEntry {
            path: e.relative_path.clone(),
            kind: e.kind,
            size: e.size,
            hash: hex::encode(leaf),
        });
    }

    let root_bytes = merkle_root(&leaves);

    Ok(BundleManifest {
        manifest_version: MANIFEST_VERSION.to_string(),
        algorithm: HASH_ALGORITHM.to_string(),
        root_hash: hex::encode(root_bytes),
        file_count: manifest_entries.len(),
        total_size,
        entries: manifest_entries,
    })
}

/// Compute a manifest from a stream of `(path, content)` pairs already in
/// canonical sorted order.
///
/// Returns [`CliError::Internal`] if the input is not lexicographically sorted.
pub fn compute_manifest_from_pairs<I, B>(pairs: I) -> CliResult<BundleManifest>
where
    I: IntoIterator<Item = (String, B)>,
    B: AsRef<[u8]>,
{
    let mut manifest_entries: Vec<ManifestEntry> = Vec::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut total_size: u64 = 0;
    let mut last_path: Option<String> = None;

    for (path, content) in pairs {
        if let Some(prev) = &last_path {
            if &path <= prev {
                return Err(CliError::Internal(format!(
                    "manifest entries must be lexicographically increasing (got {prev} then {path})"
                )));
            }
        }
        let bytes = content.as_ref();
        let leaf = leaf_hash(&path, bytes);
        leaves.push(leaf);
        total_size = total_size.saturating_add(bytes.len() as u64);
        manifest_entries.push(ManifestEntry {
            path: path.clone(),
            kind: agentlock_fs::EntryKind::File,
            size: bytes.len() as u64,
            hash: hex::encode(leaf),
        });
        last_path = Some(path);
    }

    let root_bytes = merkle_root(&leaves);

    Ok(BundleManifest {
        manifest_version: MANIFEST_VERSION.to_string(),
        algorithm: HASH_ALGORITHM.to_string(),
        root_hash: hex::encode(root_bytes),
        file_count: manifest_entries.len(),
        total_size,
        entries: manifest_entries,
    })
}

/// Hex-encode a 32-byte BLAKE3 hash with optional `b3:` prefix.
///
/// ```
/// let bytes = [0u8; 32];
/// assert_eq!(agentlock_hash::format_hash(&bytes, false).len(), 64);
/// assert!(agentlock_hash::format_hash(&bytes, true).starts_with("b3:"));
/// ```
pub fn format_hash(bytes: &[u8; 32], with_prefix: bool) -> String {
    if with_prefix {
        format!("b3:{}", hex::encode(bytes))
    } else {
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_single_leaf_is_self() {
        let l = [1u8; 32];
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn merkle_two_leaves() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let r = merkle_root(&[a, b]);
        assert_eq!(r, node_hash(&a, &b));
    }

    #[test]
    fn merkle_three_leaves_duplicates_odd() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let r = merkle_root(&[a, b, c]);
        let ab = node_hash(&a, &b);
        let cc = node_hash(&c, &c);
        assert_eq!(r, node_hash(&ab, &cc));
    }

    #[test]
    fn pairs_must_be_sorted() {
        let r = compute_manifest_from_pairs(vec![
            ("b.txt".to_string(), b"x".to_vec()),
            ("a.txt".to_string(), b"y".to_vec()),
        ]);
        assert!(r.is_err());
    }

    #[test]
    fn pairs_in_order_succeed() {
        let m = compute_manifest_from_pairs(vec![
            ("a.txt".to_string(), b"y".to_vec()),
            ("b.txt".to_string(), b"x".to_vec()),
        ])
        .unwrap();
        assert_eq!(m.file_count, 2);
        assert_eq!(m.total_size, 2);
        assert_eq!(m.root_hash.len(), 64);
    }
}
