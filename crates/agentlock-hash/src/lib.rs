//! Canonical BLAKE3 Merkle hashing of agent bundles.
//!
//! See [`merkle`] for the algorithm. The output [`BundleManifest`] is
//! deterministic and reproducible across machines.

pub mod manifest;
pub mod merkle;

pub use manifest::{BundleManifest, ManifestEntry, HASH_ALGORITHM, MANIFEST_VERSION};
pub use merkle::{
    compute_manifest, compute_manifest_from_pairs, format_hash, leaf_hash, merkle_root, node_hash,
    LEAF_DOMAIN, NODE_DOMAIN,
};
