//! Build, extract, and inspect Agenomic bundles.
//!
//! A bundle is a directory of files describing an agent. Building produces a
//! `.bundle.tar.zst` archive plus a deterministic logical hash (the BLAKE3
//! Merkle root from `agenomic-hash`) and an archive hash (the BLAKE3 of the
//! compressed bytes themselves).

pub mod build;
pub mod extract;
pub mod inspect;

pub use build::{build_bundle, read_archive_to_pairs, BuildBundleOptions, BundleBuildResult};
pub use extract::{extract_bundle, ExtractOptions};
pub use inspect::{inspect_bundle, BundleSummary, ToolSummary};
