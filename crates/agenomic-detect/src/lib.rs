//! Repo-aware genome detection and merge for `agm init` / `agm update`.
//!
//! This crate inspects a project directory — git remote, `README.md`, language
//! manifests (`go.mod`, `Cargo.toml`, `package.json`, `pyproject.toml`),
//! `Dockerfile`, and any existing `agenomic.yaml` — and produces a
//! [`DetectedGenome`] with real values instead of placeholders. It also merges
//! a fresh detection into an existing bundle while preserving hand edits.
//!
//! Design invariants:
//! - **Offline only.** Git access is local (no fetch, no network).
//! - **Deterministic.** Sources iterate alphabetically within each precedence
//!   tier; the tool list is sorted by `(kind, name)`; `detected_at` honours
//!   `SOURCE_DATE_EPOCH`.
//! - **Hash-pure.** Provenance is written to a `.agenomic/provenance.yaml`
//!   sidecar (excluded from the bundle walk), never inline in `genome.yaml`.
//!
//! All file I/O goes through [`agenomic_fs`] (atomic writes, symlink and
//! path-traversal rejection); errors surface as [`agenomic_core::CliError`].

pub mod detect;
pub mod model;

mod git;
mod infer;
mod sources;

pub use detect::{run, DetectOptions};
pub use model::{Dependency, DetectedGenome, Evidence, MemoryInfo, Source, ToolEntry, ToolKind};
