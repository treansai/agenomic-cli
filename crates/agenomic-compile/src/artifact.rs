//! The output of a compile: an in-memory, deterministic file tree plus a
//! provenance manifest. Writing to disk is a separate, explicit step.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{CompileError, CompileResult};
use crate::target::CompileTarget;

/// Version of the generator, stamped into every manifest for provenance.
pub const GENERATOR: &str = concat!("agenomic-compile/", env!("CARGO_PKG_VERSION"));

/// A compiled runtime adapter: a map of bundle-relative paths → file contents,
/// kept in a `BTreeMap` so iteration (and therefore the manifest and on-disk
/// layout) is deterministic regardless of insertion order.
#[derive(Debug, Clone)]
pub struct CompiledArtifact {
    pub target: CompileTarget,
    /// Files relative to the target's own directory (`runtime/<t>.compiled/`).
    pub files: BTreeMap<String, String>,
}

impl CompiledArtifact {
    pub fn new(target: CompileTarget) -> Self {
        Self {
            target,
            files: BTreeMap::new(),
        }
    }

    /// Insert a generated file. Later inserts at the same path win (last write).
    pub fn insert(&mut self, rel_path: impl Into<String>, contents: impl Into<String>) {
        self.files.insert(rel_path.into(), contents.into());
    }

    /// Build the provenance manifest: per-file BLAKE3 digests plus the hash of
    /// the source genome, so a downstream attestation can pin exactly what was
    /// compiled and from what.
    pub fn manifest(&self, agent_id: &str, model: &str, source_genome_hash: &str) -> Manifest {
        let files = self
            .files
            .iter()
            .map(|(path, contents)| FileDigest {
                path: path.clone(),
                blake3: blake3_hex(contents.as_bytes()),
            })
            .collect();
        Manifest {
            schema_version: 1,
            target: self.target.label().to_string(),
            agent_id: agent_id.to_string(),
            model: model.to_string(),
            generator: GENERATOR.to_string(),
            source_genome_hash: source_genome_hash.to_string(),
            files,
        }
    }

    /// Serialize the manifest into the artifact as `manifest.json` (pretty,
    /// trailing newline) so the written tree is self-describing.
    pub fn attach_manifest(
        &mut self,
        agent_id: &str,
        model: &str,
        source_genome_hash: &str,
    ) -> CompileResult<()> {
        let manifest = self.manifest(agent_id, model, source_genome_hash);
        let mut json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| CompileError::Serialize(e.to_string()))?;
        json.push('\n');
        self.insert("manifest.json", json);
        Ok(())
    }

    /// Write the artifact under `runtime/<target>.compiled/` rooted at
    /// `bundle_dir`. Existing files at those paths are overwritten; unrelated
    /// files are left untouched. Returns the target directory.
    pub fn emit_to_bundle(&self, bundle_dir: &Path) -> CompileResult<PathBuf> {
        let root = bundle_dir.join("runtime").join(self.target.dir_name());
        self.emit_to_dir(&root)?;
        Ok(root)
    }

    /// Write the artifact's files directly under `root`.
    pub fn emit_to_dir(&self, root: &Path) -> CompileResult<()> {
        for (rel, contents) in &self.files {
            let dest = root.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| CompileError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            std::fs::write(&dest, contents).map_err(|e| CompileError::Io {
                path: dest.clone(),
                source: e,
            })?;
        }
        Ok(())
    }
}

/// Provenance record written as `manifest.json` in each compiled tree.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub target: String,
    pub agent_id: String,
    pub model: String,
    pub generator: String,
    /// BLAKE3 (hex) of the canonical source `genome.yaml` bytes.
    pub source_genome_hash: String,
    pub files: Vec<FileDigest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDigest {
    pub path: String,
    pub blake3: String,
}

/// Hex-encoded BLAKE3 of `bytes` (matches the hashing used elsewhere in the
/// workspace).
pub fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_deterministic_and_sorted() {
        let mut a = CompiledArtifact::new(CompileTarget::Plain);
        a.insert("z.py", "print('z')\n");
        a.insert("a.py", "print('a')\n");
        let m = a.manifest("agent://x/y", "gpt-4o", "deadbeef");
        // Files come out sorted by path regardless of insertion order.
        assert_eq!(m.files[0].path, "a.py");
        assert_eq!(m.files[1].path, "z.py");
        // Hash is stable.
        assert_eq!(m.files[0].blake3, blake3_hex(b"print('a')\n"));
    }

    #[test]
    fn emit_writes_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = CompiledArtifact::new(CompileTarget::LangGraph);
        a.insert("prompts/system.md", "hi");
        a.insert("graph.py", "pass\n");
        let root = a.emit_to_bundle(dir.path()).unwrap();
        assert!(root.ends_with("runtime/langgraph.compiled"));
        assert_eq!(
            std::fs::read_to_string(root.join("prompts/system.md")).unwrap(),
            "hi"
        );
        assert!(root.join("graph.py").is_file());
    }

    #[test]
    fn attach_manifest_roundtrips() {
        let mut a = CompiledArtifact::new(CompileTarget::Plain);
        a.insert("agent.py", "pass\n");
        a.attach_manifest("agent://x/y", "gpt-4o", "abc").unwrap();
        let raw = a.files.get("manifest.json").unwrap();
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(v["target"], "plain");
        assert_eq!(v["agent_id"], "agent://x/y");
        // manifest.json lists agent.py but not itself (attached after listing).
        let paths: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["agent.py"]);
    }
}
