//! Read a bundle directory or archive and produce a [`BundleSummary`].

use std::path::Path;

use agentlock_core::{CliError, CliResult};
use agentlock_hash::{compute_manifest, compute_manifest_from_pairs};
use serde::{Deserialize, Serialize};

use crate::build::read_archive_to_pairs;

/// Summary of a single tool listed in the genome / lockfile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// High-level summary of a bundle's contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleSummary {
    pub spec_version: String,
    pub agent_id: String,
    pub agent_name: String,
    pub model: Option<String>,
    pub model_fingerprint: Option<String>,
    pub tool_count: usize,
    pub tools: Vec<ToolSummary>,
    pub skill_count: usize,
    pub contract_id: Option<String>,
    pub critical_rules: usize,
    pub logical_bundle_hash: String,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

/// Inspect a bundle (directory or `.tar.zst` archive) and return a summary.
///
/// ```no_run
/// let s = agentlock_bundle::inspect_bundle(std::path::Path::new("./examples/claims-agent")).unwrap();
/// println!("{}", s.agent_id);
/// ```
pub fn inspect_bundle(target: &Path) -> CliResult<BundleSummary> {
    if target.is_dir() {
        let manifest = compute_manifest(target)?;
        let pairs = collect_yaml_pairs_from_dir(target)?;
        return summarize(&pairs, &manifest);
    }
    if target.is_file() {
        let pairs = read_archive_to_pairs(target)?;
        let manifest = compute_manifest_from_pairs(
            pairs.iter().map(|(p, c)| (p.clone(), c.clone())),
        )?;
        return summarize(&pairs, &manifest);
    }
    Err(CliError::Internal(format!(
        "{} is neither a file nor a directory",
        target.display()
    )))
}

fn collect_yaml_pairs_from_dir(dir: &Path) -> CliResult<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for name in &["genome.yaml", "agent.lock.yaml", "agent.lock", "behavior.contract.yaml"] {
        let p = dir.join(name);
        if p.is_file() {
            let bytes = std::fs::read(&p).map_err(|e| agentlock_core::io_at(&p, e))?;
            out.push((name.to_string(), bytes));
        }
    }
    Ok(out)
}

fn summarize(
    pairs: &[(String, Vec<u8>)],
    manifest: &agentlock_hash::BundleManifest,
) -> CliResult<BundleSummary> {
    let mut spec_version = "0.1".to_string();
    let mut agent_id = String::new();
    let mut agent_name = String::new();
    let mut model = None;
    let mut model_fingerprint = None;
    let mut tools: Vec<ToolSummary> = Vec::new();
    let mut skill_count = 0usize;
    let mut contract_id: Option<String> = None;
    let mut critical_rules = 0usize;

    for (path, bytes) in pairs {
        if path == "genome.yaml" {
            if let Ok(v) = serde_yaml::from_slice::<serde_yaml::Value>(bytes) {
                if let Some(s) = v.get("spec_version").and_then(|x| x.as_str()) {
                    spec_version = s.to_string();
                }
                if let Some(a) = v.get("agent") {
                    if let Some(id) = a.get("id").and_then(|x| x.as_str()) {
                        agent_id = id.to_string();
                    }
                    if let Some(name) = a.get("name").and_then(|x| x.as_str()) {
                        agent_name = name.to_string();
                    }
                }
                if let Some(rt) = v.get("runtime") {
                    if let Some(p) = rt.get("model_provider").and_then(|x| x.as_str()) {
                        let id = rt.get("model_id").and_then(|x| x.as_str()).unwrap_or("");
                        model = Some(format!("{p}/{id}"));
                    }
                    if let Some(fp) = rt.get("model_fingerprint").and_then(|x| x.as_str()) {
                        model_fingerprint = Some(fp.to_string());
                    }
                }
                if let Some(arr) = v.get("tools").and_then(|x| x.as_sequence()) {
                    for t in arr {
                        let name = t
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        if name.is_empty() {
                            continue;
                        }
                        tools.push(ToolSummary {
                            name,
                            protocol: t
                                .get("protocol")
                                .and_then(|x| x.as_str())
                                .map(str::to_string),
                            version: t
                                .get("version")
                                .and_then(|x| x.as_str())
                                .map(str::to_string),
                        });
                    }
                }
                if let Some(arr) = v.get("skills").and_then(|x| x.as_sequence()) {
                    skill_count = arr.len();
                }
            }
        } else if path == "behavior.contract.yaml" {
            if let Ok(v) = serde_yaml::from_slice::<serde_yaml::Value>(bytes) {
                if let Some(c) = v.get("contract") {
                    if let Some(id) = c.get("id").and_then(|x| x.as_str()) {
                        contract_id = Some(id.to_string());
                    }
                    if let Some(rules) = c.get("rules").and_then(|x| x.as_sequence()) {
                        for r in rules {
                            if matches!(
                                r.get("severity").and_then(|x| x.as_str()),
                                Some("critical")
                            ) {
                                critical_rules += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(BundleSummary {
        spec_version,
        agent_id,
        agent_name,
        model,
        model_fingerprint,
        tool_count: tools.len(),
        tools,
        skill_count,
        contract_id,
        critical_rules,
        logical_bundle_hash: manifest.root_hash.clone(),
        file_count: manifest.file_count,
        total_size_bytes: manifest.total_size,
    })
}
