//! Static structural diff between two Agenomic bundles.
//!
//! Operates on bundle directories or `.tar.zst` archives. Produces a
//! [`DiffReport`] with severity-classified [`DiffChange`]s and an overall
//! risk level.

use std::collections::BTreeMap;
use std::path::Path;

use agenomic_bundle::read_archive_to_pairs;
use agenomic_core::{io_at, CliError, CliResult, Severity};
use agenomic_hash::{compute_manifest, compute_manifest_from_pairs, BundleManifest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffCategory {
    Model,
    Tools,
    Prompts,
    Knowledge,
    Policies,
    Memory,
    Contract,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffChange {
    pub change_type: String,
    pub category: DiffCategory,
    pub severity: Severity,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffReport {
    pub baseline_hash: String,
    pub candidate_hash: String,
    pub overall_risk: Severity,
    pub replay_required: bool,
    pub changes: Vec<DiffChange>,
}

#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub fail_on: Severity,
    pub include: Vec<DiffCategory>,
    pub ignore_prompts_whitespace: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            fail_on: Severity::Critical,
            include: vec![],
            ignore_prompts_whitespace: false,
        }
    }
}

/// Compute the diff between two bundles.
///
/// ```no_run
/// use agenomic_diff::{diff_bundles, DiffOptions};
/// let _r = diff_bundles(std::path::Path::new("./baseline"),
///                       std::path::Path::new("./candidate"),
///                       &DiffOptions::default()).unwrap();
/// ```
pub fn diff_bundles(
    baseline: &Path,
    candidate: &Path,
    options: &DiffOptions,
) -> CliResult<DiffReport> {
    let (b_pairs, b_manifest) = load_pairs_and_manifest(baseline)?;
    let (c_pairs, c_manifest) = load_pairs_and_manifest(candidate)?;

    let mut changes: Vec<DiffChange> = Vec::new();

    let b_genome = file_yaml(&b_pairs, "genome.yaml");
    let c_genome = file_yaml(&c_pairs, "genome.yaml");
    let b_contract = file_yaml(&b_pairs, "behavior.contract.yaml");
    let c_contract = file_yaml(&c_pairs, "behavior.contract.yaml");

    diff_model(&b_genome, &c_genome, &mut changes);
    diff_tools(&b_genome, &c_genome, &mut changes);
    diff_knowledge(&b_genome, &c_genome, &mut changes);
    diff_policies(&b_genome, &c_genome, &mut changes);
    diff_memory(&b_genome, &c_genome, &mut changes);
    diff_contract_rules(&b_contract, &c_contract, &mut changes);
    diff_prompts(
        &b_pairs,
        &c_pairs,
        options.ignore_prompts_whitespace,
        &mut changes,
    );

    if !options.include.is_empty() {
        changes.retain(|c| options.include.contains(&c.category));
    }

    let overall = changes
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::Info);
    let replay_required = changes.iter().any(|c| {
        c.change_type == "model_fingerprint_changed"
            || c.change_type == "knowledge_snapshot_changed"
    });

    Ok(DiffReport {
        baseline_hash: b_manifest.root_hash,
        candidate_hash: c_manifest.root_hash,
        overall_risk: overall,
        replay_required,
        changes,
    })
}

/// `(relative_path, file_bytes)` pairs for a bundle's files.
type BundlePairs = Vec<(String, Vec<u8>)>;

fn load_pairs_and_manifest(target: &Path) -> CliResult<(BundlePairs, BundleManifest)> {
    if target.is_dir() {
        let manifest = compute_manifest(target)?;
        let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
        for e in &manifest.entries {
            let p = target.join(&e.path);
            let bytes = std::fs::read(&p).map_err(|err| io_at(&p, err))?;
            pairs.push((e.path.clone(), bytes));
        }
        Ok((pairs, manifest))
    } else if target.is_file() {
        let pairs = read_archive_to_pairs(target)?;
        let manifest =
            compute_manifest_from_pairs(pairs.iter().map(|(p, c)| (p.clone(), c.clone())))?;
        Ok((pairs, manifest))
    } else {
        Err(CliError::Internal(format!(
            "{} is neither a file nor a directory",
            target.display()
        )))
    }
}

fn file_yaml(pairs: &[(String, Vec<u8>)], name: &str) -> Option<serde_yaml::Value> {
    pairs
        .iter()
        .find(|(p, _)| p == name)
        .and_then(|(_, c)| serde_yaml::from_slice::<serde_yaml::Value>(c).ok())
}

fn diff_model(
    b_g: &Option<serde_yaml::Value>,
    c_g: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let (b_id, b_fp) = model_info(b_g);
    let (c_id, c_fp) = model_info(c_g);
    if b_id != c_id {
        changes.push(DiffChange {
            change_type: "model_id_changed".into(),
            category: DiffCategory::Model,
            severity: Severity::High,
            path: "genome.yaml#runtime.model_id".into(),
            before: b_id.map(serde_json::Value::String),
            after: c_id.map(serde_json::Value::String),
            explanation: "Model ID changed — re-validate behavior".into(),
        });
    } else if b_fp != c_fp {
        changes.push(DiffChange {
            change_type: "model_fingerprint_changed".into(),
            category: DiffCategory::Model,
            severity: Severity::Medium,
            path: "genome.yaml#runtime.model_fingerprint".into(),
            before: b_fp.map(serde_json::Value::String),
            after: c_fp.map(serde_json::Value::String),
            explanation: "Model fingerprint moved — replay required".into(),
        });
    }
}

fn model_info(g: &Option<serde_yaml::Value>) -> (Option<String>, Option<String>) {
    let g = match g {
        Some(g) => g,
        None => return (None, None),
    };
    let rt = g.get("runtime");
    let id = rt
        .and_then(|r| r.get("model_id"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let fp = rt
        .and_then(|r| r.get("model_fingerprint"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    (id, fp)
}

fn diff_tools(
    b_g: &Option<serde_yaml::Value>,
    c_g: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let b = tools_map(b_g);
    let c = tools_map(c_g);
    for (name, c_v) in &c {
        match b.get(name) {
            None => changes.push(DiffChange {
                change_type: "tool_added".into(),
                category: DiffCategory::Tools,
                severity: Severity::Medium,
                path: format!("genome.yaml#tools[{name}]"),
                before: None,
                after: Some(c_v.clone()),
                explanation: format!("Tool '{name}' added"),
            }),
            Some(b_v) if b_v != c_v => changes.push(DiffChange {
                change_type: "tool_changed".into(),
                category: DiffCategory::Tools,
                severity: Severity::Medium,
                path: format!("genome.yaml#tools[{name}]"),
                before: Some(b_v.clone()),
                after: Some(c_v.clone()),
                explanation: format!("Tool '{name}' definition changed"),
            }),
            _ => {}
        }
    }
    for name in b.keys() {
        if !c.contains_key(name) {
            changes.push(DiffChange {
                change_type: "tool_removed".into(),
                category: DiffCategory::Tools,
                severity: Severity::High,
                path: format!("genome.yaml#tools[{name}]"),
                before: b.get(name).cloned(),
                after: None,
                explanation: format!("Tool '{name}' removed"),
            });
        }
    }
}

fn tools_map(g: &Option<serde_yaml::Value>) -> BTreeMap<String, serde_json::Value> {
    let g = match g {
        Some(g) => g,
        None => return BTreeMap::new(),
    };
    let mut out = BTreeMap::new();
    if let Some(arr) = g.get("tools").and_then(|x| x.as_sequence()) {
        for t in arr {
            if let Some(name) = t.get("name").and_then(|x| x.as_str()) {
                let json = serde_json::to_value(t).unwrap_or(serde_json::Value::Null);
                out.insert(name.to_string(), json);
            }
        }
    }
    out
}

fn diff_knowledge(
    b_g: &Option<serde_yaml::Value>,
    c_g: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let b = named_map(b_g, "knowledge");
    let c = named_map(c_g, "knowledge");
    for (name, c_v) in &c {
        match b.get(name) {
            None => changes.push(DiffChange {
                change_type: "knowledge_added".into(),
                category: DiffCategory::Knowledge,
                severity: Severity::Medium,
                path: format!("genome.yaml#knowledge[{name}]"),
                before: None,
                after: Some(c_v.clone()),
                explanation: format!("Knowledge source '{name}' added"),
            }),
            Some(b_v) if b_v != c_v => {
                let b_snap = b_v.get("snapshot_hash").and_then(|x| x.as_str());
                let c_snap = c_v.get("snapshot_hash").and_then(|x| x.as_str());
                if b_snap != c_snap {
                    changes.push(DiffChange {
                        change_type: "knowledge_snapshot_changed".into(),
                        category: DiffCategory::Knowledge,
                        severity: Severity::Medium,
                        path: format!("genome.yaml#knowledge[{name}].snapshot_hash"),
                        before: b_snap.map(|s| serde_json::Value::String(s.into())),
                        after: c_snap.map(|s| serde_json::Value::String(s.into())),
                        explanation: format!(
                            "Knowledge '{name}' snapshot changed — replay required"
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    for name in b.keys() {
        if !c.contains_key(name) {
            changes.push(DiffChange {
                change_type: "knowledge_removed".into(),
                category: DiffCategory::Knowledge,
                severity: Severity::Medium,
                path: format!("genome.yaml#knowledge[{name}]"),
                before: b.get(name).cloned(),
                after: None,
                explanation: format!("Knowledge '{name}' removed"),
            });
        }
    }
}

fn diff_policies(
    b_g: &Option<serde_yaml::Value>,
    c_g: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let b = id_map(b_g, "policies");
    let c = id_map(c_g, "policies");
    for id in c.keys() {
        if !b.contains_key(id) {
            changes.push(DiffChange {
                change_type: "policy_added".into(),
                category: DiffCategory::Policies,
                severity: Severity::High,
                path: format!("genome.yaml#policies[{id}]"),
                before: None,
                after: c.get(id).cloned(),
                explanation: format!("Policy '{id}' added"),
            });
        }
    }
    for id in b.keys() {
        if !c.contains_key(id) {
            changes.push(DiffChange {
                change_type: "policy_removed".into(),
                category: DiffCategory::Policies,
                severity: Severity::High,
                path: format!("genome.yaml#policies[{id}]"),
                before: b.get(id).cloned(),
                after: None,
                explanation: format!("Policy '{id}' removed"),
            });
        }
    }
}

fn diff_memory(
    b_g: &Option<serde_yaml::Value>,
    c_g: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let b = b_g.as_ref().and_then(|g| g.get("memory")).cloned();
    let c = c_g.as_ref().and_then(|g| g.get("memory")).cloned();
    if b != c {
        changes.push(DiffChange {
            change_type: "memory_schema_changed".into(),
            category: DiffCategory::Memory,
            severity: Severity::Critical,
            path: "genome.yaml#memory".into(),
            before: b.and_then(|v| serde_json::to_value(v).ok()),
            after: c.and_then(|v| serde_json::to_value(v).ok()),
            explanation: "Memory schema changed — rollback safety risk".into(),
        });
    }
}

fn diff_contract_rules(
    b_c: &Option<serde_yaml::Value>,
    c_c: &Option<serde_yaml::Value>,
    changes: &mut Vec<DiffChange>,
) {
    let b = contract_rules(b_c);
    let c = contract_rules(c_c);
    for id in c.keys() {
        if !b.contains_key(id) {
            changes.push(DiffChange {
                change_type: "contract_rule_added".into(),
                category: DiffCategory::Contract,
                severity: Severity::Medium,
                path: format!("behavior.contract.yaml#rules[{id}]"),
                before: None,
                after: c.get(id).cloned(),
                explanation: format!("Contract rule '{id}' added"),
            });
        } else if b.get(id) != c.get(id) {
            changes.push(DiffChange {
                change_type: "contract_rule_changed".into(),
                category: DiffCategory::Contract,
                severity: Severity::Medium,
                path: format!("behavior.contract.yaml#rules[{id}]"),
                before: b.get(id).cloned(),
                after: c.get(id).cloned(),
                explanation: format!("Contract rule '{id}' changed"),
            });
        }
    }
    for id in b.keys() {
        if !c.contains_key(id) {
            changes.push(DiffChange {
                change_type: "contract_rule_removed".into(),
                category: DiffCategory::Contract,
                severity: Severity::High,
                path: format!("behavior.contract.yaml#rules[{id}]"),
                before: b.get(id).cloned(),
                after: None,
                explanation: format!("Contract rule '{id}' removed"),
            });
        }
    }
}

fn contract_rules(c: &Option<serde_yaml::Value>) -> BTreeMap<String, serde_json::Value> {
    let mut out = BTreeMap::new();
    if let Some(c) = c {
        if let Some(arr) = c
            .get("contract")
            .and_then(|x| x.get("rules"))
            .and_then(|x| x.as_sequence())
        {
            for r in arr {
                if let Some(id) = r.get("id").and_then(|x| x.as_str()) {
                    out.insert(
                        id.to_string(),
                        serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
                    );
                }
            }
        }
    }
    out
}

fn diff_prompts(
    b: &[(String, Vec<u8>)],
    c: &[(String, Vec<u8>)],
    ignore_ws: bool,
    changes: &mut Vec<DiffChange>,
) {
    let b_map: BTreeMap<&String, &Vec<u8>> = b
        .iter()
        .filter(|(p, _)| p.starts_with("prompts/"))
        .map(|(p, c)| (p, c))
        .collect();
    let c_map: BTreeMap<&String, &Vec<u8>> = c
        .iter()
        .filter(|(p, _)| p.starts_with("prompts/"))
        .map(|(p, c)| (p, c))
        .collect();
    for (path, c_bytes) in &c_map {
        match b_map.get(path) {
            None => changes.push(DiffChange {
                change_type: "prompt_added".into(),
                category: DiffCategory::Prompts,
                severity: Severity::Medium,
                path: (*path).clone(),
                before: None,
                after: None,
                explanation: format!("Prompt '{path}' added"),
            }),
            Some(b_bytes) => {
                let same = if ignore_ws {
                    normalize_ws(b_bytes) == normalize_ws(c_bytes)
                } else {
                    b_bytes == c_bytes
                };
                if !same {
                    changes.push(DiffChange {
                        change_type: "prompt_changed".into(),
                        category: DiffCategory::Prompts,
                        severity: Severity::Medium,
                        path: (*path).clone(),
                        before: None,
                        after: None,
                        explanation: format!("Prompt '{path}' content changed"),
                    });
                }
            }
        }
    }
    for path in b_map.keys() {
        if !c_map.contains_key(path) {
            changes.push(DiffChange {
                change_type: "prompt_removed".into(),
                category: DiffCategory::Prompts,
                severity: Severity::Medium,
                path: (*path).clone(),
                before: None,
                after: None,
                explanation: format!("Prompt '{path}' removed"),
            });
        }
    }
}

fn normalize_ws(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .into_bytes()
}

fn named_map(g: &Option<serde_yaml::Value>, key: &str) -> BTreeMap<String, serde_json::Value> {
    let g = match g {
        Some(g) => g,
        None => return BTreeMap::new(),
    };
    let mut out = BTreeMap::new();
    if let Some(arr) = g.get(key).and_then(|x| x.as_sequence()) {
        for item in arr {
            if let Some(name) = item.get("name").and_then(|x| x.as_str()) {
                out.insert(
                    name.to_string(),
                    serde_json::to_value(item).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    out
}

fn id_map(g: &Option<serde_yaml::Value>, key: &str) -> BTreeMap<String, serde_json::Value> {
    let g = match g {
        Some(g) => g,
        None => return BTreeMap::new(),
    };
    let mut out = BTreeMap::new();
    if let Some(arr) = g.get(key).and_then(|x| x.as_sequence()) {
        for item in arr {
            if let Some(id) = item.get("id").and_then(|x| x.as_str()) {
                out.insert(
                    id.to_string(),
                    serde_json::to_value(item).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_bundle(dir: &Path, fingerprint: &str, tools: &[&str]) {
        fs::create_dir_all(dir).unwrap();
        let tools_yaml = tools
            .iter()
            .map(|t| format!("  - name: '{t}'\n    protocol: 'mcp'"))
            .collect::<Vec<_>>()
            .join("\n");
        let genome = format!(
            "spec_version: '0.1'\nagent:\n  id: 'agent://acme/foo'\n  name: 'Foo'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\n  model_fingerprint: '{fingerprint}'\ntools:\n{tools_yaml}\nskills: []\nknowledge: []\npolicies: []\n"
        );
        fs::write(dir.join("genome.yaml"), genome).unwrap();
        fs::write(
            dir.join("agent.lock.yaml"),
            "spec_version: '0.1'\nagent_id: 'agent://acme/foo'\nmodel:\n  provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nknowledge: []\n",
        )
        .unwrap();
        fs::write(
            dir.join("behavior.contract.yaml"),
            "spec_version: '0.1'\ncontract:\n  id: 'c'\n  rules: []\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("prompts")).unwrap();
        fs::write(dir.join("prompts/system.md"), "you are helpful").unwrap();
    }

    #[test]
    fn fingerprint_change_is_medium_and_replay_required() {
        let b = tempdir().unwrap();
        let c = tempdir().unwrap();
        write_bundle(b.path(), "fp1", &["a"]);
        write_bundle(c.path(), "fp2", &["a"]);
        let r = diff_bundles(b.path(), c.path(), &DiffOptions::default()).unwrap();
        assert!(r.replay_required);
        assert!(r.changes.iter().any(
            |c| c.change_type == "model_fingerprint_changed" && c.severity == Severity::Medium
        ));
    }

    #[test]
    fn tool_added_is_medium() {
        let b = tempdir().unwrap();
        let c = tempdir().unwrap();
        write_bundle(b.path(), "fp1", &["a"]);
        write_bundle(c.path(), "fp1", &["a", "b"]);
        let r = diff_bundles(b.path(), c.path(), &DiffOptions::default()).unwrap();
        assert!(r
            .changes
            .iter()
            .any(|c| c.change_type == "tool_added" && c.severity == Severity::Medium));
    }

    #[test]
    fn tool_removed_is_high() {
        let b = tempdir().unwrap();
        let c = tempdir().unwrap();
        write_bundle(b.path(), "fp1", &["a", "b"]);
        write_bundle(c.path(), "fp1", &["a"]);
        let r = diff_bundles(b.path(), c.path(), &DiffOptions::default()).unwrap();
        assert!(r
            .changes
            .iter()
            .any(|c| c.change_type == "tool_removed" && c.severity == Severity::High));
        assert_eq!(r.overall_risk, Severity::High);
    }
}
