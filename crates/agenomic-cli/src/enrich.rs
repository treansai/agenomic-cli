//! `agm enrich` — LLM-assisted completion of the fields static detection
//! cannot know: domain, criticality, description, skills, behavior-contract
//! rules, and descriptions for generated orchestration manifests.
//!
//! Detection stays deterministic and offline; enrichment is the explicit,
//! opt-in network step (`agm enrich`, or `agm init|update --agent`). The
//! model only ever *proposes*: every change is schema-guarded before it is
//! written, placeholders are the only genome fields it may replace, and the
//! merge machinery treats enriched values as hand edits afterwards.

use std::collections::BTreeMap;
use std::path::Path;

use agenomic_core::{io_at, CliError, CliResult};
use serde::Deserialize;

/// Everything shown to the model.
pub struct EnrichInput {
    pub genome_text: String,
    pub readme: Option<String>,
    pub system_text: Option<String>,
    /// `(relative path, text)` for every workflow manifest.
    pub workflows: Vec<(String, String)>,
    pub env_required: Vec<String>,
    pub env_optional: Vec<String>,
}

const MAX_DOC: usize = 6000;

fn clip(s: &str) -> &str {
    &s[..s.len().min(MAX_DOC)]
}

/// Gather the on-disk context for the prompt.
pub fn gather(dir: &Path) -> CliResult<EnrichInput> {
    let genome_path = dir.join("genome.yaml");
    if !genome_path.is_file() {
        return Err(CliError::Schema(format!(
            "no genome.yaml at {}; run `agm init` first",
            dir.display()
        )));
    }
    let genome_text = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let readme = std::fs::read_to_string(dir.join("README.md")).ok();
    let system_text = std::fs::read_to_string(dir.join("system.yaml")).ok();
    let mut workflows = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir.join("workflows")) {
        let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.extension().and_then(|x| x.to_str()) == Some("yaml") {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    let rel = format!(
                        "workflows/{}",
                        p.file_name().and_then(|x| x.to_str()).unwrap_or("?")
                    );
                    workflows.push((rel, text));
                }
            }
        }
    }
    let orch = agenomic_detect::detect_orchestration(dir)?;
    Ok(EnrichInput {
        genome_text,
        readme,
        system_text,
        workflows,
        env_required: orch.env.required,
        env_optional: orch.env.optional,
    })
}

/// The JSON document the model must return.
#[derive(Debug, Default, Deserialize)]
pub struct Enrichment {
    pub domain: Option<String>,
    pub criticality: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub behavior_rules: Vec<BehaviorRule>,
    /// Keyed by manifest path (`system.yaml`, `workflows/<x>.yaml`).
    #[serde(default)]
    pub manifest_updates: BTreeMap<String, ManifestPatch>,
}

#[derive(Debug, Deserialize)]
pub struct BehaviorRule {
    pub id: String,
    #[serde(default = "default_rule_type")]
    pub rule_type: String,
    pub severity: String,
    pub description: String,
    #[serde(default)]
    pub forbidden_tools: Vec<String>,
}

fn default_rule_type() -> String {
    "deterministic".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ManifestPatch {
    pub domain: Option<String>,
    pub criticality: Option<String>,
    pub description: Option<String>,
}

pub fn build_prompt(input: &EnrichInput) -> String {
    let mut p = String::new();
    p.push_str(
        "You are completing the declarative manifests of an AI agent bundle (Agenomic format). \
         Static detection produced them from the repository; your job is to fill ONLY the \
         semantic fields it cannot know. Be factual: derive everything from the provided \
         context, never invent capabilities.\n\n\
         Respond with ONLY a JSON object (no markdown fences) of this shape:\n\
         {\n\
           \"domain\": \"<short domain tag, e.g. claims, support, devops>\",\n\
           \"criticality\": \"low|medium|high|critical\",\n\
           \"description\": \"<2-3 factual sentences>\",\n\
           \"skills\": [\"<snake_case capability>\", ...],\n\
           \"behavior_rules\": [{\"id\": \"<snake_case>\", \"rule_type\": \"deterministic\", \
             \"severity\": \"low|medium|high|critical\", \"description\": \"<invariant>\", \
             \"forbidden_tools\": []}, ...],\n\
           \"manifest_updates\": {\"<path>\": {\"domain\": \"...\", \"criticality\": \"...\", \
             \"description\": \"...\"}}\n\
         }\n\
         Rules: skills come from what the code actually does; behavior_rules are invariants a \
         reviewer would enforce (data the agent must never expose, actions requiring a human); \
         manifest_updates may only target the listed manifest paths; criticality reflects blast \
         radius (customer-facing/regulated/financial => high or critical).\n\n",
    );
    p.push_str("## genome.yaml\n");
    p.push_str(clip(&input.genome_text));
    if let Some(readme) = &input.readme {
        p.push_str("\n\n## README.md\n");
        p.push_str(clip(readme));
    }
    if let Some(system) = &input.system_text {
        p.push_str("\n\n## system.yaml\n");
        p.push_str(clip(system));
    }
    for (rel, text) in &input.workflows {
        p.push_str(&format!("\n\n## {rel}\n"));
        p.push_str(clip(text));
    }
    if !input.env_required.is_empty() || !input.env_optional.is_empty() {
        p.push_str(&format!(
            "\n\n## detected environment variables\nrequired: {:?}\noptional: {:?}\n",
            input.env_required, input.env_optional
        ));
    }
    p
}

/// Parse the model reply, tolerating markdown fences.
pub fn parse_enrichment(raw: &str) -> CliResult<Enrichment> {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.trim_end_matches("```"))
        .unwrap_or(trimmed);
    serde_json::from_str(body.trim())
        .map_err(|e| CliError::Schema(format!("enrichment reply is not valid JSON: {e}")))
}

const VALID_SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

/// Apply an enrichment to the bundle. Placeholder-guarded: the model may only
/// replace `general` / `low` / empty fields, never a value someone set.
/// Returns the bundle-relative paths changed.
pub fn apply(dir: &Path, e: &Enrichment) -> CliResult<Vec<String>> {
    let mut changed = Vec::new();

    // --- genome.yaml (via the canonical parse → mutate → emit cycle) -------
    let genome_path = dir.join("genome.yaml");
    let genome_text = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let mut g = agenomic_detect::parse_genome(&genome_text)?;
    let mut genome_dirty = false;
    if let Some(domain) = e.domain.as_deref().filter(|d| !d.is_empty()) {
        if g.domain == "general" && domain != "general" {
            g.domain = domain.to_string();
            genome_dirty = true;
        }
    }
    if let Some(criticality) = e.criticality.as_deref() {
        if VALID_SEVERITIES.contains(&criticality) && g.criticality == "low" && criticality != "low"
        {
            g.criticality = criticality.to_string();
            genome_dirty = true;
        }
    }
    if let Some(description) = e.description.as_deref().filter(|d| !d.is_empty()) {
        if g.description.is_none() {
            g.description = Some(description.trim().to_string());
            genome_dirty = true;
        }
    }
    if g.skills.is_empty() && !e.skills.is_empty() {
        g.skills = e.skills.iter().filter(|s| !s.is_empty()).cloned().collect();
        genome_dirty = !g.skills.is_empty() || genome_dirty;
    }
    if genome_dirty {
        let bundle = agenomic_detect::emit(&g);
        let report = agenomic_validate::validate_genome(&bundle.genome)?;
        if !report.valid {
            return Err(CliError::Schema(
                "enriched genome failed schema validation; nothing written".into(),
            ));
        }
        agenomic_fs::write_atomic(&genome_path, bundle.genome.as_bytes())?;
        changed.push("genome.yaml".to_string());
    }

    // --- behavior.contract.yaml --------------------------------------------
    let rules: Vec<&BehaviorRule> = e
        .behavior_rules
        .iter()
        .filter(|r| {
            !r.id.is_empty()
                && VALID_SEVERITIES.contains(&r.severity.as_str())
                && !r.description.is_empty()
        })
        .collect();
    if !rules.is_empty() {
        let contract_path = dir.join("behavior.contract.yaml");
        let current = std::fs::read_to_string(&contract_path).unwrap_or_default();
        let has_rules = serde_yaml::from_str::<serde_yaml::Value>(&current)
            .ok()
            .and_then(|v| {
                v.get("contract")
                    .and_then(|c| c.get("rules"))
                    .and_then(|r| r.as_sequence().map(|s| !s.is_empty()))
            })
            .unwrap_or(false);
        // Only fill an empty contract; hand-written rules are never touched.
        if !has_rules {
            let mut s = String::new();
            let prior_version = serde_yaml::from_str::<serde_yaml::Value>(&current)
                .ok()
                .and_then(|v| {
                    v.get("spec_version")
                        .and_then(|x| x.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| "0.1".to_string());
            s.push_str(&format!("spec_version: '{prior_version}'\n"));
            let id = serde_yaml::from_str::<serde_yaml::Value>(&current)
                .ok()
                .and_then(|v| {
                    v.get("contract")
                        .and_then(|c| c.get("id"))
                        .and_then(|x| x.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| "contract://example/v1".to_string());
            s.push_str("contract:\n");
            s.push_str(&format!("  id: '{id}'\n"));
            s.push_str("  rules:\n");
            for r in &rules {
                s.push_str(&format!("    - id: '{}'\n", r.id.replace('\'', "")));
                s.push_str(&format!(
                    "      type: '{}'\n",
                    r.rule_type.replace('\'', "")
                ));
                s.push_str(&format!("      severity: '{}'\n", r.severity));
                s.push_str(&format!(
                    "      description: '{}'\n",
                    r.description.replace('\'', "''")
                ));
                if !r.forbidden_tools.is_empty() {
                    s.push_str(&format!(
                        "      forbidden_tools: [{}]\n",
                        r.forbidden_tools
                            .iter()
                            .map(|t| format!("'{}'", t.replace('\'', "")))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            let report = agenomic_validate::validate_behavior_contract(&s)?;
            if report.valid {
                agenomic_fs::write_atomic(&contract_path, s.as_bytes())?;
                changed.push("behavior.contract.yaml".to_string());
            }
        }
    }

    // --- system.yaml / workflows/*.yaml -------------------------------------
    for (rel, patch) in &e.manifest_updates {
        let safe = rel == "system.yaml"
            || (rel.starts_with("workflows/") && rel.ends_with(".yaml") && !rel.contains(".."));
        if !safe {
            continue;
        }
        let path = dir.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut doc) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
            continue;
        };
        let root_key = if rel == "system.yaml" {
            "system"
        } else {
            "workflow"
        };
        let Some(block) = doc.get_mut(root_key).and_then(|b| b.as_mapping_mut()) else {
            continue;
        };
        let mut dirty = false;
        let mut set_if_placeholder = |key: &str, value: &Option<String>, placeholder: &str| {
            if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
                let k = serde_yaml::Value::String(key.to_string());
                let is_placeholder = block
                    .get(&k)
                    .and_then(|x| x.as_str())
                    .map(|x| x == placeholder)
                    .unwrap_or(true);
                if is_placeholder && v != placeholder {
                    block.insert(k, serde_yaml::Value::String(v.to_string()));
                    return true;
                }
            }
            false
        };
        dirty |= set_if_placeholder("domain", &patch.domain, "general");
        dirty |= set_if_placeholder("criticality", &patch.criticality, "low");
        dirty |= set_if_placeholder("description", &patch.description, "");
        if !dirty {
            continue;
        }
        let new_text = serde_yaml::to_string(&doc)
            .map_err(|err| CliError::Schema(format!("{rel}: re-serialize: {err}")))?;
        let report = if rel == "system.yaml" {
            agenomic_validate::validate_system(&new_text)?
        } else {
            agenomic_validate::validate_workflow(&new_text)?
        };
        if report.valid {
            agenomic_fs::write_atomic(&path, new_text.as_bytes())?;
            changed.push(rel.clone());
        }
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scaffold(dir: &Path) {
        let genome = "spec_version: '0.1'\nagent:\n  id: 'agent://acme/foo'\n  name: 'Foo'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'anthropic'\n  model_id: 'claude-sonnet-4-6'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n";
        std::fs::write(dir.join("genome.yaml"), genome).unwrap();
        std::fs::write(
            dir.join("behavior.contract.yaml"),
            "spec_version: '0.1'\ncontract:\n  id: 'contract://acme/v1'\n  rules: []\n",
        )
        .unwrap();
    }

    #[test]
    fn parse_tolerates_fences() {
        let e = parse_enrichment("```json\n{\"domain\": \"claims\"}\n```").unwrap();
        assert_eq!(e.domain.as_deref(), Some("claims"));
    }

    #[test]
    fn apply_fills_placeholders_only() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold(tmp.path());
        let e: Enrichment = serde_json::from_str(
            r#"{
                "domain": "claims",
                "criticality": "high",
                "description": "Handles guest claims.",
                "skills": ["classify_claim", "draft_response"],
                "behavior_rules": [
                    {"id": "no_auto_payout", "severity": "critical",
                     "description": "Never authorize a payout without human review."}
                ]
            }"#,
        )
        .unwrap();
        let changed = apply(tmp.path(), &e).unwrap();
        assert!(changed.contains(&"genome.yaml".to_string()));
        assert!(changed.contains(&"behavior.contract.yaml".to_string()));

        let genome = std::fs::read_to_string(tmp.path().join("genome.yaml")).unwrap();
        assert!(genome.contains("domain: 'claims'"));
        assert!(genome.contains("criticality: 'high'"));
        assert!(genome.contains("{ name: 'classify_claim' }"));
        let contract = std::fs::read_to_string(tmp.path().join("behavior.contract.yaml")).unwrap();
        assert!(contract.contains("no_auto_payout"));

        // Second apply with different values must be a no-op: nothing is a
        // placeholder anymore.
        let e2: Enrichment =
            serde_json::from_str(r#"{"domain": "other", "criticality": "medium"}"#).unwrap();
        let changed2 = apply(tmp.path(), &e2).unwrap();
        assert!(changed2.is_empty(), "{changed2:?}");
    }

    #[test]
    fn apply_rejects_path_traversal_in_manifest_updates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold(tmp.path());
        let mut updates = BTreeMap::new();
        updates.insert(
            "workflows/../../evil.yaml".to_string(),
            ManifestPatch {
                domain: Some("x".into()),
                criticality: None,
                description: None,
            },
        );
        let e = Enrichment {
            manifest_updates: updates,
            ..Default::default()
        };
        let changed = apply(tmp.path(), &e).unwrap();
        assert!(changed.is_empty());
    }
}
