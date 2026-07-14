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
    /// `(relative path, text)` for supplementary project docs (`docs/*.md`)
    /// that describe agents/architecture — the only evidence available when
    /// the repository has no README.
    pub extra_docs: Vec<(String, String)>,
    pub env_required: Vec<String>,
    pub env_optional: Vec<String>,
}

const MAX_DOC: usize = 6000;
/// Architecture/agent docs get a larger window: they are the evidence for
/// the multi-agent system manifest and truncating them drops agents.
const MAX_EXTRA_DOC: usize = 16000;

fn clip(s: &str) -> &str {
    clip_to(s, MAX_DOC)
}

/// Byte-bounded, char-boundary-safe prefix.
fn clip_to(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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
    let mut extra_docs = Vec::new();
    for name in ["agents.md", "overview.md", "architecture.md"] {
        let p = dir.join("docs").join(name);
        if let Ok(text) = std::fs::read_to_string(&p) {
            extra_docs.push((format!("docs/{name}"), text));
        }
    }
    let orch = agenomic_detect::detect_orchestration(dir)?;
    Ok(EnrichInput {
        genome_text,
        readme,
        system_text,
        workflows,
        extra_docs,
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
    /// A complete spec-0.2 `system.yaml` proposed by the model for
    /// multi-agent systems static detection cannot recover (e.g. custom
    /// runtimes). Only honored when the bundle has no `system.yaml` yet, and
    /// only after full schema + semantic validation.
    pub system_manifest: Option<String>,
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
    if input.system_text.is_none() {
        p.push_str(
            "This bundle has NO system.yaml. If (and only if) the provided context shows the \
             project is a MULTI-AGENT system — multiple named agents coordinated by an \
             orchestrator, supervisor, pipeline, or graph — additionally return a \
             \"system_manifest\" key whose value is the complete YAML text of a system.yaml \
             (Agenomic spec 0.2 orchestration manifest). Declare every real agent named in the \
             context; do not invent agents. Shape:\n\
             spec_version: '0.2'\n\
             system:\n\
             \x20 id: 'system://<org>/<name>'\n\
             \x20 name: '<name>'\n\
             \x20 domain: '<domain>'\n\
             \x20 criticality: 'low|medium|high|critical'\n\
             \x20 description: '<factual summary>'\n\
             agents:\n\
             \x20 - role: '<unique_role>'\n\
             \x20   id: 'agent://<org>/<kebab-name>'\n\
             \x20   description: '<what it does>'\n\
             orchestration:\n\
             \x20 style: 'pipeline|graph|supervisor|swarm|custom'\n\
             \x20 supervisor: '<role, required for supervisor style>'\n\
             \x20 entrypoint: '<role>'\n\
             \x20 edges:\n\
             \x20 - { from: '<role>', to: '<role or END>' }\n\
             Semantic rules the validator enforces: roles are unique; entrypoint, supervisor, \
             and every edge endpoint must be a declared role ('END' is the only non-role \
             target); do not declare a workflows list. If the project is a single agent, omit \
             \"system_manifest\" entirely.\n\n",
        );
    }
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
    for (rel, text) in &input.extra_docs {
        p.push_str(&format!("\n\n## {rel}\n"));
        p.push_str(clip_to(text, MAX_EXTRA_DOC));
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

    // --- synthesized system.yaml ---------------------------------------------
    // Absence is the placeholder: a proposed manifest is only written when the
    // bundle has no system.yaml, and only if it passes the full spec-0.2
    // schema + semantic validation. An existing file — detected or
    // hand-written — is never touched.
    if let Some(manifest) = e.system_manifest.as_deref().map(str::trim) {
        let system_path = dir.join("system.yaml");
        if !manifest.is_empty() && !system_path.exists() {
            let body = manifest
                .strip_prefix("```yaml")
                .or_else(|| manifest.strip_prefix("```"))
                .map(|s| s.trim_end_matches("```"))
                .unwrap_or(manifest)
                .trim();
            let text = format!("{body}\n");
            let report = agenomic_validate::validate_system(&text)?;
            if report.valid {
                agenomic_fs::write_atomic(&system_path, text.as_bytes())?;
                changed.push("system.yaml".to_string());
            } else {
                eprintln!(
                    "warning: proposed system.yaml failed validation and was discarded:"
                );
                for issue in &report.errors {
                    eprintln!("  - {}", issue.message);
                }
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

    const VALID_SYSTEM: &str = "spec_version: '0.2'\nsystem:\n  id: 'system://acme/orchestra'\n  name: 'Orchestra'\nagents:\n  - role: 'planner'\n    id: 'agent://acme/planner'\n  - role: 'executor'\n    id: 'agent://acme/executor'\norchestration:\n  style: 'supervisor'\n  supervisor: 'planner'\n  entrypoint: 'planner'\n  edges:\n    - from: 'planner'\n      to: 'executor'\n    - from: 'executor'\n      to: 'END'\n";

    #[test]
    fn apply_writes_valid_system_manifest_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold(tmp.path());
        let e = Enrichment {
            system_manifest: Some(format!("```yaml\n{VALID_SYSTEM}```")),
            ..Default::default()
        };
        let changed = apply(tmp.path(), &e).unwrap();
        assert!(changed.contains(&"system.yaml".to_string()), "{changed:?}");
        let written = std::fs::read_to_string(tmp.path().join("system.yaml")).unwrap();
        assert!(written.contains("role: 'planner'"));
        assert!(!written.contains("```"));
    }

    #[test]
    fn apply_never_overwrites_existing_system_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold(tmp.path());
        std::fs::write(tmp.path().join("system.yaml"), "spec_version: '0.2'\n").unwrap();
        let e = Enrichment {
            system_manifest: Some(VALID_SYSTEM.to_string()),
            ..Default::default()
        };
        let changed = apply(tmp.path(), &e).unwrap();
        assert!(!changed.contains(&"system.yaml".to_string()), "{changed:?}");
        let untouched = std::fs::read_to_string(tmp.path().join("system.yaml")).unwrap();
        assert_eq!(untouched, "spec_version: '0.2'\n");
    }

    #[test]
    fn apply_discards_invalid_system_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold(tmp.path());
        // Edge target 'ghost' is not a declared role — semantic check fails.
        let bad = VALID_SYSTEM.replace("to: 'executor'", "to: 'ghost'");
        let e = Enrichment {
            system_manifest: Some(bad),
            ..Default::default()
        };
        let changed = apply(tmp.path(), &e).unwrap();
        assert!(!changed.contains(&"system.yaml".to_string()), "{changed:?}");
        assert!(!tmp.path().join("system.yaml").exists());
    }

    #[test]
    fn clip_to_respects_char_boundaries() {
        let s = "aé".repeat(4000); // 'é' is 2 bytes; boundary can land mid-char
        let clipped = clip_to(&s, MAX_DOC);
        assert!(clipped.len() <= MAX_DOC);
        assert!(s.starts_with(clipped));
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
