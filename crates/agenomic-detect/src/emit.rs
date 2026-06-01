//! Canonical emission of the four bundle files from a [`DetectedGenome`].
//!
//! The genome serializer is hand-written (not serde_yaml) to reproduce the
//! exact layout in `docs/init-and-update.md` §2.5 — single-quoted scalars, a
//! `description: |` block, an `authors` block sequence, and `tools` rendered as
//! column-aligned flow mappings — and to stay byte-identical to the legacy
//! `cmd_init` output when given the defaults (so the empty-dir path is
//! unchanged). Provenance is emitted separately into the `.agenomic/` sidecar
//! (see [`crate::provenance`]).

use std::path::Path;

use agenomic_core::CliResult;

use crate::model::{DetectedGenome, ToolEntry};

/// The byte contents of the four canonical bundle files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedBundle {
    pub genome: String,
    pub lock: String,
    pub contract: String,
    pub system_prompt: String,
}

/// Render the four bundle files from a detected genome.
///
/// ```
/// use agenomic_detect::{emit, DetectedGenome};
/// let b = emit(&DetectedGenome::defaults());
/// assert!(b.genome.starts_with("spec_version: '0.1'\n"));
/// assert!(b.genome.contains("tools: []\n"));
/// ```
pub fn emit(genome: &DetectedGenome) -> EmittedBundle {
    EmittedBundle {
        genome: emit_genome(genome),
        lock: emit_lock(genome),
        contract: emit_contract(genome),
        system_prompt: "You are a helpful agent.\n".to_string(),
    }
}

/// Write the four bundle files under `dir`. When `force` is false, an existing
/// file is left untouched (legacy `write_if_missing` semantics); when true it is
/// overwritten. Writes are atomic and create parent directories.
///
/// ```no_run
/// use agenomic_detect::{emit, write_bundle, DetectedGenome};
/// use std::path::Path;
/// let b = emit(&DetectedGenome::defaults());
/// write_bundle(Path::new("/tmp/agent"), &b, false).unwrap();
/// ```
pub fn write_bundle(dir: &Path, bundle: &EmittedBundle, force: bool) -> CliResult<()> {
    write_one(&dir.join("genome.yaml"), &bundle.genome, force)?;
    write_one(&dir.join("agent.lock.yaml"), &bundle.lock, force)?;
    write_one(&dir.join("behavior.contract.yaml"), &bundle.contract, force)?;
    write_one(&dir.join("prompts/system.md"), &bundle.system_prompt, force)?;
    Ok(())
}

fn write_one(path: &Path, content: &str, force: bool) -> CliResult<()> {
    if !force && path.exists() {
        return Ok(());
    }
    agenomic_fs::write_atomic(path, content.as_bytes())
}

/// Single-quote a YAML scalar, doubling any embedded single quote.
fn yq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Right-pad `cell` with spaces to `width`.
fn pad(cell: &str, width: usize) -> String {
    let mut c = cell.to_string();
    c.push_str(&" ".repeat(width.saturating_sub(cell.len())));
    c
}

/// Organisation segment of an `agent://<org>/<repo>` id (for the contract id).
fn agent_org(agent_id: &str) -> &str {
    agent_id
        .strip_prefix("agent://")
        .and_then(|rest| rest.split('/').next())
        .filter(|s| !s.is_empty())
        .unwrap_or("example")
}

fn emit_genome(g: &DetectedGenome) -> String {
    let mut s = String::new();
    s.push_str(&format!("spec_version: {}\n", yq(&g.spec_version)));
    s.push_str("agent:\n");
    s.push_str(&format!("  id: {}\n", yq(&g.agent_id)));
    s.push_str(&format!("  name: {}\n", yq(&g.agent_name)));
    s.push_str(&format!("  domain: {}\n", yq(&g.domain)));
    s.push_str(&format!("  criticality: {}\n", yq(&g.criticality)));
    if !g.authors.is_empty() {
        s.push_str("  authors:\n");
        for a in &g.authors {
            s.push_str(&format!("    - {}\n", yq(a)));
        }
    }
    if let Some(desc) = g.description.as_deref().filter(|d| !d.is_empty()) {
        s.push_str("description: |\n");
        for line in desc.lines() {
            s.push_str(&format!("  {line}\n"));
        }
    }
    s.push_str("runtime:\n");
    if let Some(fw) = &g.framework {
        s.push_str(&format!("  framework: {}\n", yq(fw)));
    }
    if let Some(rk) = &g.runtime_kind {
        s.push_str(&format!("  runtime_kind: {}\n", yq(rk)));
    }
    s.push_str(&format!("  model_provider: {}\n", yq(&g.model_provider)));
    s.push_str(&format!("  model_id: {}\n", yq(&g.model_id)));
    if let Some(ep) = &g.entrypoint {
        s.push_str(&format!("  entrypoint: {}\n", yq(ep)));
    }
    if let Some(mem) = &g.memory {
        s.push_str("  memory:\n");
        s.push_str(&format!("    enabled: {}\n", mem.enabled));
        s.push_str(&format!("    backend: {}\n", yq(&mem.backend)));
    }
    s.push_str(&emit_list("tools", &format_tools(&g.tools)));
    s.push_str(&emit_str_list("skills", &g.skills));
    s.push_str(&emit_str_list("knowledge", &g.knowledge));
    s.push_str(&emit_str_list("policies", &g.policies));
    s
}

/// Render `tools:` as column-aligned flow mappings (§2.5), or empty.
fn format_tools(tools: &[ToolEntry]) -> Vec<String> {
    let name_cells: Vec<String> = tools.iter().map(|t| format!("{},", yq(&t.name))).collect();
    let versioned_kind_cells: Vec<String> = tools
        .iter()
        .filter(|t| t.version.is_some())
        .map(|t| format!("{},", yq(t.kind.label())))
        .collect();
    let name_w = name_cells.iter().map(String::len).max().unwrap_or(0);
    let kind_w = versioned_kind_cells
        .iter()
        .map(String::len)
        .max()
        .unwrap_or(0);

    tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut line = format!("{{ name: {} ", pad(&name_cells[i], name_w));
            match &t.version {
                Some(v) => {
                    let kind_cell = format!("{},", yq(t.kind.label()));
                    line.push_str(&format!(
                        "kind: {} version: {} }}",
                        pad(&kind_cell, kind_w),
                        yq(v)
                    ));
                }
                None => line.push_str(&format!("kind: {} }}", yq(t.kind.label()))),
            }
            line
        })
        .collect()
}

/// Emit a `key:` block: `key: []` if empty, else a block sequence of the
/// pre-rendered (already flow-formatted) items.
fn emit_list(key: &str, items: &[String]) -> String {
    if items.is_empty() {
        return format!("{key}: []\n");
    }
    let mut s = format!("{key}:\n");
    for item in items {
        s.push_str(&format!("  - {item}\n"));
    }
    s
}

fn emit_str_list(key: &str, items: &[String]) -> String {
    if items.is_empty() {
        return format!("{key}: []\n");
    }
    let mut s = format!("{key}:\n");
    for item in items {
        s.push_str(&format!("  - {}\n", yq(item)));
    }
    s
}

fn emit_lock(g: &DetectedGenome) -> String {
    let mut s = String::new();
    s.push_str(&format!("spec_version: {}\n", yq(&g.spec_version)));
    s.push_str(&format!("agent_id: {}\n", yq(&g.agent_id)));
    s.push_str("model:\n");
    s.push_str(&format!("  provider: {}\n", yq(&g.model_provider)));
    s.push_str(&format!("  model_id: {}\n", yq(&g.model_id)));
    let tool_names: Vec<String> = g.tools.iter().map(|t| t.name.clone()).collect();
    s.push_str(&emit_str_list("tools", &tool_names));
    s.push_str("knowledge: []\n");
    s
}

fn emit_contract(g: &DetectedGenome) -> String {
    let mut s = String::new();
    s.push_str(&format!("spec_version: {}\n", yq(&g.spec_version)));
    s.push_str("contract:\n");
    s.push_str(&format!(
        "  id: {}\n",
        yq(&format!("contract://{}/v1", agent_org(&g.agent_id)))
    ));
    s.push_str("  rules: []\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemoryInfo, ToolKind};

    /// The legacy empty-dir output must be byte-identical to the old `cmd_init`.
    #[test]
    fn defaults_match_legacy_bytes() {
        let b = emit(&DetectedGenome::defaults());
        let expected_genome = "spec_version: '0.1'\n\
agent:\n  id: 'agent://example/new'\n  name: 'Example Agent'\n  domain: 'general'\n  criticality: 'low'\n\
runtime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\n\
tools: []\nskills: []\nknowledge: []\npolicies: []\n";
        assert_eq!(b.genome, expected_genome);

        let expected_lock = "spec_version: '0.1'\n\
agent_id: 'agent://example/new'\n\
model:\n  provider: 'openai'\n  model_id: 'gpt-4o'\n\
tools: []\nknowledge: []\n";
        assert_eq!(b.lock, expected_lock);

        let expected_contract =
            "spec_version: '0.1'\ncontract:\n  id: 'contract://example/v1'\n  rules: []\n";
        assert_eq!(b.contract, expected_contract);

        assert_eq!(b.system_prompt, "You are a helpful agent.\n");
    }

    /// The codedrift genome must match §2.5 byte-for-byte.
    #[test]
    fn codedrift_genome_matches_spec_2_5() {
        let g = DetectedGenome {
            spec_version: "0.1".into(),
            agent_id: "agent://traidano/agenomic-codedrift".into(),
            agent_name: "codedrift-agent".into(),
            domain: "general".into(),
            criticality: "low".into(),
            authors: vec!["Traidano <dev@traidano.com>".into()],
            description: Some(
                "E2E test agent — measures Claude code-quality drift over a fixed benchmark".into(),
            ),
            framework: Some("langgraph".into()),
            runtime_kind: Some("python".into()),
            model_provider: "anthropic".into(),
            model_id: "claude-sonnet-4-6".into(),
            entrypoint: Some("agenomic_codedrift.__main__:main".into()),
            memory: None,
            tools: vec![
                ToolEntry {
                    name: "ruff".into(),
                    kind: ToolKind::Linter,
                    version: Some(">=0.6.0".into()),
                },
                ToolEntry {
                    name: "radon".into(),
                    kind: ToolKind::Complexity,
                    version: Some(">=6.0.1".into()),
                },
                ToolEntry {
                    name: "bandit".into(),
                    kind: ToolKind::Security,
                    version: Some(">=1.7.9".into()),
                },
            ],
            skills: vec![],
            knowledge: vec![],
            policies: vec![],
            evidence: vec![],
        };
        let expected = "spec_version: '0.1'
agent:
  id: 'agent://traidano/agenomic-codedrift'
  name: 'codedrift-agent'
  domain: 'general'
  criticality: 'low'
  authors:
    - 'Traidano <dev@traidano.com>'
description: |
  E2E test agent — measures Claude code-quality drift over a fixed benchmark
runtime:
  framework: 'langgraph'
  runtime_kind: 'python'
  model_provider: 'anthropic'
  model_id: 'claude-sonnet-4-6'
  entrypoint: 'agenomic_codedrift.__main__:main'
tools:
  - { name: 'ruff',   kind: 'linter',     version: '>=0.6.0' }
  - { name: 'radon',  kind: 'complexity', version: '>=6.0.1' }
  - { name: 'bandit', kind: 'security',   version: '>=1.7.9' }
skills: []
knowledge: []
policies: []
";
        assert_eq!(emit_genome(&g), expected);
    }

    #[test]
    fn memory_block_emitted_when_present() {
        let mut g = DetectedGenome::defaults();
        g.memory = Some(MemoryInfo {
            enabled: true,
            backend: "redis".into(),
        });
        let out = emit_genome(&g);
        assert!(out.contains("  memory:\n    enabled: true\n    backend: 'redis'\n"));
    }
}
