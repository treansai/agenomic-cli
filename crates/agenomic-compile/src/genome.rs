//! Typed view of the parts of `genome.yaml` the compilers consume, plus a
//! bundle loader that resolves skill prompt files relative to the bundle root.
//!
//! Only the fields the code generators actually read are typed; everything
//! else in the genome is ignored (`#[serde(default)]` + lenient parsing) so a
//! richer future genome still compiles.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{CompileError, CompileResult};

/// The compiler's view of a genome bundle: the parsed `genome.yaml` plus the
/// resolved text of the system prompt and each skill prompt.
#[derive(Debug, Clone)]
pub struct Genome {
    /// Parsed `genome.yaml`.
    pub spec: GenomeSpec,
    /// Contents of `prompts/system.md`, if present.
    pub system_prompt: Option<String>,
    /// Skill name → resolved prompt text, in genome declaration order. Skills
    /// whose `prompt` file is missing are kept with `text: None` so the
    /// generated adapter still lists them (and the gap is visible).
    pub skill_prompts: Vec<ResolvedSkill>,
}

/// A skill paired with the text loaded from its `prompt` file.
#[derive(Debug, Clone)]
pub struct ResolvedSkill {
    pub name: String,
    /// The declared `prompt` path (relative to the bundle), if any.
    pub prompt_path: Option<String>,
    /// The loaded prompt text, if the file existed and was readable.
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenomeSpec {
    pub spec_version: String,
    pub agent: Agent,
    pub runtime: Runtime,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub skills: Vec<Skill>,
    #[serde(default)]
    pub knowledge: Vec<Knowledge>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub criticality: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Runtime {
    pub model_provider: String,
    pub model_id: String,
    #[serde(default)]
    pub temperature: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Skill {
    pub name: String,
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Knowledge {
    pub name: String,
    #[serde(default)]
    pub snapshot_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub id: String,
    #[serde(default)]
    pub source: Option<String>,
}

impl Genome {
    /// Load and resolve a genome bundle rooted at `bundle_dir`.
    ///
    /// Reads `genome.yaml`, then `prompts/system.md` and each skill's `prompt`
    /// file (paths are taken relative to the bundle root). Missing optional
    /// prompt files are tolerated; a missing or malformed `genome.yaml` is a
    /// hard error.
    pub fn load(bundle_dir: &Path) -> CompileResult<Self> {
        let genome_path = bundle_dir.join("genome.yaml");
        let raw = std::fs::read_to_string(&genome_path).map_err(|e| CompileError::Io {
            path: genome_path.clone(),
            source: e,
        })?;
        Self::from_yaml(&raw, bundle_dir)
    }

    /// Parse a `genome.yaml` string and resolve prompt files under `bundle_dir`.
    pub fn from_yaml(yaml: &str, bundle_dir: &Path) -> CompileResult<Self> {
        let spec: GenomeSpec = serde_yaml::from_str(yaml)
            .map_err(|e| CompileError::Genome(format!("genome.yaml: {e}")))?;

        let system_prompt = read_optional(&bundle_dir.join("prompts/system.md"));

        let skill_prompts = spec
            .skills
            .iter()
            .map(|s| {
                let text = s
                    .prompt
                    .as_ref()
                    .and_then(|rel| read_optional(&bundle_dir.join(rel)));
                ResolvedSkill {
                    name: s.name.clone(),
                    prompt_path: s.prompt.clone(),
                    text,
                }
            })
            .collect();

        Ok(Self {
            spec,
            system_prompt,
            skill_prompts,
        })
    }

    /// Slug derived from the agent id (`agent://org/name` → `name`), suitable
    /// for use as a Python identifier seed and titles. Falls back to the full
    /// id when it has no path segment.
    pub fn agent_slug(&self) -> String {
        self.spec
            .agent
            .id
            .rsplit(['/', ':'])
            .find(|s| !s.is_empty())
            .unwrap_or(&self.spec.agent.id)
            .to_string()
    }
}

/// Read a file to a string, returning `None` (not an error) when it is absent
/// or unreadable — used for optional prompt files.
fn read_optional(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Turn an arbitrary label into a safe Python identifier (`[a-z0-9_]`, never
/// leading-digit). Deterministic and total.
pub fn py_ident(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    let base = if trimmed.is_empty() {
        "skill".to_string()
    } else {
        trimmed
    };
    if base.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("s_{base}")
    } else {
        base
    }
}

#[allow(dead_code)]
fn _assert_pathbuf_used(_: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    const GENOME: &str = r#"
spec_version: '0.1'
agent:
  id: 'agent://treans/claims-agent'
  name: 'Claims Agent'
  domain: 'insurance'
  criticality: 'high'
runtime:
  model_provider: 'openai'
  model_id: 'gpt-4o'
  temperature: 0.0
tools:
  - name: 'classify_claim'
    protocol: 'mcp'
    server: 'mcp://internal/claims'
    version: '1.2.0'
skills:
  - name: 'classify_claim'
    prompt: 'prompts/skills/classify_claim.md'
knowledge: []
policies: []
"#;

    #[test]
    fn parses_and_resolves_missing_prompts_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let g = Genome::from_yaml(GENOME, dir.path()).unwrap();
        assert_eq!(g.spec.agent.name, "Claims Agent");
        assert_eq!(g.spec.runtime.model_id, "gpt-4o");
        assert_eq!(g.skill_prompts.len(), 1);
        assert_eq!(g.skill_prompts[0].name, "classify_claim");
        assert!(g.skill_prompts[0].text.is_none(), "missing file → None");
        assert!(g.system_prompt.is_none());
    }

    #[test]
    fn resolves_prompt_files_when_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("prompts/skills")).unwrap();
        std::fs::write(dir.path().join("prompts/system.md"), "You are helpful.").unwrap();
        std::fs::write(
            dir.path().join("prompts/skills/classify_claim.md"),
            "Classify the claim.",
        )
        .unwrap();
        let g = Genome::from_yaml(GENOME, dir.path()).unwrap();
        assert_eq!(g.system_prompt.as_deref(), Some("You are helpful."));
        assert_eq!(
            g.skill_prompts[0].text.as_deref(),
            Some("Classify the claim.")
        );
    }

    #[test]
    fn agent_slug_extracts_last_segment() {
        let dir = tempfile::tempdir().unwrap();
        let g = Genome::from_yaml(GENOME, dir.path()).unwrap();
        assert_eq!(g.agent_slug(), "claims-agent");
    }

    #[test]
    fn py_ident_is_safe() {
        assert_eq!(py_ident("classify_claim"), "classify_claim");
        assert_eq!(py_ident("Compensation Reasoning"), "compensation_reasoning");
        assert_eq!(py_ident("7-eleven"), "s_7_eleven");
        assert_eq!(py_ident("---"), "skill");
    }
}
