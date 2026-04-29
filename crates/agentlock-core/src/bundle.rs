use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use crate::errors::AgentlockError;
use crate::models::{
    AgentLock, AgentMetadata, BehaviorContract, ContractDefinition, DeterministicCheck, Genome,
    KnowledgeSnapshot, LoadedBundle, ModelConfig, Policy, ToolSpec, TrackedFile,
};

pub const GENOME_FILE: &str = "genome.yaml";
pub const AGENT_LOCK_FILE: &str = "agent.lock.yaml";
pub const BEHAVIOR_CONTRACT_FILE: &str = "behavior.contract.yaml";
pub const PROMPTS_DIR: &str = "prompts";
pub const SYSTEM_PROMPT_FILE: &str = "prompts/system.md";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFileEntry {
    pub relative_path: String,
    pub absolute_path: PathBuf,
}

pub fn init_bundle_dir(path: &Path) -> Result<()> {
    let bundle_id = slugify_bundle_name(path);
    let display_name = title_case_name(&bundle_id);
    let contract_id = format!("{bundle_id}-contract-v1");
    let root = path;

    fs::create_dir_all(root.join(PROMPTS_DIR))
        .with_context(|| format!("failed to create `{}`", root.display()))?;

    for relative in [
        GENOME_FILE,
        AGENT_LOCK_FILE,
        BEHAVIOR_CONTRACT_FILE,
        SYSTEM_PROMPT_FILE,
    ] {
        let target = root.join(relative);
        if target.exists() {
            anyhow::bail!("refusing to overwrite existing file `{}`", target.display());
        }
    }

    let genome = Genome {
        schema_version: 1,
        agent: AgentMetadata {
            id: bundle_id.clone(),
            name: display_name.clone(),
            version: "0.1.0".to_owned(),
            description: Some(format!("A starter AgentLock bundle for {display_name}.")),
        },
        model: ModelConfig {
            provider: "local-stub".to_owned(),
            model: "deterministic-replay".to_owned(),
            temperature: Some(0.0),
            max_input_tokens: None,
            max_output_tokens: Some(512),
        },
        tools: vec![ToolSpec {
            id: format!("{bundle_id}.lookup"),
            description: Some("Example read-only lookup tool.".to_owned()),
            kind: Some("read_only".to_owned()),
        }],
        knowledge_snapshots: vec![KnowledgeSnapshot {
            id: format!("{bundle_id}-knowledge"),
            digest: format!("sha256:{bundle_id}-knowledge"),
            description: Some("Example knowledge snapshot placeholder.".to_owned()),
            uri: Some(format!("local://knowledge/{bundle_id}")),
        }],
    };

    let agent_lock = AgentLock {
        schema_version: 1,
        agent_id: bundle_id.clone(),
        behavior_contract_id: contract_id.clone(),
        tracked_files: vec![
            TrackedFile {
                path: GENOME_FILE.to_owned(),
                blake3: None,
            },
            TrackedFile {
                path: BEHAVIOR_CONTRACT_FILE.to_owned(),
                blake3: None,
            },
            TrackedFile {
                path: SYSTEM_PROMPT_FILE.to_owned(),
                blake3: None,
            },
        ],
    };

    let behavior_contract = BehaviorContract {
        schema_version: 1,
        contract: ContractDefinition {
            id: contract_id,
            description: Some("Starter deterministic checks for local replay.".to_owned()),
            policies: vec![Policy {
                id: "provide-final-answer".to_owned(),
                description: "Always provide a final answer in the assistant output.".to_owned(),
            }],
            checks: vec![
                DeterministicCheck::RequireFinalOutput {
                    id: "final-answer-present".to_owned(),
                    description: Some("Require at least one assistant output event.".to_owned()),
                },
                DeterministicCheck::MaxTotalEvents {
                    id: "bounded-events".to_owned(),
                    description: Some("Keep starter traces small and deterministic.".to_owned()),
                    max: 12,
                },
            ],
        },
    };

    write_yaml_file(&root.join(GENOME_FILE), &genome)?;
    write_yaml_file(&root.join(AGENT_LOCK_FILE), &agent_lock)?;
    write_yaml_file(&root.join(BEHAVIOR_CONTRACT_FILE), &behavior_contract)?;

    let system_prompt = format!(
        "# {display_name}\n\n\
You are the {bundle_id} bundle.\n\
Follow the behavior contract, use only approved tools, and provide a concise final answer.\n"
    );
    fs::write(root.join(SYSTEM_PROMPT_FILE), system_prompt).with_context(|| {
        format!(
            "failed to write `{}`",
            root.join(SYSTEM_PROMPT_FILE).display()
        )
    })?;

    Ok(())
}

pub fn load_bundle_dir(path: &Path) -> Result<LoadedBundle> {
    if !path.exists() {
        return Err(AgentlockError::MissingPath(path.display().to_string()).into());
    }
    if !path.is_dir() {
        return Err(AgentlockError::NotADirectory(path.display().to_string()).into());
    }

    let genome: Genome = load_yaml_struct(&path.join(GENOME_FILE))?;
    let agent_lock: AgentLock = load_yaml_struct(&path.join(AGENT_LOCK_FILE))?;
    let behavior_contract: BehaviorContract = load_yaml_struct(&path.join(BEHAVIOR_CONTRACT_FILE))?;
    let prompts = load_prompt_files(path)?;

    Ok(LoadedBundle {
        root: path.to_path_buf(),
        genome,
        agent_lock,
        behavior_contract,
        prompts,
    })
}

pub fn collect_bundle_file_entries(
    path: &Path,
    bundle: &LoadedBundle,
) -> Result<Vec<BundleFileEntry>> {
    let mut included = BTreeSet::new();

    for required in [GENOME_FILE, AGENT_LOCK_FILE, BEHAVIOR_CONTRACT_FILE] {
        included.insert(required.to_owned());
    }

    for prompt_name in bundle.prompts.keys() {
        included.insert(prompt_name.clone());
    }

    let prompts_root = path.join(PROMPTS_DIR);
    if prompts_root.exists() {
        for entry in walkdir::WalkDir::new(&prompts_root)
            .sort_by_file_name()
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let relative = normalized_relative_path(path, entry.path())?;
                included.insert(relative);
            }
        }
    }

    let knowledge_root = path.join("knowledge");
    if knowledge_root.exists() {
        for entry in walkdir::WalkDir::new(&knowledge_root)
            .sort_by_file_name()
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let relative = normalized_relative_path(path, entry.path())?;
                included.insert(relative);
            }
        }
    }

    for tracked in &bundle.agent_lock.tracked_files {
        included.insert(tracked.path.clone());
    }

    included
        .into_iter()
        .map(|relative_path| {
            let normalized = normalized_relative_components(Path::new(&relative_path))?;
            let absolute_path = path.join(&normalized);
            if !absolute_path.exists() {
                return Err(AgentlockError::MissingTrackedFile(relative_path).into());
            }
            Ok(BundleFileEntry {
                relative_path: normalized
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
                absolute_path,
            })
        })
        .collect()
}

pub fn normalized_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("`{}` is not inside `{}`", path.display(), root.display()))?;
    Ok(normalized_relative_components(relative)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

pub fn default_attestation_output(source: &Path) -> PathBuf {
    if source.is_dir() {
        source.join("release_attestation.json")
    } else {
        source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("release_attestation.json")
    }
}

fn write_yaml_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let yaml = serde_yaml::to_string(value)
        .with_context(|| format!("failed to serialize `{}`", path.display()))?;
    fs::write(path, yaml).with_context(|| format!("failed to write `{}`", path.display()))?;
    Ok(())
}

fn load_yaml_struct<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    serde_yaml::from_slice(&bytes).with_context(|| format!("invalid YAML in `{}`", path.display()))
}

fn load_prompt_files(path: &Path) -> Result<BTreeMap<String, String>> {
    let prompts_root = path.join(PROMPTS_DIR);
    let mut prompts = BTreeMap::new();

    if !prompts_root.exists() {
        return Ok(prompts);
    }

    for entry in walkdir::WalkDir::new(&prompts_root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = normalized_relative_path(path, entry.path())?;
        let bytes = fs::read(entry.path())
            .with_context(|| format!("failed to read `{}`", entry.path().display()))?;
        let content =
            String::from_utf8(bytes).map_err(|_| AgentlockError::InvalidUtf8(relative.clone()))?;
        prompts.insert(relative, content);
    }

    Ok(prompts)
}

fn slugify_bundle_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("agent-bundle");

    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "agent-bundle".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn title_case_name(slug: &str) -> String {
    slug.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut out = String::new();
                    out.push(first.to_ascii_uppercase());
                    out.push_str(chars.as_str());
                    out
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalized_relative_components(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AgentlockError::EscapingPath(path.display().to_string()).into())
            }
        }
    }
    Ok(normalized)
}
