//! Compile a bundle's `genome.yaml` into adapter-specific runtime artifacts.
//!
//! The generated files live under `runtime/` and are deterministic: no
//! timestamps, random ids, or host-specific paths are embedded. The output is
//! intentionally a **compiled launch plan**, not framework source code. This
//! gives Agenomic a concrete `genome -> runtime` step today while keeping the
//! format stable enough to feed richer launchers later.

use std::fs;
use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;

/// Runtime adapter targets supported by the compiler MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAdapter {
    Plain,
    Langgraph,
    Crewai,
}

impl RuntimeAdapter {
    pub fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Langgraph => "langgraph",
            Self::Crewai => "crewai",
        }
    }

    pub fn file_name(self) -> String {
        format!("{}.compiled", self.label())
    }
}

/// Inputs for [`compile_runtime_artifacts`].
#[derive(Debug, Clone)]
pub struct CompileRuntimeOptions {
    pub input_dir: PathBuf,
    /// Defaults to `<input_dir>/runtime`.
    pub output_dir: Option<PathBuf>,
    /// Empty = compiler default (`plain` + the framework-specific adapter when
    /// the genome declares one).
    pub adapters: Vec<RuntimeAdapter>,
}

/// One generated runtime artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRuntimeArtifactSummary {
    pub adapter: RuntimeAdapter,
    pub path: PathBuf,
    pub ready: bool,
    pub warnings: Vec<String>,
}

/// Result of [`compile_runtime_artifacts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileRuntimeResult {
    pub output_dir: PathBuf,
    pub artifacts: Vec<CompiledRuntimeArtifactSummary>,
}

#[derive(Debug, Clone)]
enum GenomeShape {
    CliV01,
    V1Alpha1,
    Legacy,
}

impl GenomeShape {
    fn label(&self) -> &'static str {
        match self {
            Self::CliV01 => "cli_v0.1",
            Self::V1Alpha1 => "agenomic_v1alpha1",
            Self::Legacy => "legacy",
        }
    }
}

#[derive(Debug, Clone)]
struct NormalizedBundle {
    shape: GenomeShape,
    agent_id: Option<String>,
    agent_name: String,
    framework_hint: Option<String>,
    runtime_kind_hint: Option<String>,
    model_provider: Option<String>,
    model_id: Option<String>,
    execution: Option<CompiledExecution>,
    prompts: CompiledPrompts,
    bindings: CompiledBindings,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledRuntimeArtifact {
    schema_version: String,
    adapter: RuntimeAdapter,
    ready: bool,
    source: CompiledSource,
    agent: CompiledAgent,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<CompiledModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<CompiledExecution>,
    prompts: CompiledPrompts,
    bindings: CompiledBindings,
    adapter_config: JsonValue,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledSource {
    bundle_root: String,
    genome_shape: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    framework_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_kind_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledAgent {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledModel {
    provider: String,
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledPrompts {
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skills: Vec<CompiledPromptRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledPromptRef {
    id: String,
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledBindings {
    #[serde(skip_serializing_if = "Option::is_none")]
    lockfile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    behavior_contract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_lock: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    knowledge_lock: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policy_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attestation_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledExecution {
    source: String,
    entrypoint: CompiledEntrypoint,
    runtime: CompiledRuntimeSpec,
    working_directory: String,
    env: CompiledEnv,
    permissions: CompiledPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledEntrypoint {
    kind: String,
    command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledRuntimeSpec {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CompiledEnv {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    optional: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CompiledPermissions {
    #[serde(default)]
    filesystem: CompiledFilesystemPermissions,
    #[serde(default)]
    network: CompiledNetworkPermissions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CompiledFilesystemPermissions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CompiledNetworkPermissions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow: Vec<String>,
}

/// Compile deterministic adapter artifacts into `runtime/`.
pub fn compile_runtime_artifacts(
    options: CompileRuntimeOptions,
) -> CliResult<CompileRuntimeResult> {
    if !options.input_dir.is_dir() {
        return Err(CliError::Schema(format!(
            "runtime compilation requires a bundle directory, got {}",
            options.input_dir.display()
        )));
    }
    let genome_path = options.input_dir.join("genome.yaml");
    if !genome_path.is_file() {
        return Err(CliError::MissingRequiredFile {
            path: genome_path.display().to_string(),
        });
    }

    let genome_text = fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let yaml: YamlValue = serde_yaml::from_str(&genome_text)
        .map_err(|e| CliError::Schema(format!("genome.yaml: {e}")))?;

    let normalized = normalize_bundle(&options.input_dir, &yaml)?;
    let adapters = choose_adapters(&normalized, &options.adapters);
    let output_dir = options
        .output_dir
        .unwrap_or_else(|| options.input_dir.join("runtime"));

    fs::create_dir_all(&output_dir).map_err(|e| io_at(&output_dir, e))?;

    let mut artifacts = Vec::with_capacity(adapters.len());
    for adapter in adapters {
        let compiled = compile_for_adapter(&normalized, adapter);
        let path = output_dir.join(adapter.file_name());
        let bytes = serde_json::to_vec_pretty(&compiled)
            .map_err(|e| CliError::Internal(format!("runtime compile json: {e}")))?;
        agenomic_fs::write_atomic(&path, &bytes)?;
        artifacts.push(CompiledRuntimeArtifactSummary {
            adapter,
            path,
            ready: compiled.ready,
            warnings: compiled.warnings,
        });
    }

    Ok(CompileRuntimeResult {
        output_dir,
        artifacts,
    })
}

fn choose_adapters(
    normalized: &NormalizedBundle,
    requested: &[RuntimeAdapter],
) -> Vec<RuntimeAdapter> {
    let mut adapters = if requested.is_empty() {
        let mut out = vec![RuntimeAdapter::Plain];
        match normalized.framework_hint.as_deref() {
            Some("langgraph") => out.push(RuntimeAdapter::Langgraph),
            Some("crewai") => out.push(RuntimeAdapter::Crewai),
            _ => {}
        }
        out
    } else {
        requested.to_vec()
    };
    adapters.sort();
    adapters.dedup();
    adapters
}

fn compile_for_adapter(
    normalized: &NormalizedBundle,
    adapter: RuntimeAdapter,
) -> CompiledRuntimeArtifact {
    let mut warnings = normalized.warnings.clone();
    let mut ready = normalized.execution.is_some();

    match adapter {
        RuntimeAdapter::Plain => {}
        RuntimeAdapter::Langgraph => {
            if normalized.framework_hint.as_deref() != Some("langgraph") {
                warnings.push(adapter_framework_warning(
                    adapter,
                    normalized.framework_hint.as_deref(),
                ));
                ready = false;
            }
        }
        RuntimeAdapter::Crewai => {
            if normalized.framework_hint.as_deref() != Some("crewai") {
                warnings.push(adapter_framework_warning(
                    adapter,
                    normalized.framework_hint.as_deref(),
                ));
                ready = false;
            }
        }
    }

    if normalized.execution.is_none() {
        warnings.push(
            "no execution contract could be declared or derived; adapter is metadata-only until an entrypoint is supplied"
                .to_string(),
        );
    }

    if normalized.model_provider.is_none() || normalized.model_id.is_none() {
        warnings.push(
            "model provider/id not fully declared in genome; downstream runtime wiring may need manual completion"
                .to_string(),
        );
    }

    warnings.sort();
    warnings.dedup();

    CompiledRuntimeArtifact {
        schema_version: "agenomic.runtime/v1".to_string(),
        adapter,
        ready,
        source: CompiledSource {
            bundle_root: ".".to_string(),
            genome_shape: normalized.shape.label().to_string(),
            framework_hint: normalized.framework_hint.clone(),
            runtime_kind_hint: normalized.runtime_kind_hint.clone(),
        },
        agent: CompiledAgent {
            id: normalized.agent_id.clone(),
            name: normalized.agent_name.clone(),
        },
        model: match (&normalized.model_provider, &normalized.model_id) {
            (Some(provider), Some(id)) => Some(CompiledModel {
                provider: provider.clone(),
                id: id.clone(),
            }),
            _ => None,
        },
        execution: normalized.execution.clone(),
        prompts: normalized.prompts.clone(),
        bindings: normalized.bindings.clone(),
        adapter_config: adapter_config(adapter, normalized),
        warnings,
    }
}

fn adapter_framework_warning(adapter: RuntimeAdapter, declared: Option<&str>) -> String {
    match declared {
        Some(current) => format!(
            "adapter `{}` was requested, but genome declares runtime.framework `{current}`",
            adapter.label()
        ),
        None => format!(
            "adapter `{}` was requested, but genome does not declare a runtime.framework hint",
            adapter.label()
        ),
    }
}

fn adapter_config(adapter: RuntimeAdapter, normalized: &NormalizedBundle) -> JsonValue {
    match adapter {
        RuntimeAdapter::Plain => json!({
            "launcher": "command",
            "transport": "subprocess",
            "entrypoint_source": normalized.execution.as_ref().map(|e| e.source.as_str()).unwrap_or("missing"),
        }),
        RuntimeAdapter::Langgraph => json!({
            "framework": "langgraph",
            "binding_mode": "bundle-prompts-and-tools",
            "entrypoint_source": normalized.execution.as_ref().map(|e| e.source.as_str()).unwrap_or("missing"),
        }),
        RuntimeAdapter::Crewai => json!({
            "framework": "crewai",
            "binding_mode": "bundle-prompts-and-tools",
            "entrypoint_source": normalized.execution.as_ref().map(|e| e.source.as_str()).unwrap_or("missing"),
        }),
    }
}

fn normalize_bundle(root: &Path, yaml: &YamlValue) -> CliResult<NormalizedBundle> {
    match detect_shape(yaml) {
        GenomeShape::CliV01 => normalize_cli_v01(root, yaml),
        GenomeShape::V1Alpha1 => normalize_v1alpha1(root, yaml),
        GenomeShape::Legacy => normalize_legacy(root, yaml),
    }
}

fn detect_shape(yaml: &YamlValue) -> GenomeShape {
    if yaml.get("spec_version").is_some() && yaml.get("agent").and_then(|a| a.get("id")).is_some() {
        return GenomeShape::CliV01;
    }
    match yaml.get("apiVersion").and_then(YamlValue::as_str) {
        Some(v) if v.starts_with("agenomic/") => GenomeShape::V1Alpha1,
        _ => GenomeShape::Legacy,
    }
}

fn normalize_cli_v01(root: &Path, yaml: &YamlValue) -> CliResult<NormalizedBundle> {
    let runtime = yaml.get("runtime");
    let framework_hint = string_field(runtime, "framework");
    let entrypoint = string_field(runtime, "entrypoint");
    let runtime_kind_hint =
        string_field(runtime, "runtime_kind").or_else(|| infer_runtime_kind(entrypoint.as_deref()));

    let execution = if let Some(node) = yaml.get("execution") {
        Some(parse_declared_execution(node)?)
    } else {
        derive_execution(runtime_kind_hint.as_deref(), entrypoint.as_deref())
    };

    let mut warnings = Vec::new();
    if yaml.get("execution").is_none() && execution.is_some() {
        warnings.push(
            "execution block absent; compiled runtime plan was derived from runtime.entrypoint/runtime_kind"
                .to_string(),
        );
    }

    Ok(NormalizedBundle {
        shape: GenomeShape::CliV01,
        agent_id: yaml
            .get("agent")
            .and_then(|a| a.get("id"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        agent_name: yaml
            .get("agent")
            .and_then(|a| a.get("name"))
            .and_then(YamlValue::as_str)
            .unwrap_or("unknown-agent")
            .to_string(),
        framework_hint,
        runtime_kind_hint,
        model_provider: string_field(runtime, "model_provider"),
        model_id: string_field(runtime, "model_id"),
        execution,
        prompts: CompiledPrompts {
            system: relative_if_exists(root, "prompts/system.md"),
            skills: cli_skill_prompts(yaml.get("skills")),
        },
        bindings: CompiledBindings {
            lockfile: first_existing(root, &["agent.lock.yaml", "agent.lock"]),
            behavior_contract: relative_if_exists(root, "behavior.contract.yaml"),
            tool_lock: relative_if_exists(root, "tools/mcp.lock.yaml"),
            knowledge_lock: relative_if_exists(root, "knowledge/snapshots.yaml"),
            memory_schema: relative_if_exists(root, "memory/memory.schema.yaml"),
            replay_manifest: relative_if_exists(root, "evals/replay_manifest.yaml"),
            policy_sources: cli_policy_sources(yaml.get("policies")),
            attestation_files: attestation_files(root)?,
        },
        warnings,
    })
}

fn normalize_v1alpha1(root: &Path, yaml: &YamlValue) -> CliResult<NormalizedBundle> {
    let artifacts = yaml.get("artifacts");
    let execution = if let Some(node) = yaml.get("execution") {
        Some(parse_declared_execution(node)?)
    } else {
        None
    };

    let mut warnings = vec![
        "v1alpha1 genomes do not declare a stable agent id in-bundle; compiled artifact omits `agent.id`"
            .to_string(),
    ];
    if execution.is_none() {
        warnings.push(
            "v1alpha1 genome has no execution block; compiled runtime plan is metadata-only"
                .to_string(),
        );
    }

    Ok(NormalizedBundle {
        shape: GenomeShape::V1Alpha1,
        agent_id: None,
        agent_name: yaml
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(YamlValue::as_str)
            .unwrap_or("unknown-agent")
            .to_string(),
        framework_hint: None,
        runtime_kind_hint: None,
        model_provider: None,
        model_id: None,
        execution,
        prompts: CompiledPrompts {
            system: artifacts
                .and_then(|a| a.get("system_prompt"))
                .and_then(YamlValue::as_str)
                .map(str::to_string),
            skills: prompt_list(
                artifacts
                    .and_then(|a| a.get("skills"))
                    .and_then(YamlValue::as_sequence),
            ),
        },
        bindings: CompiledBindings {
            lockfile: first_existing(root, &["agent.lock.yaml", "agent.lock"]),
            behavior_contract: artifacts
                .and_then(|a| a.get("behavior_contract"))
                .and_then(YamlValue::as_str)
                .map(str::to_string)
                .or_else(|| relative_if_exists(root, "behavior.contract.yaml")),
            tool_lock: artifacts
                .and_then(|a| a.get("tool_lock"))
                .and_then(YamlValue::as_str)
                .map(str::to_string)
                .or_else(|| relative_if_exists(root, "tools/mcp.lock.yaml")),
            knowledge_lock: relative_if_exists(root, "knowledge/snapshots.yaml"),
            memory_schema: artifacts
                .and_then(|a| a.get("memory_schema"))
                .and_then(YamlValue::as_str)
                .map(str::to_string)
                .or_else(|| relative_if_exists(root, "memory/memory.schema.yaml")),
            replay_manifest: artifacts
                .and_then(|a| a.get("evals"))
                .and_then(YamlValue::as_sequence)
                .and_then(|seq| seq.first())
                .and_then(YamlValue::as_str)
                .map(str::to_string)
                .or_else(|| relative_if_exists(root, "evals/replay_manifest.yaml")),
            policy_sources: string_list(
                artifacts
                    .and_then(|a| a.get("policies"))
                    .and_then(YamlValue::as_sequence),
            ),
            attestation_files: attestation_files(root)?,
        },
        warnings,
    })
}

fn normalize_legacy(root: &Path, yaml: &YamlValue) -> CliResult<NormalizedBundle> {
    let execution = if let Some(node) = yaml.get("execution") {
        Some(parse_declared_execution(node)?)
    } else {
        None
    };
    let mut warnings = Vec::new();
    warnings.push(
        "legacy genome shape detected; compiler extracted only common runtime metadata".to_string(),
    );
    if execution.is_none() {
        warnings.push(
            "legacy genome has no execution block; compiled runtime plan is metadata-only"
                .to_string(),
        );
    }

    Ok(NormalizedBundle {
        shape: GenomeShape::Legacy,
        agent_id: yaml
            .get("agent")
            .and_then(|a| a.get("id"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        agent_name: yaml
            .get("agent")
            .and_then(|a| a.get("name"))
            .and_then(YamlValue::as_str)
            .or_else(|| {
                yaml.get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(YamlValue::as_str)
            })
            .unwrap_or("unknown-agent")
            .to_string(),
        framework_hint: yaml
            .get("runtime")
            .and_then(|r| r.get("framework"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        runtime_kind_hint: yaml
            .get("runtime")
            .and_then(|r| r.get("runtime_kind"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        model_provider: yaml
            .get("runtime")
            .and_then(|r| r.get("model_provider"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        model_id: yaml
            .get("runtime")
            .and_then(|r| r.get("model_id"))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        execution,
        prompts: CompiledPrompts {
            system: relative_if_exists(root, "prompts/system.md"),
            skills: prompt_list(None),
        },
        bindings: CompiledBindings {
            lockfile: first_existing(root, &["agent.lock.yaml", "agent.lock"]),
            behavior_contract: relative_if_exists(root, "behavior.contract.yaml"),
            tool_lock: relative_if_exists(root, "tools/mcp.lock.yaml"),
            knowledge_lock: relative_if_exists(root, "knowledge/snapshots.yaml"),
            memory_schema: relative_if_exists(root, "memory/memory.schema.yaml"),
            replay_manifest: relative_if_exists(root, "evals/replay_manifest.yaml"),
            policy_sources: Vec::new(),
            attestation_files: attestation_files(root)?,
        },
        warnings,
    })
}

fn parse_declared_execution(node: &YamlValue) -> CliResult<CompiledExecution> {
    let entrypoint = node
        .get("entrypoint")
        .ok_or_else(|| CliError::Schema("execution.entrypoint is required".to_string()))?;
    let runtime = node
        .get("runtime")
        .ok_or_else(|| CliError::Schema("execution.runtime is required".to_string()))?;

    let kind = entrypoint
        .get("kind")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| {
            CliError::Schema("execution.entrypoint.kind must be a string".to_string())
        })?;
    if kind != "command" {
        return Err(CliError::Schema(format!(
            "execution.entrypoint.kind `{kind}` is unsupported; MVP supports `command` only"
        )));
    }
    let command = entrypoint
        .get("command")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| {
            CliError::Schema("execution.entrypoint.command must be a string".to_string())
        })?;

    Ok(CompiledExecution {
        source: "declared".to_string(),
        entrypoint: CompiledEntrypoint {
            kind: kind.to_string(),
            command: command.to_string(),
            args: string_list(entrypoint.get("args").and_then(YamlValue::as_sequence)),
        },
        runtime: CompiledRuntimeSpec {
            kind: runtime
                .get("kind")
                .and_then(YamlValue::as_str)
                .ok_or_else(|| {
                    CliError::Schema("execution.runtime.kind must be a string".to_string())
                })?
                .to_string(),
            version: runtime
                .get("version")
                .and_then(YamlValue::as_str)
                .map(str::to_string),
        },
        working_directory: node
            .get("working_directory")
            .and_then(YamlValue::as_str)
            .unwrap_or(".")
            .to_string(),
        env: CompiledEnv {
            required: string_list(
                node.get("env")
                    .and_then(|e| e.get("required"))
                    .and_then(YamlValue::as_sequence),
            ),
            optional: string_list(
                node.get("env")
                    .and_then(|e| e.get("optional"))
                    .and_then(YamlValue::as_sequence),
            ),
        },
        permissions: CompiledPermissions {
            filesystem: CompiledFilesystemPermissions {
                read: string_list(
                    node.get("permissions")
                        .and_then(|p| p.get("filesystem"))
                        .and_then(|f| f.get("read"))
                        .and_then(YamlValue::as_sequence),
                ),
                write: string_list(
                    node.get("permissions")
                        .and_then(|p| p.get("filesystem"))
                        .and_then(|f| f.get("write"))
                        .and_then(YamlValue::as_sequence),
                ),
            },
            network: CompiledNetworkPermissions {
                allow: string_list(
                    node.get("permissions")
                        .and_then(|p| p.get("network"))
                        .and_then(|n| n.get("allow"))
                        .and_then(YamlValue::as_sequence),
                ),
            },
        },
    })
}

fn derive_execution(
    runtime_kind: Option<&str>,
    entrypoint: Option<&str>,
) -> Option<CompiledExecution> {
    let entrypoint = entrypoint?;
    let runtime_kind = runtime_kind?;
    let runtime_kind = runtime_kind.to_ascii_lowercase();

    let (command, args) = match runtime_kind.as_str() {
        "python" => derive_python_command(entrypoint)?,
        "node" => ("node".to_string(), vec![entrypoint.to_string()]),
        "rust" => (
            "cargo".to_string(),
            vec!["run".to_string(), "--release".to_string()],
        ),
        "binary" => (entrypoint.to_string(), Vec::new()),
        _ => return None,
    };

    Some(CompiledExecution {
        source: "derived".to_string(),
        entrypoint: CompiledEntrypoint {
            kind: "command".to_string(),
            command,
            args,
        },
        runtime: CompiledRuntimeSpec {
            kind: runtime_kind,
            version: None,
        },
        working_directory: ".".to_string(),
        env: CompiledEnv::default(),
        permissions: CompiledPermissions::default(),
    })
}

fn derive_python_command(entrypoint: &str) -> Option<(String, Vec<String>)> {
    if entrypoint.trim().is_empty() {
        return None;
    }
    if entrypoint.ends_with(".py") {
        return Some(("python".to_string(), vec![entrypoint.to_string()]));
    }
    let module = match entrypoint.split_once(':') {
        Some((module, _)) => module,
        None => entrypoint,
    };
    let module = module.trim_end_matches(".__main__");
    Some((
        "python".to_string(),
        vec!["-m".to_string(), module.to_string()],
    ))
}

fn infer_runtime_kind(entrypoint: Option<&str>) -> Option<String> {
    let entrypoint = entrypoint?;
    if entrypoint.ends_with(".py") || entrypoint.contains(':') {
        return Some("python".to_string());
    }
    if entrypoint.ends_with(".js") || entrypoint.ends_with(".mjs") || entrypoint.ends_with(".cjs") {
        return Some("node".to_string());
    }
    None
}

fn string_field(parent: Option<&YamlValue>, key: &str) -> Option<String> {
    parent
        .and_then(|node| node.get(key))
        .and_then(YamlValue::as_str)
        .map(str::to_string)
}

fn cli_skill_prompts(node: Option<&YamlValue>) -> Vec<CompiledPromptRef> {
    let mut out = Vec::new();
    let Some(seq) = node.and_then(YamlValue::as_sequence) else {
        return out;
    };
    for item in seq {
        match item {
            YamlValue::String(path) => out.push(CompiledPromptRef {
                id: prompt_id_from_path(path),
                path: path.clone(),
            }),
            YamlValue::Mapping(_) => {
                let path = item
                    .get("prompt")
                    .or_else(|| item.get("prompt_path"))
                    .and_then(YamlValue::as_str);
                if let Some(path) = path {
                    let id = item
                        .get("name")
                        .or_else(|| item.get("id"))
                        .and_then(YamlValue::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| prompt_id_from_path(path));
                    out.push(CompiledPromptRef {
                        id,
                        path: path.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.id.cmp(&b.id)));
    out
}

fn cli_policy_sources(node: Option<&YamlValue>) -> Vec<String> {
    let Some(seq) = node.and_then(YamlValue::as_sequence) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in seq {
        match item {
            YamlValue::String(path) => out.push(path.clone()),
            YamlValue::Mapping(_) => {
                if let Some(path) = item.get("source").and_then(YamlValue::as_str) {
                    out.push(path.to_string());
                }
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

fn prompt_list(node: Option<&Vec<YamlValue>>) -> Vec<CompiledPromptRef> {
    let mut out = Vec::new();
    let Some(seq) = node else {
        return out;
    };
    for value in seq {
        if let Some(path) = value.as_str() {
            out.push(CompiledPromptRef {
                id: prompt_id_from_path(path),
                path: path.to_string(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.id.cmp(&b.id)));
    out
}

fn prompt_id_from_path(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.strip_suffix(".md").unwrap_or(file).to_string()
}

fn string_list(node: Option<&Vec<YamlValue>>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(seq) = node else {
        return out;
    };
    for value in seq {
        if let Some(s) = value.as_str() {
            out.push(s.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn relative_if_exists(root: &Path, relative: &str) -> Option<String> {
    root.join(relative).exists().then(|| relative.to_string())
}

fn first_existing(root: &Path, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| relative_if_exists(root, candidate))
}

fn attestation_files(root: &Path) -> CliResult<Vec<String>> {
    let dir = root.join("attestations");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| io_at(&dir, e))? {
        let entry = entry.map_err(|e| io_at(&dir, e))?;
        let path = entry.path();
        if path.is_file() {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            out.push(format!("attestations/{name}"));
        }
    }
    out.sort();
    Ok(out)
}
