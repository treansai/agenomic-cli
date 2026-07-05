//! Runtime / framework / tool inference from declared dependencies (§2.4).
//!
//! Runs after the §2.3 source chain. Inference only fills fields that detection
//! left at their built-in default — an explicit value from `agenomic.yaml`
//! (highest-precedence source) is never overwritten (so a pinned `model_id`
//! wins). All scans iterate dependencies in alphabetical order for determinism
//! (§2.7).

use crate::model::{Dependency, DetectedGenome, MemoryInfo, Source, ToolEntry, ToolKind};

/// Apply the §2.4 inference tables: framework, model provider, default
/// `model_id`, the tool allow-list, and the memory backend.
pub(crate) fn apply(deps: &[Dependency], genome: &mut DetectedGenome) {
    let mut sorted: Vec<&Dependency> = deps.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    infer_framework(&sorted, genome);
    infer_provider(&sorted, genome);
    infer_model_id(genome);
    infer_tools(&sorted, genome);
    infer_memory(&sorted, genome);
}

/// The evidence source currently backing `field`, if any.
fn source_of(genome: &DetectedGenome, field: &str) -> Option<Source> {
    genome
        .evidence
        .iter()
        .find(|e| e.field == field)
        .map(|e| e.source)
}

/// True if `field` was set by something other than the built-in defaults
/// (i.e. an explicit source like `agenomic.yaml`) — inference must not clobber it.
fn explicitly_set(genome: &DetectedGenome, field: &str) -> bool {
    matches!(source_of(genome, field), Some(s) if s != Source::Defaults)
}

fn dep_evidence(dep: &Dependency) -> String {
    format!(
        "dependency {}{}",
        dep.name,
        dep.version.as_deref().unwrap_or("")
    )
}

type NamePred = fn(&str) -> bool;

fn infer_framework(deps: &[&Dependency], genome: &mut DetectedGenome) {
    if explicitly_set(genome, "runtime.framework") {
        return;
    }
    // Priority order; within a rule the alphabetically-first matching dep wins.
    let rules: &[(&str, NamePred, bool)] = &[
        (
            "google-adk",
            |n| n == "google-adk" || n == "google-agents-cli" || n == "agents-cli",
            false,
        ),
        ("langgraph", |n| n == "langgraph", false),
        (
            "langchain",
            |n| n == "langchain" || n.starts_with("langchain-"),
            false,
        ),
        (
            "openai-agents",
            |n| n == "openai-agents" || n == "openai-swarm",
            true,
        ),
        ("crewai", |n| n == "crewai", false),
        ("llama-index", |n| n == "llama-index", false),
    ];
    for (framework, pred, sets_openai) in rules {
        if let Some(dep) = deps.iter().find(|d| pred(&d.name)) {
            genome.framework = Some((*framework).to_string());
            genome.record(
                dep.source,
                "runtime.framework",
                framework,
                &dep_evidence(dep),
            );
            if *sets_openai {
                set_provider(genome, "openai", dep);
            }
            return;
        }
    }
    genome.framework = Some("custom".to_string());
    genome.record(
        Source::Defaults,
        "runtime.framework",
        "custom",
        "no known framework dependency",
    );
}

fn infer_provider(deps: &[&Dependency], genome: &mut DetectedGenome) {
    if explicitly_set(genome, "runtime.model_provider") {
        return;
    }
    let rules: &[(&str, NamePred)] = &[
        ("anthropic", |n| n == "anthropic"),
        ("openai", |n| n == "openai"),
        ("google", |n| {
            n == "google-generativeai"
                || n == "google-genai"
                || n == "vertexai"
                || n == "google-adk"
                || n == "google-agents-cli"
        }),
        ("cohere", |n| n == "cohere"),
        ("huggingface", |n| {
            n == "huggingface-hub" || n == "huggingface_hub" || n == "transformers"
        }),
    ];
    for (provider, pred) in rules {
        if let Some(dep) = deps.iter().find(|d| pred(&d.name)) {
            set_provider(genome, provider, dep);
            return;
        }
    }
    // Nothing matched → keep the legacy default provider.
}

fn set_provider(genome: &mut DetectedGenome, provider: &str, dep: &Dependency) {
    genome.model_provider = provider.to_string();
    genome.record(
        dep.source,
        "runtime.model_provider",
        provider,
        &dep_evidence(dep),
    );
}

fn infer_model_id(genome: &mut DetectedGenome) {
    // A pinned model_id (e.g. from agenomic.yaml) wins; only replace a default.
    if explicitly_set(genome, "runtime.model_id") {
        return;
    }
    let default = match genome.model_provider.as_str() {
        "anthropic" => Some("claude-sonnet-4-6"),
        "openai" => Some("gpt-4o"),
        "google" => Some("gemini-1.5-pro"),
        "cohere" => Some("command-r-plus"),
        _ => None,
    };
    if let Some(model_id) = default {
        genome.model_id = model_id.to_string();
        genome.record(
            Source::Defaults,
            "runtime.model_id",
            model_id,
            &format!("default for provider {}", genome.model_provider),
        );
    }
}

fn tool_kind(name: &str) -> Option<ToolKind> {
    Some(match name {
        "ruff" | "mypy" | "pylint" | "black" => ToolKind::Linter,
        "radon" | "lizard" => ToolKind::Complexity,
        "bandit" | "semgrep" => ToolKind::Security,
        "pytest" | "unittest2" => ToolKind::Test,
        "requests" | "httpx" | "aiohttp" => ToolKind::Http,
        "pydantic" => ToolKind::Schema,
        "redis" | "chromadb" | "weaviate-client" | "pinecone-client" => ToolKind::Memory,
        "sqlalchemy" | "psycopg" | "asyncpg" => ToolKind::Sql,
        _ => return None,
    })
}

fn infer_tools(deps: &[&Dependency], genome: &mut DetectedGenome) {
    let mut tools: Vec<(ToolEntry, Source, String)> = Vec::new();
    for dep in deps {
        if let Some(kind) = tool_kind(&dep.name) {
            let entry = ToolEntry {
                name: dep.name.clone(),
                kind,
                version: dep.version.clone(),
            };
            tools.push((entry, dep.source, dep_evidence(dep)));
        }
    }
    // Deduplicate (a dep can be declared twice across manifests), then sort by
    // (kind, name) per §2.7.
    tools.sort_by(|a, b| (a.0.kind, &a.0.name).cmp(&(b.0.kind, &b.0.name)));
    tools.dedup_by(|a, b| a.0.name == b.0.name && a.0.kind == b.0.kind);

    for (i, (entry, source, evidence)) in tools.iter().enumerate() {
        genome.record(*source, &format!("tools[{i}]"), &entry.name, evidence);
    }
    genome.tools = tools.into_iter().map(|(entry, _, _)| entry).collect();
}

fn infer_memory(deps: &[&Dependency], genome: &mut DetectedGenome) {
    // Dep-name backends only; import-path heuristics (langchain vectorstores,
    // langgraph checkpoint) require source scanning, reserved for `--deep`.
    const BACKENDS: &[&str] = &["chromadb", "pinecone-client", "redis", "weaviate-client"];
    if let Some(dep) = deps.iter().find(|d| BACKENDS.contains(&d.name.as_str())) {
        genome.memory = Some(MemoryInfo {
            enabled: true,
            backend: dep.name.clone(),
        });
        genome.record(
            dep.source,
            "runtime.memory.backend",
            &dep.name,
            &dep_evidence(dep),
        );
    }
    // Otherwise omit the memory block entirely (do not write enabled: false).
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            source: Source::Pyproject,
        }
    }

    #[test]
    fn codedrift_shape_matches_spec() {
        let deps = vec![
            dep("anthropic", Some(">=0.45.0")),
            dep("langgraph", Some(">=0.2.0")),
            dep("ruff", Some(">=0.6.0")),
            dep("radon", Some(">=6.0.1")),
            dep("bandit", Some(">=1.7.9")),
        ];
        let mut g = DetectedGenome::defaults();
        apply(&deps, &mut g);

        assert_eq!(g.framework.as_deref(), Some("langgraph"));
        assert_eq!(g.model_provider, "anthropic");
        assert_eq!(g.model_id, "claude-sonnet-4-6");
        assert!(g.memory.is_none());
        // Sorted by (kind, name): linter, complexity, security → ruff, radon, bandit.
        let tools: Vec<(&str, ToolKind)> =
            g.tools.iter().map(|t| (t.name.as_str(), t.kind)).collect();
        assert_eq!(
            tools,
            vec![
                ("ruff", ToolKind::Linter),
                ("radon", ToolKind::Complexity),
                ("bandit", ToolKind::Security),
            ]
        );
    }

    #[test]
    fn no_ai_deps_yields_custom_openai_default() {
        let deps = vec![dep("requests", Some(">=2"))];
        let mut g = DetectedGenome::defaults();
        apply(&deps, &mut g);
        assert_eq!(g.framework.as_deref(), Some("custom"));
        assert_eq!(g.model_provider, "openai");
        assert_eq!(g.model_id, "gpt-4o");
        assert_eq!(g.tools.len(), 1);
        assert_eq!(g.tools[0].kind, ToolKind::Http);
    }

    #[test]
    fn pinned_model_id_is_not_overwritten() {
        let mut g = DetectedGenome::defaults();
        // Simulate agenomic.yaml having pinned model_id.
        g.model_id = "claude-opus-4-7".to_string();
        g.record(
            Source::AgenomicYaml,
            "runtime.model_id",
            "claude-opus-4-7",
            "agenomic.yaml",
        );
        apply(&[dep("anthropic", Some(">=0.45.0"))], &mut g);
        assert_eq!(g.model_provider, "anthropic");
        assert_eq!(g.model_id, "claude-opus-4-7"); // pin wins over provider default
    }

    #[test]
    fn memory_backend_inferred() {
        let mut g = DetectedGenome::defaults();
        apply(&[dep("redis", Some(">=5"))], &mut g);
        let mem = g.memory.expect("memory block");
        assert!(mem.enabled);
        assert_eq!(mem.backend, "redis");
        // redis is also a memory-kind tool.
        assert_eq!(g.tools[0].kind, ToolKind::Memory);
    }

    #[test]
    fn openai_agents_sets_provider_openai() {
        let mut g = DetectedGenome::defaults();
        apply(&[dep("openai-agents", Some(">=0.1"))], &mut g);
        assert_eq!(g.framework.as_deref(), Some("openai-agents"));
        assert_eq!(g.model_provider, "openai");
    }

    #[test]
    fn google_adk_sets_framework_and_gemini_default() {
        let mut g = DetectedGenome::defaults();
        apply(&[dep("google-adk", Some(">=1.0"))], &mut g);
        assert_eq!(g.framework.as_deref(), Some("google-adk"));
        assert_eq!(g.model_provider, "google");
        assert_eq!(g.model_id, "gemini-1.5-pro");
    }

    #[test]
    fn agents_cli_package_detected_as_google_adk() {
        let mut g = DetectedGenome::defaults();
        apply(&[dep("google-agents-cli", Some(">=0.1"))], &mut g);
        assert_eq!(g.framework.as_deref(), Some("google-adk"));
        assert_eq!(g.model_provider, "google");
    }
}
