//! Parse an existing `genome.yaml` back into a [`DetectedGenome`] — the
//! `Current` side of an `agm update` merge (§3.4).

use agenomic_core::{CliError, CliResult};

use crate::model::{DetectedGenome, MemoryInfo, ToolEntry, ToolKind};

/// Parse a `genome.yaml` document. The returned genome carries no evidence
/// (that lives in the provenance sidecar); merge uses it only for field values.
///
/// ```
/// use agenomic_detect::parse_genome;
/// let g = parse_genome("spec_version: '0.1'\nagent:\n  id: 'agent://a/b'\n  name: 'n'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n").unwrap();
/// assert_eq!(g.agent_id, "agent://a/b");
/// ```
pub fn parse_genome(text: &str) -> CliResult<DetectedGenome> {
    let v: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| CliError::Schema(format!("genome.yaml: {e}")))?;

    let mut g = DetectedGenome::defaults();
    g.evidence.clear();

    if let Some(x) = nested_str(&v, &["spec_version"]) {
        g.spec_version = x.to_string();
    }
    if let Some(x) = nested_str(&v, &["agent", "id"]) {
        g.agent_id = x.to_string();
    }
    if let Some(x) = nested_str(&v, &["agent", "name"]) {
        g.agent_name = x.to_string();
    }
    if let Some(x) = nested_str(&v, &["agent", "domain"]) {
        g.domain = x.to_string();
    }
    if let Some(x) = nested_str(&v, &["agent", "criticality"]) {
        g.criticality = x.to_string();
    }
    g.authors = str_seq(&v, &["agent", "authors"]);
    // A `description: |` block scalar parses with a trailing newline; trim it so
    // it compares equal to the (trimmed) detected description.
    g.description = nested_str(&v, &["description"]).map(|d| d.trim_end().to_string());
    g.framework = nested_str(&v, &["runtime", "framework"]).map(str::to_string);
    g.runtime_kind = nested_str(&v, &["runtime", "runtime_kind"]).map(str::to_string);
    if let Some(x) = nested_str(&v, &["runtime", "model_provider"]) {
        g.model_provider = x.to_string();
    }
    if let Some(x) = nested_str(&v, &["runtime", "model_id"]) {
        g.model_id = x.to_string();
    }
    g.entrypoint = nested_str(&v, &["runtime", "entrypoint"]).map(str::to_string);
    g.memory = parse_memory(&v);
    g.tools = parse_tools(&v)?;
    g.skills = parse_skills(&v);
    g.knowledge = str_seq(&v, &["knowledge"]);
    g.policies = parse_policies(&v);
    Ok(g)
}

/// Skills are emitted as `{ name: … }` objects (schema requirement) but the
/// legacy form was a plain string list; accept both.
fn parse_skills(value: &serde_yaml::Value) -> Vec<String> {
    let Some(seq) = value.get("skills").and_then(|x| x.as_sequence()) else {
        return Vec::new();
    };
    seq.iter()
        .filter_map(|item| {
            item.as_str().map(str::to_string).or_else(|| {
                item.get("name")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
            })
        })
        .collect()
}

fn nested_str<'a>(value: &'a serde_yaml::Value, keys: &[&str]) -> Option<&'a str> {
    let mut node = value;
    for k in keys {
        node = node.get(k)?;
    }
    node.as_str().filter(|s| !s.is_empty())
}

fn str_seq(value: &serde_yaml::Value, keys: &[&str]) -> Vec<String> {
    let mut node = value;
    for k in keys {
        match node.get(k) {
            Some(n) => node = n,
            None => return Vec::new(),
        }
    }
    node.as_sequence()
        .map(|seq| {
            seq.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_memory(value: &serde_yaml::Value) -> Option<MemoryInfo> {
    let mem = value.get("runtime")?.get("memory")?;
    let backend = mem.get("backend")?.as_str()?.to_string();
    let enabled = mem
        .get("enabled")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(true);
    Some(MemoryInfo { enabled, backend })
}

fn parse_policies(value: &serde_yaml::Value) -> Vec<String> {
    let Some(seq) = value.get("policies").and_then(|p| p.as_sequence()) else {
        return Vec::new();
    };
    // Policies may be bare strings or mappings with an `id`.
    seq.iter()
        .filter_map(|p| {
            p.as_str()
                .map(str::to_string)
                .or_else(|| p.get("id").and_then(|i| i.as_str()).map(str::to_string))
        })
        .collect()
}

fn parse_tools(value: &serde_yaml::Value) -> CliResult<Vec<ToolEntry>> {
    let Some(seq) = value.get("tools").and_then(|t| t.as_sequence()) else {
        return Ok(Vec::new());
    };
    let mut tools = Vec::with_capacity(seq.len());
    for item in seq {
        let name = item
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| CliError::Schema("genome.yaml: tool entry missing `name`".into()))?
            .to_string();
        let kind_label = item
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("linter");
        let kind = kind_from_label(kind_label).ok_or_else(|| {
            CliError::Schema(format!("genome.yaml: unknown tool kind '{kind_label}'"))
        })?;
        let version = item
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        tools.push(ToolEntry {
            name,
            kind,
            version,
        });
    }
    Ok(tools)
}

fn kind_from_label(label: &str) -> Option<ToolKind> {
    Some(match label {
        "linter" => ToolKind::Linter,
        "complexity" => ToolKind::Complexity,
        "security" => ToolKind::Security,
        "test" => ToolKind::Test,
        "http" => ToolKind::Http,
        "schema" => ToolKind::Schema,
        "memory" => ToolKind::Memory,
        "sql" => ToolKind::Sql,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::emit;

    #[test]
    fn roundtrips_codedrift_genome() {
        // emit a detected genome, parse it back, re-emit → identical bytes.
        let mut g = DetectedGenome::defaults();
        g.agent_id = "agent://traidano/agenomic-codedrift".into();
        g.agent_name = "codedrift-agent".into();
        g.authors = vec!["Traidano <dev@traidano.com>".into()];
        g.description = Some("A drift agent".into());
        g.framework = Some("langgraph".into());
        g.runtime_kind = Some("python".into());
        g.model_provider = "anthropic".into();
        g.model_id = "claude-sonnet-4-6".into();
        g.entrypoint = Some("pkg.__main__:main".into());
        g.tools = vec![
            ToolEntry {
                name: "ruff".into(),
                kind: ToolKind::Linter,
                version: Some(">=0.6.0".into()),
            },
            ToolEntry {
                name: "bandit".into(),
                kind: ToolKind::Security,
                version: Some(">=1.7.9".into()),
            },
        ];
        let yaml = emit(&g).genome;
        let parsed = parse_genome(&yaml).unwrap();
        assert_eq!(emit(&parsed).genome, yaml);
    }
}
