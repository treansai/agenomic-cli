//! Source: `pyproject.toml` (PEP 621 `[project]`) (§2.3 tier 5).

use std::collections::BTreeMap;
use std::path::Path;

use agenomic_core::{CliError, CliResult};
use serde::Deserialize;

use crate::model::{Dependency, DetectedGenome, Source};
use crate::sources::read_file_opt;

#[derive(Deserialize)]
struct PyProject {
    project: Option<Project>,
}

#[derive(Deserialize)]
struct Project {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    authors: Vec<Author>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Author {
    name: Option<String>,
    email: Option<String>,
}

/// Map `[project]` onto name/description/authors/entrypoint, set
/// `runtime_kind = "python"`, and collect dependencies for §2.4 inference.
pub(crate) fn apply(
    path: &Path,
    genome: &mut DetectedGenome,
    deps: &mut Vec<Dependency>,
) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("pyproject.toml"))? else {
        return Ok(());
    };
    let parsed: PyProject =
        toml::from_str(&text).map_err(|e| CliError::Schema(format!("pyproject.toml: {e}")))?;
    let Some(project) = parsed.project else {
        return Ok(());
    };

    genome.runtime_kind = Some("python".to_string());
    genome.record(
        Source::Pyproject,
        "runtime.runtime_kind",
        "python",
        "pyproject.toml present",
    );

    if let Some(name) = project.name.filter(|s| !s.is_empty()) {
        genome.agent_name = name.clone();
        genome.record(Source::Pyproject, "agent.name", &name, "project.name");
    }
    if let Some(desc) = project.description.filter(|s| !s.trim().is_empty()) {
        let desc = desc.trim().to_string();
        genome.description = Some(desc.clone());
        genome.record(
            Source::Pyproject,
            "description",
            &desc,
            "project.description",
        );
    }

    let authors: Vec<String> = project.authors.iter().filter_map(format_author).collect();
    if !authors.is_empty() {
        genome.record(
            Source::Pyproject,
            "agent.authors",
            &authors.join(", "),
            "project.authors",
        );
        genome.authors = authors;
    }

    // Deterministic: BTreeMap iterates keys alphabetically; the first script's
    // *target* (module:func) is the entrypoint, keyed evidence references it.
    if let Some((key, target)) = project.scripts.iter().next() {
        if !target.is_empty() {
            genome.entrypoint = Some(target.clone());
            genome.record(
                Source::Pyproject,
                "runtime.entrypoint",
                target,
                &format!("project.scripts.{key}"),
            );
        }
    }

    for req in &project.dependencies {
        if let Some((name, version)) = parse_requirement(req) {
            deps.push(Dependency {
                name,
                version,
                source: Source::Pyproject,
            });
        }
    }
    Ok(())
}

fn format_author(a: &Author) -> Option<String> {
    match (a.name.as_deref(), a.email.as_deref()) {
        (Some(n), Some(e)) if !n.is_empty() && !e.is_empty() => Some(format!("{n} <{e}>")),
        (Some(n), _) if !n.is_empty() => Some(n.to_string()),
        (_, Some(e)) if !e.is_empty() => Some(e.to_string()),
        _ => None,
    }
}

/// Parse a PEP 508 requirement string into `(name, version_spec)`.
/// e.g. `anthropic>=0.45.0` → `("anthropic", Some(">=0.45.0"))`.
fn parse_requirement(req: &str) -> Option<(String, Option<String>)> {
    let req = req.trim();
    let name_end = req
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(req.len());
    let name = req[..name_end].to_lowercase();
    if name.is_empty() {
        return None;
    }
    let mut rest = req[name_end..].trim();
    // Drop an extras group like `[standard]` before the version specifier.
    if let Some(after_bracket) = rest.strip_prefix('[') {
        rest = after_bracket.split(']').nth(1).unwrap_or("").trim();
    }
    let version = (!rest.is_empty()).then(|| rest.to_string());
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requirements() {
        assert_eq!(
            parse_requirement("anthropic>=0.45.0"),
            Some(("anthropic".to_string(), Some(">=0.45.0".to_string())))
        );
        assert_eq!(
            parse_requirement("requests"),
            Some(("requests".to_string(), None))
        );
        assert_eq!(
            parse_requirement("uvicorn[standard]>=0.30"),
            Some(("uvicorn".to_string(), Some(">=0.30".to_string())))
        );
        assert_eq!(
            parse_requirement("LangGraph >= 0.2.0"),
            Some(("langgraph".to_string(), Some(">= 0.2.0".to_string())))
        );
    }

    #[test]
    fn formats_authors() {
        let a = Author {
            name: Some("Traidano".into()),
            email: Some("dev@traidano.com".into()),
        };
        assert_eq!(
            format_author(&a).as_deref(),
            Some("Traidano <dev@traidano.com>")
        );
    }
}
