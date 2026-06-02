//! Sources: `go.mod`, `Cargo.toml`, `package.json` (§2.3 tier 4).
//!
//! Each sets `runtime.runtime_kind` and, where available, `agent.name` /
//! `description`, and collects dependencies for the §2.4 inference pass.

use std::collections::BTreeMap;
use std::path::Path;

use agenomic_core::{CliError, CliResult};
use serde::Deserialize;

use crate::model::{Dependency, DetectedGenome, Source};
use crate::sources::read_file_opt;

/// `go.mod` → `runtime_kind = "go"`, last module path segment → name.
pub(crate) fn apply_go_mod(path: &Path, genome: &mut DetectedGenome) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("go.mod"))? else {
        return Ok(());
    };
    genome.runtime_kind = Some("go".to_string());
    genome.record(
        Source::GoMod,
        "runtime.runtime_kind",
        "go",
        "go.mod present",
    );
    if let Some(module) = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("module ").map(str::trim))
    {
        let name = module.rsplit('/').next().unwrap_or(module).trim();
        if !name.is_empty() {
            genome.agent_name = name.to_string();
            genome.record(Source::GoMod, "agent.name", name, "go.mod module path");
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct CargoToml {
    package: Option<CargoPackage>,
    dependencies: Option<toml::Table>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: Option<String>,
    description: Option<String>,
}

/// `Cargo.toml` → `runtime_kind = "rust"`, package name/description, deps.
pub(crate) fn apply_cargo(
    path: &Path,
    genome: &mut DetectedGenome,
    deps: &mut Vec<Dependency>,
) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("Cargo.toml"))? else {
        return Ok(());
    };
    let parsed: CargoToml =
        toml::from_str(&text).map_err(|e| CliError::Schema(format!("Cargo.toml: {e}")))?;
    genome.runtime_kind = Some("rust".to_string());
    genome.record(
        Source::Cargo,
        "runtime.runtime_kind",
        "rust",
        "Cargo.toml present",
    );
    if let Some(pkg) = parsed.package {
        if let Some(name) = pkg.name.filter(|s| !s.is_empty()) {
            genome.agent_name = name.clone();
            genome.record(
                Source::Cargo,
                "agent.name",
                &name,
                "Cargo.toml package.name",
            );
        }
        if let Some(desc) = pkg.description.filter(|s| !s.is_empty()) {
            genome.description = Some(desc.clone());
            genome.record(
                Source::Cargo,
                "description",
                &desc,
                "Cargo.toml package.description",
            );
        }
    }
    if let Some(table) = parsed.dependencies {
        for (name, value) in table {
            deps.push(Dependency {
                name: name.to_lowercase(),
                version: cargo_dep_version(&value),
                source: Source::Cargo,
            });
        }
    }
    Ok(())
}

fn cargo_dep_version(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    }
}

#[derive(Deserialize)]
struct PackageJson {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
}

/// `package.json` → `runtime_kind = "node"`, name/description, deps.
pub(crate) fn apply_package_json(
    path: &Path,
    genome: &mut DetectedGenome,
    deps: &mut Vec<Dependency>,
) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("package.json"))? else {
        return Ok(());
    };
    let parsed: PackageJson =
        serde_json::from_str(&text).map_err(|e| CliError::Schema(format!("package.json: {e}")))?;
    genome.runtime_kind = Some("node".to_string());
    genome.record(
        Source::PackageJson,
        "runtime.runtime_kind",
        "node",
        "package.json present",
    );
    if let Some(name) = parsed.name.filter(|s| !s.is_empty()) {
        genome.agent_name = name.clone();
        genome.record(
            Source::PackageJson,
            "agent.name",
            &name,
            "package.json name",
        );
    }
    if let Some(desc) = parsed.description.filter(|s| !s.is_empty()) {
        genome.description = Some(desc.clone());
        genome.record(
            Source::PackageJson,
            "description",
            &desc,
            "package.json description",
        );
    }
    for (name, version) in parsed
        .dependencies
        .into_iter()
        .chain(parsed.dev_dependencies)
    {
        deps.push(Dependency {
            name: name.to_lowercase(),
            version: Some(version),
            source: Source::PackageJson,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_dep_version_string_and_table() {
        assert_eq!(
            cargo_dep_version(&toml::Value::String("1.2".into())).as_deref(),
            Some("1.2")
        );
        let t: toml::Value = toml::from_str("version = \"2.0\"\nfeatures = []\n")
            .map(toml::Value::Table)
            .unwrap();
        assert_eq!(cargo_dep_version(&t).as_deref(), Some("2.0"));
    }
}
