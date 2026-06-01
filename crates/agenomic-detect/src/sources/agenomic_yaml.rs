//! Source: an existing `agenomic.yaml` (§2.3 tier 7, highest precedence).
//!
//! Read last so its values win — this is what makes a second `agm init` (or any
//! `agm update`) idempotent, and lets a project pin a `model_id` that overrides
//! the inferred default (§2.4).

use std::path::Path;

use agenomic_core::{CliError, CliResult};

use crate::model::{DetectedGenome, Source};
use crate::sources::read_file_opt;

/// Overlay scalar fields from `agenomic.yaml` onto the detected genome.
pub(crate) fn apply(path: &Path, genome: &mut DetectedGenome) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("agenomic.yaml"))? else {
        return Ok(());
    };
    let value: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|e| CliError::Schema(format!("agenomic.yaml: {e}")))?;

    if let Some(s) = nested_str(&value, &["agent", "id"]) {
        genome.agent_id = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "agent.id",
            s,
            "agenomic.yaml agent.id",
        );
    }
    if let Some(s) = nested_str(&value, &["agent", "name"]) {
        genome.agent_name = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "agent.name",
            s,
            "agenomic.yaml agent.name",
        );
    }
    if let Some(s) = nested_str(&value, &["agent", "domain"]) {
        genome.domain = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "agent.domain",
            s,
            "agenomic.yaml agent.domain",
        );
    }
    if let Some(s) = nested_str(&value, &["agent", "criticality"]) {
        genome.criticality = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "agent.criticality",
            s,
            "agenomic.yaml agent.criticality",
        );
    }
    if let Some(s) = nested_str(&value, &["description"]) {
        genome.description = Some(s.to_string());
        genome.record(
            Source::AgenomicYaml,
            "description",
            s,
            "agenomic.yaml description",
        );
    }
    if let Some(s) = nested_str(&value, &["runtime", "framework"]) {
        genome.framework = Some(s.to_string());
        genome.record(
            Source::AgenomicYaml,
            "runtime.framework",
            s,
            "agenomic.yaml runtime.framework",
        );
    }
    if let Some(s) = nested_str(&value, &["runtime", "runtime_kind"]) {
        genome.runtime_kind = Some(s.to_string());
        genome.record(
            Source::AgenomicYaml,
            "runtime.runtime_kind",
            s,
            "agenomic.yaml runtime.runtime_kind",
        );
    }
    if let Some(s) = nested_str(&value, &["runtime", "model_provider"]) {
        genome.model_provider = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "runtime.model_provider",
            s,
            "agenomic.yaml runtime.model_provider",
        );
    }
    if let Some(s) = nested_str(&value, &["runtime", "model_id"]) {
        genome.model_id = s.to_string();
        genome.record(
            Source::AgenomicYaml,
            "runtime.model_id",
            s,
            "agenomic.yaml runtime.model_id",
        );
    }
    if let Some(s) = nested_str(&value, &["runtime", "entrypoint"]) {
        genome.entrypoint = Some(s.to_string());
        genome.record(
            Source::AgenomicYaml,
            "runtime.entrypoint",
            s,
            "agenomic.yaml runtime.entrypoint",
        );
    }
    Ok(())
}

/// Follow a path of mapping keys and return the leaf as a non-empty `&str`.
fn nested_str<'a>(value: &'a serde_yaml::Value, keys: &[&str]) -> Option<&'a str> {
    let mut node = value;
    for k in keys {
        node = node.get(k)?;
    }
    node.as_str().filter(|s| !s.is_empty())
}
