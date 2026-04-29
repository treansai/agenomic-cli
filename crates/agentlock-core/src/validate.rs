use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use blake3::Hasher;
use jsonschema::{Draft, JSONSchema};

use crate::bundle::{
    collect_bundle_file_entries, load_bundle_dir, AGENT_LOCK_FILE, BEHAVIOR_CONTRACT_FILE,
    GENOME_FILE, SYSTEM_PROMPT_FILE,
};
use crate::errors::AgentlockError;
use crate::models::{LoadedBundle, TraceEvent};

const GENOME_SCHEMA: &str = include_str!("../../../schemas/genome.schema.json");
const AGENT_LOCK_SCHEMA: &str = include_str!("../../../schemas/agent-lock.schema.json");
const BEHAVIOR_CONTRACT_SCHEMA: &str =
    include_str!("../../../schemas/behavior-contract.schema.json");
const TRACE_EVENT_SCHEMA: &str = include_str!("../../../schemas/trace-event.schema.json");

pub fn validate_bundle_dir(path: &Path) -> Result<LoadedBundle> {
    let mut errors = Vec::new();

    if !path.exists() {
        return Err(AgentlockError::MissingPath(path.display().to_string()).into());
    }
    if !path.is_dir() {
        return Err(AgentlockError::NotADirectory(path.display().to_string()).into());
    }

    for required in [
        GENOME_FILE,
        AGENT_LOCK_FILE,
        BEHAVIOR_CONTRACT_FILE,
        SYSTEM_PROMPT_FILE,
    ] {
        if !path.join(required).exists() {
            errors.push(format!("required file missing: {required}"));
        }
    }

    if !errors.is_empty() {
        anyhow::bail!("bundle validation failed:\n- {}", errors.join("\n- "));
    }

    validate_yaml_schema(&path.join(GENOME_FILE), GENOME_SCHEMA)?;
    validate_yaml_schema(&path.join(AGENT_LOCK_FILE), AGENT_LOCK_SCHEMA)?;
    validate_yaml_schema(&path.join(BEHAVIOR_CONTRACT_FILE), BEHAVIOR_CONTRACT_SCHEMA)?;

    let bundle = load_bundle_dir(path)?;

    if bundle.agent_lock.agent_id != bundle.genome.agent.id {
        errors.push(format!(
            "agent.lock.yaml agent_id `{}` does not match genome agent.id `{}`",
            bundle.agent_lock.agent_id, bundle.genome.agent.id
        ));
    }

    if bundle.agent_lock.behavior_contract_id != bundle.behavior_contract.contract.id {
        errors.push(format!(
            "agent.lock.yaml behavior_contract_id `{}` does not match behavior.contract.yaml contract.id `{}`",
            bundle.agent_lock.behavior_contract_id, bundle.behavior_contract.contract.id
        ));
    }

    for tracked in &bundle.agent_lock.tracked_files {
        if !path.join(&tracked.path).exists() {
            errors.push(format!("tracked file missing: {}", tracked.path));
        }
    }

    if bundle.prompts.is_empty() {
        errors.push("no prompt files found under prompts/".to_owned());
    }

    if !errors.is_empty() {
        anyhow::bail!("bundle validation failed:\n- {}", errors.join("\n- "));
    }

    Ok(bundle)
}

pub fn parse_trace_events(path: &Path) -> Result<Vec<TraceEvent>> {
    if !path.exists() {
        return Err(AgentlockError::MissingPath(path.display().to_string()).into());
    }

    let schema = compile_schema(TRACE_EVENT_SCHEMA)?;
    let input =
        fs::read_to_string(path).with_context(|| format!("failed to read `{}`", path.display()))?;

    let mut events = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!("invalid JSON in `{}` at line {}", path.display(), index + 1)
        })?;
        if let Err(iter) = schema.validate(&value) {
            let message = iter
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!(
                "trace schema validation failed in `{}` at line {}: {message}",
                path.display(),
                index + 1
            );
        }

        let event: TraceEvent = serde_json::from_value(value).with_context(|| {
            format!(
                "trace event deserialization failed in `{}` at line {}",
                path.display(),
                index + 1
            )
        })?;
        events.push(event);
    }

    if events.is_empty() {
        return Err(AgentlockError::EmptyTraceFile(path.display().to_string()).into());
    }

    Ok(events)
}

pub fn hash_bundle_dir(path: &Path) -> Result<String> {
    let bundle = validate_bundle_dir(path)?;
    let entries = collect_bundle_file_entries(path, &bundle)?;
    hash_bundle_from_entries(&entries)
}

pub fn hash_bundle_from_entries(entries: &[crate::bundle::BundleFileEntry]) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(b"agentlock.bundle.v1\n");

    for entry in entries {
        let bytes = fs::read(&entry.absolute_path)
            .with_context(|| format!("failed to read `{}`", entry.absolute_path.display()))?;
        hasher.update(entry.relative_path.as_bytes());
        hasher.update(b"\n");
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b"\n");
        hasher.update(&bytes);
        hasher.update(b"\n");
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_yaml_schema(path: &Path, schema: &'static str) -> Result<()> {
    let schema = compile_schema(schema)?;
    let bytes = fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    let instance: serde_json::Value = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("invalid YAML in `{}`", path.display()))?;

    if let Err(iter) = schema.validate(&instance) {
        let message = iter
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!(
            "schema validation failed for `{}`: {message}",
            path.display()
        );
    }

    Ok(())
}

fn compile_schema(raw: &'static str) -> Result<JSONSchema> {
    let schema: serde_json::Value =
        serde_json::from_str(raw).context("failed to parse embedded JSON schema")?;
    let leaked_schema: &'static serde_json::Value = Box::leak(Box::new(schema));
    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(leaked_schema)
        .context("failed to compile JSON schema")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;

    use crate::bundle::init_bundle_dir;

    use super::{hash_bundle_dir, parse_trace_events, validate_bundle_dir};

    #[test]
    fn init_then_validate_bundle() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bundle_path = temp.path().join("starter");
        init_bundle_dir(&bundle_path)?;

        let bundle = validate_bundle_dir(&bundle_path)?;
        assert_eq!(bundle.genome.agent.id, "starter");
        assert!(bundle.prompts.contains_key("prompts/system.md"));
        Ok(())
    }

    #[test]
    fn hash_is_stable_for_same_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bundle_path = temp.path().join("stable-bundle");
        init_bundle_dir(&bundle_path)?;

        let first = hash_bundle_dir(&bundle_path)?;
        let second = hash_bundle_dir(&bundle_path)?;
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn parse_trace_file() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let trace_path = temp.path().join("trace.jsonl");
        fs::write(
            &trace_path,
            "{\"trace_id\":\"t1\",\"step\":1,\"event\":\"assistant_output\",\"content\":\"ok\"}\n",
        )?;

        let traces = parse_trace_events(&trace_path)?;
        assert_eq!(traces.len(), 1);
        Ok(())
    }
}
