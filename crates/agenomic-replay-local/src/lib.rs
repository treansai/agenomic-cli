//! Deterministic offline replay for Agenomic bundles.
//!
//! This crate does NOT call any LLM. It evaluates a stored corpus of
//! [`TraceEnvelope`]s against a [`BehaviorContract`]'s deterministic checks
//! and produces a [`ReplayReport`].

use std::path::{Path, PathBuf};

use agenomic_atep::{AtepStore, StreamId};
use agenomic_bundle::{inspect_bundle, read_archive_to_pairs};
use agenomic_contract::{
    evaluate_contract, parse_contract_yaml, parse_traces_jsonl, BehaviorContract,
    ContractEvaluation, TraceEnvelope, TraceViolation,
};
use agenomic_core::{io_at, CliError, CliResult, Severity, ValidationIssue};
use agenomic_hash::{compute_manifest, compute_manifest_from_pairs, BundleManifest};
use serde::{Deserialize, Serialize};

/// Replay options.
#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub bundle: PathBuf,
    pub traces: Option<PathBuf>,
    pub atep_store: Option<PathBuf>,
    pub contract: Option<PathBuf>,
    pub runs_per_trace: u32,
    pub fail_on: Severity,
}

/// One violation in the replay report.
pub type ReplayViolation = TraceViolation;

/// Aggregate counters for a replay.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReplayAggregates {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

/// Replay report (matches `replay-report.schema.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayReport {
    pub report_version: String,
    pub bundle_hash: String,
    pub bundle_logical_hash: String,
    pub contract_id: String,
    pub total_traces: usize,
    pub total_runs: usize,
    pub mode: String,
    pub contract_passed: bool,
    pub violations: Vec<ReplayViolation>,
    pub aggregates: ReplayAggregates,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Honesty disclaimers and other diagnostic notes.
    #[serde(default)]
    pub notes: Vec<ValidationIssue>,
}

const REPORT_VERSION: &str = "agenomic.replay/v0.1";

/// Run a local replay and produce a [`ReplayReport`].
///
/// ```no_run
/// use agenomic_replay_local::{run_local_replay, ReplayOptions};
/// use agenomic_core::Severity;
/// let opts = ReplayOptions {
///     bundle: "./examples/claims-agent".into(),
///     traces: Some("./examples/claims-agent/traces/synthetic_claim_traces.jsonl".into()),
///     atep_store: None,
///     contract: None,
///     runs_per_trace: 1,
///     fail_on: Severity::Critical,
/// };
/// let _r = run_local_replay(opts).unwrap();
/// ```
pub fn run_local_replay(options: ReplayOptions) -> CliResult<ReplayReport> {
    let manifest = load_manifest(&options.bundle)?;
    let summary = inspect_bundle(&options.bundle)?;

    // Contract resolution: explicit override > bundle's behavior.contract.yaml
    let contract_text = match &options.contract {
        Some(p) => std::fs::read_to_string(p).map_err(|e| io_at(p, e))?,
        None => read_bundle_contract(&options.bundle)?,
    };
    let contract: BehaviorContract = parse_contract_yaml(&contract_text)?;

    // Trace source
    let mut traces: Vec<TraceEnvelope> = Vec::new();
    if let Some(traces_path) = &options.traces {
        let text = std::fs::read_to_string(traces_path).map_err(|e| io_at(traces_path, e))?;
        traces.extend(parse_traces_jsonl(&text)?);
    }
    if let Some(store_path) = &options.atep_store {
        traces.extend(traces_from_atep(store_path)?);
    }

    let mut notes: Vec<ValidationIssue> = Vec::new();
    if options.runs_per_trace > 1 {
        notes.push(ValidationIssue {
            code: "agenomic::replay::runs_per_trace_no_op".into(),
            severity: Severity::Medium,
            message: "Local replay v0.1 only validates stored traces against deterministic contract checks. \
                runs_per_trace > 1 has no effect without a runtime adapter (provider plugin). \
                For statistical replay across LLM stochasticity, use Agenomic Cloud or a custom runtime adapter."
                .into(),
            path: None,
            hint: None,
            doc: None,
        });
    }

    let evaluation: ContractEvaluation = evaluate_contract(&contract, &traces)?;

    let mut violations: Vec<ReplayViolation> = Vec::new();
    for vs in evaluation.violations_by_check.values() {
        violations.extend(vs.iter().cloned());
    }

    let aggregates = ReplayAggregates {
        critical: evaluation.critical_count,
        high: evaluation.high_count,
        medium: evaluation.medium_count,
        low: evaluation.low_count,
    };

    let max_sev = aggregates_max(&aggregates);
    let contract_passed = max_sev < options.fail_on
        || (matches!(options.fail_on, Severity::Critical) && aggregates.critical == 0);

    Ok(ReplayReport {
        report_version: REPORT_VERSION.into(),
        bundle_hash: summary.logical_bundle_hash,
        bundle_logical_hash: manifest.root_hash,
        contract_id: contract.id,
        total_traces: traces.len(),
        total_runs: traces.len() * options.runs_per_trace as usize,
        mode: "deterministic_offline".into(),
        contract_passed,
        violations,
        aggregates,
        generated_at: chrono::Utc::now(),
        notes,
    })
}

fn aggregates_max(a: &ReplayAggregates) -> Severity {
    if a.critical > 0 {
        Severity::Critical
    } else if a.high > 0 {
        Severity::High
    } else if a.medium > 0 {
        Severity::Medium
    } else if a.low > 0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn load_manifest(target: &Path) -> CliResult<BundleManifest> {
    if target.is_dir() {
        compute_manifest(target)
    } else {
        let pairs = read_archive_to_pairs(target)?;
        compute_manifest_from_pairs(pairs.into_iter().map(|(p, c)| (p, c)))
    }
}

fn read_bundle_contract(target: &Path) -> CliResult<String> {
    if target.is_dir() {
        let p = target.join("behavior.contract.yaml");
        std::fs::read_to_string(&p).map_err(|e| io_at(&p, e))
    } else {
        let pairs = read_archive_to_pairs(target)?;
        for (p, c) in pairs {
            if p == "behavior.contract.yaml" {
                return String::from_utf8(c)
                    .map_err(|e| CliError::Internal(format!("contract not utf-8: {e}")));
            }
        }
        Err(CliError::Internal(
            "behavior.contract.yaml not found in archive".into(),
        ))
    }
}

fn traces_from_atep(store_path: &Path) -> CliResult<Vec<TraceEnvelope>> {
    // Read the manifest first to learn the agent_id.
    let manifest_path = store_path.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
    let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| CliError::Internal(format!("atep manifest parse: {e}")))?;
    let store = AtepStore::open_or_init(store_path, &manifest.agent_id)?;
    let interactions = store.read_stream(StreamId::Interaction)?;

    let mut out: Vec<TraceEnvelope> = Vec::new();
    for ev in interactions {
        // Convert CBOR payload to JSON; skip events that fail conversion.
        let json = match cbor_to_json(&ev.payload.0) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let trace_id = json
            .get("trace_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| ulid::Ulid::from_bytes(ev.header.event_id).to_string());
        let input = json
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let output = json.get("output").cloned();
        let tool_calls: Vec<agenomic_contract::ToolCall> = json
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let metadata = json.get("metadata").cloned();
        out.push(TraceEnvelope {
            trace_id,
            agent_id: ev.header.agent_id,
            input,
            output,
            tool_calls,
            metadata,
        });
    }
    Ok(out)
}

fn cbor_to_json(v: &ciborium::value::Value) -> CliResult<serde_json::Value> {
    use ciborium::value::Value as C;
    Ok(match v {
        C::Null => serde_json::Value::Null,
        C::Bool(b) => serde_json::Value::Bool(*b),
        C::Integer(i) => {
            let as_i128: i128 = (*i).into();
            if let Ok(n) = i64::try_from(as_i128) {
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::String(as_i128.to_string())
            }
        }
        C::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        C::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        C::Text(s) => serde_json::Value::String(s.clone()),
        C::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                out.push(cbor_to_json(x)?);
            }
            serde_json::Value::Array(out)
        }
        C::Map(m) => {
            let mut out = serde_json::Map::with_capacity(m.len());
            for (k, val) in m {
                let key = match k {
                    C::Text(s) => s.clone(),
                    C::Integer(i) => i128::from(*i).to_string(),
                    _ => continue,
                };
                out.insert(key, cbor_to_json(val)?);
            }
            serde_json::Value::Object(out)
        }
        C::Tag(_, inner) => cbor_to_json(inner)?,
        _ => serde_json::Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_bundle(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("genome.yaml"),
            "spec_version: '0.1'\nagent:\n  id: 'agent://acme/foo'\n  name: 'Foo'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n",
        )
        .unwrap();
        fs::write(
            dir.join("agent.lock.yaml"),
            "spec_version: '0.1'\nagent_id: 'agent://acme/foo'\nmodel:\n  provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nknowledge: []\n",
        )
        .unwrap();
        fs::write(
            dir.join("behavior.contract.yaml"),
            "spec_version: '0.1'\ncontract:\n  id: 'c1'\n  rules:\n    - id: r1\n      type: required_output_field\n      severity: high\n      required_fields: [language]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("prompts")).unwrap();
        fs::write(dir.join("prompts/system.md"), "x").unwrap();
    }

    #[test]
    fn passing_replay() {
        let d = tempdir().unwrap();
        write_bundle(d.path());

        let traces = d.path().join("traces.jsonl");
        fs::write(
            &traces,
            r#"{"trace_id":"t1","agent_id":"agent://acme/foo","input":{},"output":{"language":"en"}}"#,
        )
        .unwrap();

        let r = run_local_replay(ReplayOptions {
            bundle: d.path().to_path_buf(),
            traces: Some(traces),
            atep_store: None,
            contract: None,
            runs_per_trace: 1,
            fail_on: Severity::Critical,
        })
        .unwrap();
        assert!(r.contract_passed);
        assert_eq!(r.aggregates.high, 0);
    }

    #[test]
    fn failing_replay() {
        let d = tempdir().unwrap();
        write_bundle(d.path());

        let traces = d.path().join("traces.jsonl");
        fs::write(
            &traces,
            r#"{"trace_id":"t1","agent_id":"agent://acme/foo","input":{},"output":{}}"#,
        )
        .unwrap();

        let r = run_local_replay(ReplayOptions {
            bundle: d.path().to_path_buf(),
            traces: Some(traces),
            atep_store: None,
            contract: None,
            runs_per_trace: 1,
            fail_on: Severity::High,
        })
        .unwrap();
        assert!(!r.contract_passed);
        assert_eq!(r.aggregates.high, 1);
    }

    #[test]
    fn runs_per_trace_emits_disclaimer() {
        let d = tempdir().unwrap();
        write_bundle(d.path());
        let traces = d.path().join("traces.jsonl");
        fs::write(
            &traces,
            r#"{"trace_id":"t1","agent_id":"agent://acme/foo","input":{},"output":{"language":"en"}}"#,
        )
        .unwrap();
        let r = run_local_replay(ReplayOptions {
            bundle: d.path().to_path_buf(),
            traces: Some(traces),
            atep_store: None,
            contract: None,
            runs_per_trace: 5,
            fail_on: Severity::Critical,
        })
        .unwrap();
        assert!(r
            .notes
            .iter()
            .any(|n| n.code == "agenomic::replay::runs_per_trace_no_op"));
    }
}
