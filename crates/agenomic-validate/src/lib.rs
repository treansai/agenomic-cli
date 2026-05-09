//! Multi-level validation for Agenomic bundle directories and archives.
//!
//! Three levels:
//!
//! - **Basic**: required files present, YAML parses
//! - **Strict**: schema validation, cross-references
//! - **Ci**: strict + security scan, all warnings ≥ High become errors,
//!   model fingerprint required, knowledge snapshot_hash required

pub mod security;

use std::collections::HashSet;
use std::path::Path;

use agenomic_core::{
    io_at, CliError, CliResult, Severity, ValidationIssue, ValidationLevel, ValidationReport,
};
use agenomic_spec::{validator, SchemaKind};

/// Required files for a bundle directory (Basic level).
pub const REQUIRED_FILES: &[&str] = &["genome.yaml", "behavior.contract.yaml"];

/// Validate a bundle directory.
///
/// ```no_run
/// use agenomic_validate::validate_bundle;
/// use agenomic_core::ValidationLevel;
/// let r = validate_bundle(std::path::Path::new("./examples/claims-agent"),
///                         ValidationLevel::Strict).unwrap();
/// assert!(r.valid);
/// ```
pub fn validate_bundle(dir: &Path, level: ValidationLevel) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };

    // ---- Basic ----
    for required in REQUIRED_FILES {
        let p = dir.join(required);
        if !p.is_file() {
            report.push_error(ValidationIssue {
                code: "agenomic::bundle::missing_required_file".into(),
                severity: Severity::High,
                message: format!("missing required file: {required}"),
                path: Some(required.to_string()),
                hint: Some("run `agenomic init` to scaffold the bundle".into()),
                doc: None,
            });
        }
    }
    let lock_yaml = dir.join("agent.lock.yaml");
    let lock_plain = dir.join("agent.lock");
    let have_lockfile = lock_yaml.is_file() || lock_plain.is_file();
    if !have_lockfile {
        report.push_error(ValidationIssue {
            code: "agenomic::bundle::missing_required_file".into(),
            severity: Severity::High,
            message: "missing required file: agent.lock(.yaml)".into(),
            path: Some("agent.lock.yaml".into()),
            hint: Some("run `agenomic init` to scaffold the lockfile".into()),
            doc: None,
        });
    }

    let prompts_dir = dir.join("prompts");
    let prompts_present = prompts_dir.is_dir()
        && walkdir::WalkDir::new(&prompts_dir)
            .into_iter()
            .filter_map(Result::ok)
            .any(|e| e.file_type().is_file());
    if !prompts_present {
        report.push_warning(ValidationIssue {
            code: "agenomic::bundle::missing_prompts".into(),
            severity: Severity::Medium,
            message: "no prompts/ directory or it is empty".into(),
            path: Some("prompts/".into()),
            hint: Some("add at least one prompt under prompts/".into()),
            doc: None,
        });
    }

    let genome_text = read_if_exists(&dir.join("genome.yaml"))?;
    let lock_text = if lock_yaml.is_file() {
        read_if_exists(&lock_yaml)?
    } else if lock_plain.is_file() {
        read_if_exists(&lock_plain)?
    } else {
        None
    };
    let contract_text = read_if_exists(&dir.join("behavior.contract.yaml"))?;

    if let Some(t) = &genome_text {
        if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(t) {
            report.push_error(ValidationIssue {
                code: "agenomic::bundle::yaml_parse".into(),
                severity: Severity::High,
                message: format!("genome.yaml: parse error: {e}"),
                path: Some("genome.yaml".into()),
                hint: None,
                doc: None,
            });
        }
    }
    if let Some(t) = &lock_text {
        if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(t) {
            report.push_error(ValidationIssue {
                code: "agenomic::bundle::yaml_parse".into(),
                severity: Severity::High,
                message: format!("agent.lock(.yaml): parse error: {e}"),
                path: Some("agent.lock.yaml".into()),
                hint: None,
                doc: None,
            });
        }
    }
    if let Some(t) = &contract_text {
        if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(t) {
            report.push_error(ValidationIssue {
                code: "agenomic::bundle::yaml_parse".into(),
                severity: Severity::High,
                message: format!("behavior.contract.yaml: parse error: {e}"),
                path: Some("behavior.contract.yaml".into()),
                hint: None,
                doc: None,
            });
        }
    }

    if matches!(level, ValidationLevel::Basic) {
        if !report.errors.is_empty() {
            report.valid = false;
        }
        return Ok(report);
    }

    // ---- Strict ----
    if let Some(t) = &genome_text {
        run_schema(SchemaKind::Genome, t, "genome.yaml", &mut report)?;
    }
    if let Some(t) = &lock_text {
        run_schema(SchemaKind::Agenomic, t, "agent.lock.yaml", &mut report)?;
    }
    if let Some(t) = &contract_text {
        run_schema(
            SchemaKind::BehaviorContract,
            t,
            "behavior.contract.yaml",
            &mut report,
        )?;
    }

    cross_reference(&genome_text, &lock_text, &contract_text, &mut report);

    if matches!(level, ValidationLevel::Strict) {
        if !report.errors.is_empty() {
            report.valid = false;
        }
        return Ok(report);
    }

    // ---- Ci ----
    if let Some(t) = &genome_text {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(t) {
            let fp = v
                .get("runtime")
                .and_then(|r| r.get("model_fingerprint"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if fp.is_empty() {
                report.push_error(ValidationIssue {
                    code: "agenomic::ci::missing_model_fingerprint".into(),
                    severity: Severity::High,
                    message: "runtime.model_fingerprint is required at ci level".into(),
                    path: Some("genome.yaml".into()),
                    hint: Some("pin the model fingerprint after a successful run".into()),
                    doc: None,
                });
            }
            if let Some(arr) = v.get("knowledge").and_then(|x| x.as_sequence()) {
                for k in arr {
                    let snap = k
                        .get("snapshot_hash")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let name = k.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    if snap.is_empty() {
                        report.push_error(ValidationIssue {
                            code: "agenomic::ci::missing_snapshot_hash".into(),
                            severity: Severity::High,
                            message: format!(
                                "knowledge[{name}].snapshot_hash is required at ci level"
                            ),
                            path: Some("genome.yaml".into()),
                            hint: None,
                            doc: None,
                        });
                    }
                }
            }
        }
    }

    let scan_issues = security::security_scan(dir)?;
    for issue in scan_issues {
        if issue.severity >= Severity::High {
            report.push_error(issue);
        } else {
            report.push_warning(issue);
        }
    }

    if !report.errors.is_empty() {
        report.valid = false;
    } else if report.warnings.iter().any(|i| i.severity >= Severity::High) {
        report.valid = false;
    }

    Ok(report)
}

/// Validate by extracting an archive into a temp dir and running [`validate_bundle`].
pub fn validate_archive(archive: &Path, level: ValidationLevel) -> CliResult<ValidationReport> {
    let tmp = tempfile::tempdir().map_err(|e| CliError::Internal(format!("tempdir: {e}")))?;
    agenomic_bundle::extract_bundle(agenomic_bundle::ExtractOptions {
        archive: archive.to_path_buf(),
        destination: tmp.path().to_path_buf(),
    })?;
    validate_bundle(tmp.path(), level)
}

/// Validate a single genome YAML string.
pub fn validate_genome(genome_yaml: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    run_schema(SchemaKind::Genome, genome_yaml, "genome.yaml", &mut report)?;
    if !report.errors.is_empty() {
        report.valid = false;
    }
    Ok(report)
}

/// Validate a single lockfile YAML string.
pub fn validate_agenomic(lock_yaml: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    run_schema(
        SchemaKind::Agenomic,
        lock_yaml,
        "agent.lock.yaml",
        &mut report,
    )?;
    if !report.errors.is_empty() {
        report.valid = false;
    }
    Ok(report)
}

/// Validate a single behavior contract YAML string.
pub fn validate_behavior_contract(contract_yaml: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    run_schema(
        SchemaKind::BehaviorContract,
        contract_yaml,
        "behavior.contract.yaml",
        &mut report,
    )?;
    if !report.errors.is_empty() {
        report.valid = false;
    }
    Ok(report)
}

/// Validate an ATEP event JSON document.
pub fn validate_atep_event(event_json: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    let v: serde_json::Value = serde_json::from_str(event_json)
        .map_err(|e| CliError::Schema(format!("event json parse: {e}")))?;
    let validator = validator(SchemaKind::AtepEvent)?;
    if let Err(errs) = validator.validate(&v) {
        for err in errs {
            report.push_error(ValidationIssue {
                code: "agenomic::atep::schema".into(),
                severity: Severity::High,
                message: err.to_string(),
                path: Some(err.instance_path.to_string()),
                hint: None,
                doc: None,
            });
        }
    }
    if !report.errors.is_empty() {
        report.valid = false;
    }
    Ok(report)
}

fn read_if_exists(p: &Path) -> CliResult<Option<String>> {
    if p.is_file() {
        Ok(Some(std::fs::read_to_string(p).map_err(|e| io_at(p, e))?))
    } else {
        Ok(None)
    }
}

fn run_schema(
    kind: SchemaKind,
    yaml_text: &str,
    file_label: &str,
    report: &mut ValidationReport,
) -> CliResult<()> {
    let value: serde_yaml::Value = match serde_yaml::from_str(yaml_text) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let json = serde_yaml_to_json(value);
    let v = validator(kind)?;
    if let Err(errs) = v.validate(&json) {
        for err in errs {
            report.push_error(ValidationIssue {
                code: format!("agenomic::schema::{}", kind.label()),
                severity: Severity::High,
                message: err.to_string(),
                path: Some(format!("{file_label}{}", err.instance_path)),
                hint: None,
                doc: None,
            });
        }
    }
    Ok(())
}

fn serde_yaml_to_json(v: serde_yaml::Value) -> serde_json::Value {
    match v {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(b) => serde_json::Value::Bool(b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml::Value::String(s) => serde_json::Value::String(s),
        serde_yaml::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.into_iter().map(serde_yaml_to_json).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    other => format!("{other:?}"),
                };
                out.insert(key, serde_yaml_to_json(v));
            }
            serde_json::Value::Object(out)
        }
        serde_yaml::Value::Tagged(t) => serde_yaml_to_json(t.value),
    }
}

fn cross_reference(
    genome: &Option<String>,
    lock: &Option<String>,
    _contract: &Option<String>,
    report: &mut ValidationReport,
) {
    let g_yaml = genome
        .as_ref()
        .and_then(|t| serde_yaml::from_str::<serde_yaml::Value>(t).ok());
    let l_yaml = lock
        .as_ref()
        .and_then(|t| serde_yaml::from_str::<serde_yaml::Value>(t).ok());

    if let (Some(g), Some(l)) = (&g_yaml, &l_yaml) {
        let g_id = g
            .get("agent")
            .and_then(|a| a.get("id"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let l_id = l.get("agent_id").and_then(|x| x.as_str()).unwrap_or("");
        if !g_id.is_empty() && !l_id.is_empty() && g_id != l_id {
            report.push_error(ValidationIssue {
                code: "agenomic::xref::agent_id_mismatch".into(),
                severity: Severity::High,
                message: format!(
                    "agent.id in genome ({g_id}) does not match agent_id in lockfile ({l_id})"
                ),
                path: Some("agent.lock.yaml".into()),
                hint: None,
                doc: None,
            });
        }

        let g_tools: HashSet<String> = g
            .get("tools")
            .and_then(|x| x.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let l_tools: HashSet<String> = l
            .get("tools")
            .and_then(|x| x.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        for t in g_tools.difference(&l_tools) {
            report.push_warning(ValidationIssue {
                code: "agenomic::xref::tool_in_genome_not_locked".into(),
                severity: Severity::Medium,
                message: format!("tool '{t}' declared in genome but not present in lockfile"),
                path: Some("agent.lock.yaml".into()),
                hint: Some("run `agenomic build` to refresh the lockfile".into()),
                doc: None,
            });
        }
        for t in l_tools.difference(&g_tools) {
            report.push_warning(ValidationIssue {
                code: "agenomic::xref::tool_in_lock_not_genome".into(),
                severity: Severity::Medium,
                message: format!("tool '{t}' is locked but not declared in genome"),
                path: Some("genome.yaml".into()),
                hint: None,
                doc: None,
            });
        }
    }
}
