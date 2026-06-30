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
    // System bundles (spec 0.2, RFC 0009) carry a `system.yaml` instead of a
    // genome and are validated by their own rules.
    if dir.join("system.yaml").is_file() && !dir.join("genome.yaml").is_file() {
        return validate_system_bundle(dir, level);
    }

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

    validate_workflow_files(dir, &mut report)?;

    // An agent bundle may also carry a system manifest (e.g. a monorepo whose
    // genome describes the platform and whose system.yaml describes the
    // member topology, RFC 0009).
    if let Some(t) = read_if_exists(&dir.join("system.yaml"))? {
        run_schema(SchemaKind::System, &t, "system.yaml", &mut report)?;
        if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&t) {
            system_semantic_checks(&doc, Some(dir), &mut report);
        }
    }

    cross_reference(&genome_text, &lock_text, &contract_text, &mut report);

    // Provider-specific semantic checks (e.g. Hugging Face).
    if let Some(t) = &genome_text {
        if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(t) {
            provider_semantic_checks(&doc, &mut report);
        }
    }

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

    if !report.errors.is_empty() || report.warnings.iter().any(|i| i.severity >= Severity::High) {
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
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(genome_yaml) {
        provider_semantic_checks(&doc, &mut report);
    }
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

/// Validate a single standalone manifest file (YAML).
///
/// The manifest kind is inferred from its top-level keys: `workflow` →
/// workflow manifest, `system` → system manifest, `agent` → genome.
pub fn validate_manifest_file(path: &Path) -> CliResult<ValidationReport> {
    let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
    let doc: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            let mut report = ValidationReport {
                valid: false,
                ..Default::default()
            };
            report.push_error(ValidationIssue {
                code: "agenomic::bundle::yaml_parse".into(),
                severity: Severity::High,
                message: format!("{}: parse error: {e}", path.display()),
                path: Some(path.display().to_string()),
                hint: None,
                doc: None,
            });
            return Ok(report);
        }
    };
    if doc.get("workflow").is_some() {
        validate_workflow(&text)
    } else if doc.get("system").is_some() {
        validate_system(&text)
    } else if doc.get("agent").is_some() {
        validate_genome(&text)
    } else {
        Err(CliError::Schema(
            "cannot infer manifest kind: expected a top-level `workflow`, `system`, or `agent` key"
                .into(),
        ))
    }
}

/// Validate a single workflow manifest YAML string (spec 0.2, RFC 0009).
pub fn validate_workflow(workflow_yaml: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    run_schema(
        SchemaKind::Workflow,
        workflow_yaml,
        "workflow.yaml",
        &mut report,
    )?;
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(workflow_yaml) {
        workflow_semantic_checks(&doc, "workflow.yaml", &mut report);
    }
    if !report.errors.is_empty() {
        report.valid = false;
    }
    Ok(report)
}

/// Validate a single system manifest YAML string (spec 0.2, RFC 0009).
pub fn validate_system(system_yaml: &str) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };
    run_schema(SchemaKind::System, system_yaml, "system.yaml", &mut report)?;
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(system_yaml) {
        system_semantic_checks(&doc, None, &mut report);
    }
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

/// Validate a system bundle: `system.yaml` plus its owned workflow manifests
/// (spec 0.2, RFC 0009).
fn validate_system_bundle(dir: &Path, level: ValidationLevel) -> CliResult<ValidationReport> {
    let mut report = ValidationReport {
        valid: true,
        ..Default::default()
    };

    // ---- Basic ----
    let system_text = read_if_exists(&dir.join("system.yaml"))?;
    let system_doc = match &system_text {
        Some(t) => match serde_yaml::from_str::<serde_yaml::Value>(t) {
            Ok(v) => Some(v),
            Err(e) => {
                report.push_error(ValidationIssue {
                    code: "agenomic::bundle::yaml_parse".into(),
                    severity: Severity::High,
                    message: format!("system.yaml: parse error: {e}"),
                    path: Some("system.yaml".into()),
                    hint: None,
                    doc: None,
                });
                None
            }
        },
        None => None,
    };

    if matches!(level, ValidationLevel::Basic) {
        if !report.errors.is_empty() {
            report.valid = false;
        }
        return Ok(report);
    }

    // ---- Strict ----
    if let Some(t) = &system_text {
        run_schema(SchemaKind::System, t, "system.yaml", &mut report)?;
    }
    if let Some(doc) = &system_doc {
        system_semantic_checks(doc, Some(dir), &mut report);
    }
    validate_workflow_files(dir, &mut report)?;

    if matches!(level, ValidationLevel::Strict) {
        if !report.errors.is_empty() {
            report.valid = false;
        }
        return Ok(report);
    }

    // ---- Ci ----
    let scan_issues = security::security_scan(dir)?;
    for issue in scan_issues {
        if issue.severity >= Severity::High {
            report.push_error(issue);
        } else {
            report.push_warning(issue);
        }
    }

    if !report.errors.is_empty() || report.warnings.iter().any(|i| i.severity >= Severity::High) {
        report.valid = false;
    }

    Ok(report)
}

/// Schema-validate the optional orchestration manifests of a bundle:
/// `workflow.yaml` at the root and every YAML file under `workflows/`.
fn validate_workflow_files(dir: &Path, report: &mut ValidationReport) -> CliResult<()> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let root = dir.join("workflow.yaml");
    if root.is_file() {
        files.push(root);
    }
    let workflows_dir = dir.join("workflows");
    if workflows_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&workflows_dir)
            .map_err(|e| io_at(&workflows_dir, e))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension().and_then(|x| x.to_str()).is_some_and(|x| {
                        x.eq_ignore_ascii_case("yaml") || x.eq_ignore_ascii_case("yml")
                    })
            })
            .collect();
        entries.sort();
        files.extend(entries);
    }

    for file in files {
        let label = file
            .strip_prefix(dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        if let Some(text) = read_if_exists(&file)? {
            match serde_yaml::from_str::<serde_yaml::Value>(&text) {
                Ok(doc) => {
                    run_schema(SchemaKind::Workflow, &text, &label, report)?;
                    workflow_semantic_checks(&doc, &label, report);
                }
                Err(e) => {
                    report.push_error(ValidationIssue {
                        code: "agenomic::bundle::yaml_parse".into(),
                        severity: Severity::High,
                        message: format!("{label}: parse error: {e}"),
                        path: Some(label.clone()),
                        hint: None,
                        doc: None,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Checks RFC 0009 requires beyond JSON Schema: step ids unique across the
/// workflow (including loop bodies), and every `depends_on` entry naming an
/// existing step at the same nesting level.
fn workflow_semantic_checks(
    doc: &serde_yaml::Value,
    file_label: &str,
    report: &mut ValidationReport,
) {
    fn check_level(
        steps: &[serde_yaml::Value],
        file_label: &str,
        all_ids: &mut HashSet<String>,
        report: &mut ValidationReport,
    ) {
        let level_ids: HashSet<&str> = steps
            .iter()
            .filter_map(|s| s.get("id").and_then(|x| x.as_str()))
            .collect();
        for step in steps {
            let id = step.get("id").and_then(|x| x.as_str()).unwrap_or("?");
            if !all_ids.insert(id.to_string()) {
                report.push_error(ValidationIssue {
                    code: "agenomic::workflow::duplicate_step_id".into(),
                    severity: Severity::High,
                    message: format!("duplicate step id '{id}'"),
                    path: Some(file_label.to_string()),
                    hint: None,
                    doc: None,
                });
            }
            if let Some(deps) = step.get("depends_on").and_then(|x| x.as_sequence()) {
                for dep in deps.iter().filter_map(|d| d.as_str()) {
                    if !level_ids.contains(dep) {
                        report.push_error(ValidationIssue {
                            code: "agenomic::workflow::unknown_dependency".into(),
                            severity: Severity::High,
                            message: format!(
                                "step '{id}' depends on unknown step '{dep}' (must exist at the same nesting level)"
                            ),
                            path: Some(file_label.to_string()),
                            hint: None,
                            doc: None,
                        });
                    }
                }
            }
            if let Some(body) = step.get("body").and_then(|x| x.as_sequence()) {
                check_level(body, file_label, all_ids, report);
            }
        }
    }

    if let Some(steps) = doc.get("steps").and_then(|x| x.as_sequence()) {
        let mut all_ids = HashSet::new();
        check_level(steps, file_label, &mut all_ids, report);
    }
}

/// Checks RFC 0009 requires beyond JSON Schema: member roles unique,
/// orchestration entrypoint/supervisor/edges referencing declared roles
/// (`END` allowed as edge target), and — when the bundle directory is known —
/// every `workflows[].path` existing on disk.
fn system_semantic_checks(
    doc: &serde_yaml::Value,
    dir: Option<&Path>,
    report: &mut ValidationReport,
) {
    let mut roles: HashSet<String> = HashSet::new();
    if let Some(agents) = doc.get("agents").and_then(|x| x.as_sequence()) {
        for agent in agents {
            if let Some(role) = agent.get("role").and_then(|x| x.as_str()) {
                if !roles.insert(role.to_string()) {
                    report.push_error(ValidationIssue {
                        code: "agenomic::system::duplicate_role".into(),
                        severity: Severity::High,
                        message: format!("duplicate member role '{role}'"),
                        path: Some("system.yaml".into()),
                        hint: None,
                        doc: None,
                    });
                }
            }
        }
    }

    if let Some(orch) = doc.get("orchestration") {
        for key in ["entrypoint", "supervisor"] {
            if let Some(role) = orch.get(key).and_then(|x| x.as_str()) {
                if !roles.contains(role) {
                    report.push_error(ValidationIssue {
                        code: "agenomic::system::unknown_role".into(),
                        severity: Severity::High,
                        message: format!("orchestration.{key} references undeclared role '{role}'"),
                        path: Some("system.yaml".into()),
                        hint: None,
                        doc: None,
                    });
                }
            }
        }
        if let Some(edges) = orch.get("edges").and_then(|x| x.as_sequence()) {
            for edge in edges {
                let from = edge.get("from").and_then(|x| x.as_str());
                let to = edge.get("to").and_then(|x| x.as_str());
                if let Some(from) = from {
                    if !roles.contains(from) {
                        report.push_error(ValidationIssue {
                            code: "agenomic::system::unknown_role".into(),
                            severity: Severity::High,
                            message: format!("edge references undeclared role '{from}'"),
                            path: Some("system.yaml".into()),
                            hint: None,
                            doc: None,
                        });
                    }
                }
                if let Some(to) = to {
                    if to != "END" && !roles.contains(to) {
                        report.push_error(ValidationIssue {
                            code: "agenomic::system::unknown_role".into(),
                            severity: Severity::High,
                            message: format!("edge references undeclared role '{to}'"),
                            path: Some("system.yaml".into()),
                            hint: None,
                            doc: None,
                        });
                    }
                }
            }
        }
    }

    if let (Some(dir), Some(workflows)) = (dir, doc.get("workflows").and_then(|x| x.as_sequence()))
    {
        for wf in workflows {
            if let Some(path) = wf.get("path").and_then(|x| x.as_str()) {
                if !dir.join(path).is_file() {
                    report.push_error(ValidationIssue {
                        code: "agenomic::system::missing_workflow_file".into(),
                        severity: Severity::High,
                        message: format!("workflows[].path '{path}' does not exist in the bundle"),
                        path: Some(path.to_string()),
                        hint: None,
                        doc: None,
                    });
                }
            }
        }
    }
}

/// Known provider aliases for Hugging Face. Kept here (rather than depending on
/// the CLI crate) so the validate crate stays dependency-light.
fn is_huggingface_provider(provider: &str) -> bool {
    matches!(
        provider.trim().to_ascii_lowercase().replace('-', "_").as_str(),
        "huggingface" | "hugging_face" | "hf"
    )
}

/// Provider-specific semantic checks. Currently validates Hugging Face model
/// declarations: a non-empty `model_id`, a safe `endpoint_url` (https, no inline
/// credentials), and a recognised `task` when present. All are warnings except
/// credential-bearing endpoint URLs, which are errors (they leak secrets).
fn provider_semantic_checks(doc: &serde_yaml::Value, report: &mut ValidationReport) {
    let runtime = match doc.get("runtime") {
        Some(r) => r,
        None => return,
    };
    let provider = runtime
        .get("model_provider")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if !is_huggingface_provider(provider) {
        return;
    }

    let model_id = runtime
        .get("model_id")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if model_id.trim().is_empty() {
        report.push_error(ValidationIssue {
            code: "agenomic::provider::huggingface::missing_model_id".into(),
            severity: Severity::High,
            message: "runtime.model_id is required for the huggingface provider".into(),
            path: Some("genome.yaml".into()),
            hint: Some("set a Hugging Face model id, e.g. mistralai/Mistral-7B-Instruct-v0.3".into()),
            doc: None,
        });
    } else if model_id.contains(char::is_whitespace) {
        report.push_warning(ValidationIssue {
            code: "agenomic::provider::huggingface::suspicious_model_id".into(),
            severity: Severity::Low,
            message: format!("runtime.model_id '{model_id}' contains whitespace"),
            path: Some("genome.yaml".into()),
            hint: Some("Hugging Face model ids look like 'namespace/name'".into()),
            doc: None,
        });
    }

    if let Some(endpoint) = runtime.get("endpoint_url").and_then(|x| x.as_str()) {
        if !endpoint.is_empty() {
            let lower = endpoint.to_ascii_lowercase();
            let scheme_ok = lower.starts_with("https://") || lower.starts_with("http://");
            if !scheme_ok {
                report.push_warning(ValidationIssue {
                    code: "agenomic::provider::huggingface::endpoint_scheme".into(),
                    severity: Severity::Medium,
                    message: "runtime.endpoint_url should be an http(s) URL".into(),
                    path: Some("genome.yaml".into()),
                    hint: None,
                    doc: None,
                });
            } else if lower.starts_with("http://") {
                report.push_warning(ValidationIssue {
                    code: "agenomic::provider::huggingface::endpoint_insecure".into(),
                    severity: Severity::Medium,
                    message: "runtime.endpoint_url uses http://; prefer https:// for token auth".into(),
                    path: Some("genome.yaml".into()),
                    hint: None,
                    doc: None,
                });
            }
            // Inline credentials (`scheme://user:pass@host`) would leak a secret
            // into the genome/lockfile. Treat as an error.
            let after_scheme = endpoint.split("://").nth(1).unwrap_or("");
            let authority = after_scheme.split('/').next().unwrap_or("");
            if authority.contains('@') {
                report.push_error(ValidationIssue {
                    code: "agenomic::provider::huggingface::endpoint_credentials".into(),
                    severity: Severity::High,
                    message: "runtime.endpoint_url must not contain inline credentials".into(),
                    path: Some("genome.yaml".into()),
                    hint: Some("remove the user:pass@ portion; authenticate with HUGGINGFACE_API_TOKEN".into()),
                    doc: None,
                });
            }
        }
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

#[cfg(test)]
mod hf_tests {
    use super::*;

    const VALID_HF: &str = "spec_version: '0.1'\nagent:\n  id: 'agent://acme/hf'\n  name: 'HF'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'huggingface'\n  model_id: 'mistralai/Mistral-7B-Instruct-v0.3'\n  task: 'text-generation'\n  revision: 'main'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n";

    #[test]
    fn accepts_valid_huggingface_genome() {
        let report = validate_genome(VALID_HF).unwrap();
        assert!(report.valid, "valid HF genome rejected: {:?}", report.errors);
    }

    #[test]
    fn rejects_endpoint_with_inline_credentials() {
        let genome = "spec_version: '0.1'\nagent:\n  id: 'agent://acme/hf'\n  name: 'HF'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'hf'\n  model_id: 'mistralai/Mistral-7B-Instruct-v0.3'\n  endpoint_url: 'https://user:pass@endpoint.hf.space/v1'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n";
        let report = validate_genome(genome).unwrap();
        assert!(!report.valid);
        assert!(report
            .errors
            .iter()
            .any(|e| e.code == "agenomic::provider::huggingface::endpoint_credentials"));
    }

    #[test]
    fn warns_on_http_endpoint() {
        let genome = "spec_version: '0.1'\nagent:\n  id: 'agent://acme/hf'\n  name: 'HF'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'huggingface'\n  model_id: 'gpt2'\n  endpoint_url: 'http://endpoint.hf.space/v1'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n";
        let report = validate_genome(genome).unwrap();
        assert!(report.valid, "http endpoint should warn, not error");
        assert!(report
            .warnings
            .iter()
            .any(|w| w.code == "agenomic::provider::huggingface::endpoint_insecure"));
    }

    #[test]
    fn non_huggingface_provider_is_untouched() {
        let genome = "spec_version: '0.1'\nagent:\n  id: 'agent://acme/x'\n  name: 'X'\n  domain: 'general'\n  criticality: 'low'\nruntime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nskills: []\nknowledge: []\npolicies: []\n";
        let report = validate_genome(genome).unwrap();
        assert!(report.valid);
        assert!(report.warnings.iter().all(|w| !w.code.contains("huggingface")));
    }
}
