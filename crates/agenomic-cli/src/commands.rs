//! Thin command handlers. Each handler parses args, calls the relevant crate
//! function, renders, and returns an [`ExitCode`].

use std::path::Path;

use agenomic_attestation::{
    create_attestation, verify_attestation, AttestationOptions, SigningMode,
};
use agenomic_bundle::{
    build_bundle, compile_runtime_artifacts, extract_bundle, inspect_bundle, BuildBundleOptions,
    CompileRuntimeOptions, ExtractOptions,
};
use agenomic_core::{io_at, CliError, CliResult, ExitCode, Severity, ValidationLevel};
use agenomic_diff::{diff_bundles, DiffOptions};
use agenomic_replay_local::{run_local_replay, ReplayOptions};
use agenomic_validate::{validate_archive, validate_bundle, validate_manifest_file};

use crate::cli::*;
use crate::render::render;

pub fn cmd_init(args: &InitArgs, format: OutputFormat) -> CliResult<ExitCode> {
    let dir = &args.path;
    if !args.dry_run && !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| io_at(dir, e))?;
    }

    let has_manifest = manifest_present(dir);
    // We only run manifest-based detection when a recognised manifest is present
    // and the user didn't opt out; otherwise we behave like the legacy scaffolder.
    let detected = has_manifest && !args.no_detect;
    let genome_path = dir.join("genome.yaml");

    // §2.1: a real project that already has a genome refuses (exit 2) and points
    // the user at `agm update`, unless --force is set.
    if !args.dry_run && detected && genome_path.exists() && !args.force {
        return Err(CliError::InitWouldOverwrite {
            path: genome_path.display().to_string(),
        });
    }

    let project = agenomic_config::load_project_walking_up(dir)?;
    // `--from` overrides config; config `[init].sources` is the fallback.
    let only: Option<Vec<agenomic_detect::Source>> = if !args.from.is_empty() {
        Some(args.from.iter().map(|s| s.to_source()).collect())
    } else {
        config_sources(&project)
    };
    let opts = agenomic_detect::DetectOptions {
        only,
        no_detect: !detected,
        name_override: args.name.clone(),
        agent_id_override: args.agent_id.clone(),
    };

    let mut genome = agenomic_detect::run(dir, &opts)?;
    apply_init_config(&mut genome, &project);
    let bundle = agenomic_detect::emit(&genome);

    // Orchestration pass (spec 0.2, RFC 0009): workflow topology, multi-agent
    // system, env vars — only when manifest-based detection is active.
    let orch = if detected {
        agenomic_detect::detect_orchestration(dir)?
    } else {
        agenomic_detect::DetectedOrchestration::default()
    };

    if args.dry_run {
        render_init(&genome, &bundle, format, true, dir)?;
        render_orchestration(&orch, &[], format, true);
        return Ok(ExitCode::Success);
    }

    agenomic_detect::write_bundle(dir, &bundle, args.force)?;
    let orch_written =
        agenomic_detect::write_orchestration(dir, &orch, &genome.agent_id, args.force)?;
    if detected {
        let provenance = agenomic_detect::Provenance::from_detection(
            &genome,
            agenomic_detect::resolved_detected_at(),
        );
        agenomic_detect::write_provenance(dir, &provenance)?;
    }
    render_init(&genome, &bundle, format, false, dir)?;
    render_orchestration(&orch, &orch_written, format, false);
    if args.agent {
        run_agent_enrichment(dir, format);
    }
    Ok(ExitCode::Success)
}

/// `agm enrich` — fill the semantic fields detection cannot know, using the
/// agent's own declared model provider.
pub fn cmd_enrich(args: &EnrichArgs, format: OutputFormat) -> CliResult<ExitCode> {
    let dir = &args.path;
    let input = crate::enrich::gather(dir)?;
    let genome = agenomic_detect::parse_genome(&input.genome_text)?;
    let provider = args
        .provider
        .clone()
        .unwrap_or_else(|| genome.model_provider.clone());
    let model = args
        .model
        .clone()
        .unwrap_or_else(|| genome.model_id.clone());

    let prompt = crate::enrich::build_prompt(&input);
    let reply = crate::enrich::call_llm(&provider, &model, &prompt)?;
    let enrichment = crate::enrich::parse_enrichment(&reply)?;

    if args.dry_run {
        match format {
            OutputFormat::Human => {
                println!("proposed enrichment (dry run, nothing written):");
                println!("{}", reply.trim());
            }
            _ => println!("{}", reply.trim()),
        }
        return Ok(ExitCode::Success);
    }

    let changed = crate::enrich::apply(dir, &enrichment)?;
    match format {
        OutputFormat::Human => {
            if changed.is_empty() {
                println!("nothing to enrich — every field is already set");
            } else {
                for rel in &changed {
                    println!("enriched {rel}");
                }
            }
        }
        _ => println!(
            "{}",
            serde_json::json!({ "provider": provider, "model": model, "changed": changed })
        ),
    }
    Ok(ExitCode::Success)
}

/// Best-effort enrichment after `init`/`update --agent`: the bundle is
/// already written, so a missing API key degrades to a hint, not a failure.
fn run_agent_enrichment(dir: &Path, format: OutputFormat) {
    let args = EnrichArgs {
        path: dir.to_path_buf(),
        provider: None,
        model: None,
        dry_run: false,
    };
    if let Err(e) = cmd_enrich(&args, format) {
        eprintln!("warning: enrichment skipped: {e}");
        eprintln!(
            "hint: set the provider API key and run `agm enrich {}`",
            dir.display()
        );
    }
}

/// Human-format report of the orchestration pass (RFC 0009). Other formats
/// stay byte-compatible with their pre-0.2 output.
fn render_orchestration(
    orch: &agenomic_detect::DetectedOrchestration,
    written: &[String],
    format: OutputFormat,
    dry_run: bool,
) {
    if !matches!(format, OutputFormat::Human) || orch.is_empty() {
        return;
    }
    for wf in &orch.workflows {
        let rel = format!("workflows/{}.yaml", wf.slug);
        if dry_run {
            println!(
                "would write {rel} ({} engine, from {})",
                wf.engine, wf.origin
            );
        } else if written.contains(&rel) {
            println!("wrote {rel} (from {})", wf.origin);
        }
    }
    if let Some(sys) = &orch.system {
        if dry_run {
            println!(
                "would write system.yaml ({} member agents, engine {})",
                sys.roles.len(),
                sys.engine
            );
        } else if written.iter().any(|w| w == "system.yaml") {
            println!(
                "wrote system.yaml ({} member agents, engine {})",
                sys.roles.len(),
                sys.engine
            );
        }
    }
    if !orch.env.required.is_empty() || !orch.env.optional.is_empty() {
        println!(
            "detected env vars — required: [{}] optional: [{}]",
            orch.env.required.join(", "),
            orch.env.optional.join(", ")
        );
    }
}

/// True if `dir` contains a recognised project manifest that triggers detection.
fn manifest_present(dir: &Path) -> bool {
    [
        "pyproject.toml",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "agenomic.yaml",
    ]
    .iter()
    .any(|f| dir.join(f).exists())
}

/// Render init output per `--format`: human prints a status line (or the genome
/// under `--dry-run`), yaml prints the genome, json/json-pretty print the §2.3
/// precedence-chain log.
fn render_init(
    genome: &agenomic_detect::DetectedGenome,
    bundle: &agenomic_detect::EmittedBundle,
    format: OutputFormat,
    dry_run: bool,
    dir: &Path,
) -> CliResult<()> {
    match format {
        OutputFormat::Human => {
            if dry_run {
                print!("{}", bundle.genome);
            } else {
                println!("initialized bundle at {}", dir.display());
            }
        }
        OutputFormat::Yaml => print!("{}", bundle.genome),
        OutputFormat::Json => println!("{}", precedence_json(genome, false)?),
        OutputFormat::JsonPretty => println!("{}", precedence_json(genome, true)?),
    }
    Ok(())
}

/// The detection precedence chain as a JSON array of `{field, value, source, evidence}`.
fn precedence_json(genome: &agenomic_detect::DetectedGenome, pretty: bool) -> CliResult<String> {
    let records: Vec<serde_json::Value> = genome
        .sorted_evidence()
        .iter()
        .map(|e| {
            serde_json::json!({
                "field": e.field,
                "value": e.value,
                "source": e.source.label(),
                "evidence": e.evidence,
            })
        })
        .collect();
    let value = serde_json::Value::Array(records);
    let out = if pretty {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    };
    out.map_err(|e| CliError::Internal(format!("{e}")))
}

/// Detection sources from `[init].sources` in `agenomic.toml`, if configured.
fn config_sources(
    project: &Option<agenomic_config::ProjectConfig>,
) -> Option<Vec<agenomic_detect::Source>> {
    let labels = project.as_ref()?.init.as_ref()?.sources.as_ref()?;
    let sources: Vec<agenomic_detect::Source> = labels
        .iter()
        .filter_map(|l| agenomic_detect::Source::from_label(l))
        .collect();
    (!sources.is_empty()).then_some(sources)
}

/// Apply `[init].default_domain`/`default_criticality` unless detection (e.g.
/// `agenomic.yaml`) already set the field.
fn apply_init_config(
    genome: &mut agenomic_detect::DetectedGenome,
    project: &Option<agenomic_config::ProjectConfig>,
) {
    let Some(init) = project.as_ref().and_then(|p| p.init.as_ref()) else {
        return;
    };
    if let Some(domain) = &init.default_domain {
        if !genome.evidence.iter().any(|e| e.field == "agent.domain") {
            genome.domain = domain.clone();
        }
    }
    if let Some(crit) = &init.default_criticality {
        if !genome
            .evidence
            .iter()
            .any(|e| e.field == "agent.criticality")
        {
            genome.criticality = crit.clone();
        }
    }
}

/// Default branches on which `agm update` refuses to auto-commit (§3.6),
/// when `[update].protected_branches` is not configured.
const DEFAULT_PROTECTED_BRANCHES: [&str; 3] = ["main", "master", "release/*"];

/// Paths whose working-tree changes do NOT trigger the §3.6 dirty refusal: the
/// bundle files themselves plus the detection-source manifests a user edits to
/// drive an update (so the §3.3 "edit pyproject, then update" flow works).
const UPDATE_DIRTY_IGNORE: &[&str] = &[
    "genome.yaml",
    "agent.lock.yaml",
    "behavior.contract.yaml",
    "prompts/system.md",
    "system.yaml",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "agenomic.yaml",
    "README.md",
    "Dockerfile",
];

/// True when a dirty path belongs to the bundle itself (and so never blocks
/// `agm update`): an exact [`UPDATE_DIRTY_IGNORE`] entry or an orchestration
/// manifest under `workflows/`.
fn update_dirty_ignored(path: &str) -> bool {
    UPDATE_DIRTY_IGNORE.contains(&path) || path.starts_with("workflows/")
}

/// What an update run did, for rendering.
enum UpdateOutcome {
    DryRun,
    NoChange,
    Written { bundle_hash: String },
    Committed { oid: String, bundle_hash: String },
}

pub fn cmd_update(args: &UpdateArgs, format: OutputFormat) -> CliResult<ExitCode> {
    let dir = &args.path;
    let genome_path = dir.join("genome.yaml");
    if !genome_path.exists() {
        return Err(CliError::UpdateRefused {
            reason: format!("no genome.yaml at {}; run `agm init` first", dir.display()),
        });
    }

    // Detect → parse current → merge.
    let only: Option<Vec<agenomic_detect::Source>> = if args.from.is_empty() {
        None
    } else {
        Some(args.from.iter().map(|s| s.to_source()).collect())
    };
    let opts = agenomic_detect::DetectOptions {
        only,
        no_detect: false,
        name_override: None,
        agent_id_override: None,
    };
    let detected = agenomic_detect::run(dir, &opts)?;
    let current_text = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let current = agenomic_detect::parse_genome(&current_text)?;
    let prior = agenomic_detect::load_provenance(dir)?;
    let result = agenomic_detect::merge(&current, &detected, prior.as_ref(), args.prune);

    // Orchestration pass (spec 0.2, RFC 0009). Files are only created when
    // missing, so hand edits to generated manifests always survive.
    let orch = agenomic_detect::detect_orchestration(dir)?;

    if args.dry_run {
        render_update(&result, format, &UpdateOutcome::DryRun)?;
        render_orchestration(&orch, &[], format, true);
        return Ok(ExitCode::Success);
    }
    if result.is_noop() {
        let orch_written =
            agenomic_detect::write_orchestration(dir, &orch, &result.merged.agent_id, false)?;
        if orch_written.is_empty() {
            render_update(&result, format, &UpdateOutcome::NoChange)?;
            return Ok(ExitCode::ValidationFailed); // exit 1 (§3.7)
        }
        render_update(&result, format, &UpdateOutcome::NoChange)?;
        render_orchestration(&orch, &orch_written, format, false);
        return Ok(ExitCode::Success);
    }

    // Resolve `[update]` config (with §3/§4 defaults).
    let project = agenomic_config::load_project_walking_up(dir)?;
    let update_cfg = project
        .as_ref()
        .and_then(|p| p.update.clone())
        .unwrap_or_default();
    let cfg_auto_commit = update_cfg.auto_commit.unwrap_or(true);
    let protected: Vec<String> = update_cfg.protected_branches.clone().unwrap_or_else(|| {
        DEFAULT_PROTECTED_BRANCHES
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });
    let commit_template = update_cfg
        .commit_template
        .clone()
        .unwrap_or_else(|| "chore(agenomic): update bundle ({step} {hash})".to_string());

    // Decide on committing and run the §3.6 refusal checks BEFORE writing.
    let state = agenomic_detect::repo_state(dir)?;
    let should_commit = !args.no_commit && state.is_repo && (args.commit || cfg_auto_commit);
    if should_commit {
        if args.sign || update_cfg.sign.unwrap_or(false) {
            return Err(CliError::UpdateRefused {
                reason: "signed commits are not supported by the offline commit path; use --no-commit then `git commit -S`".into(),
            });
        }
        if !args.allow_dirty {
            if state.detached {
                return Err(CliError::UpdateRefused {
                    reason: "HEAD is detached".into(),
                });
            }
            if let Some(branch) = state.branch.as_deref() {
                if branch_protected(branch, &protected) {
                    return Err(CliError::UpdateRefused {
                        reason: format!("branch '{branch}' is protected; run on a feature branch"),
                    });
                }
            }
            let dirty_outside: Vec<&str> = state
                .changed
                .iter()
                .map(String::as_str)
                .filter(|p| !update_dirty_ignored(p))
                .collect();
            if !dirty_outside.is_empty() {
                return Err(CliError::UpdateRefused {
                    reason: format!(
                        "working tree has unrelated changes: {}",
                        dirty_outside.join(", ")
                    ),
                });
            }
        }
    }

    // Write the merged bundle (overwrite the four files).
    let bundle = agenomic_detect::emit(&result.merged);
    agenomic_detect::write_bundle(dir, &bundle, true)?;
    let orch_written =
        agenomic_detect::write_orchestration(dir, &orch, &result.merged.agent_id, false)?;

    // Logical bundle hash (matches `agenomic hash`); the sidecar is excluded.
    let manifest = agenomic_hash::compute_manifest(dir)?;
    let full_hash = manifest.root_hash;
    let short_hash: String = full_hash.chars().take(12).collect();

    // Provenance: record this detection + frozen fields + the last_update summary.
    let mut provenance = agenomic_detect::Provenance::from_detection(
        &result.merged,
        agenomic_detect::resolved_detected_at(),
    );
    provenance.frozen = result.frozen.clone();
    provenance.last_update = Some(agenomic_detect::LastUpdate {
        step: args.step.as_deref().map(sanitize_step),
        bundle_hash: full_hash.clone(),
        changes: result.changes.iter().map(|c| c.render()).collect(),
    });
    agenomic_detect::write_provenance(dir, &provenance)?;

    let outcome = if should_commit {
        let step = args.step.as_deref().map(sanitize_step).unwrap_or_default();
        let message = args.message.clone().unwrap_or_else(|| {
            build_commit_message(
                &commit_template,
                &step,
                &short_hash,
                &full_hash,
                &result.changes,
            )
        });
        // Commit the four bundle files plus the provenance sidecar (which the
        // next merge needs); the sidecar is still excluded from the logical hash.
        let mut commit_files: Vec<&str> = agenomic_detect::BUNDLE_FILES.to_vec();
        commit_files.push(".agenomic/provenance.yaml");
        // Orchestration manifests created by this run are part of the bundle.
        commit_files.extend(orch_written.iter().map(String::as_str));
        let oid = agenomic_detect::commit_bundle(dir, &commit_files, &message)?;
        UpdateOutcome::Committed {
            oid,
            bundle_hash: full_hash,
        }
    } else {
        UpdateOutcome::Written {
            bundle_hash: full_hash,
        }
    };
    render_update(&result, format, &outcome)?;
    render_orchestration(&orch, &orch_written, format, false);
    if args.agent {
        run_agent_enrichment(dir, format);
    }
    Ok(ExitCode::Success)
}

fn branch_protected(branch: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix("/*") {
        Some(prefix) => branch.starts_with(&format!("{prefix}/")),
        None => branch == p.as_str(),
    })
}

fn sanitize_step(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn build_commit_message(
    template: &str,
    step: &str,
    short_hash: &str,
    full_hash: &str,
    changes: &[agenomic_detect::Change],
) -> String {
    let subject = if step.is_empty() {
        template
            .replace("{step} ", "")
            .replace("{step}", "")
            .replace("{hash}", short_hash)
    } else {
        template
            .replace("{step}", step)
            .replace("{hash}", short_hash)
    };
    let mut msg = subject;
    msg.push_str("\n\nDetected changes:\n");
    for c in changes {
        msg.push_str(&format!("- {}\n", c.render()));
    }
    msg.push_str(&format!("\nBundle hash: b3:{full_hash}\n"));
    msg
}

fn render_update(
    result: &agenomic_detect::MergeResult,
    format: OutputFormat,
    outcome: &UpdateOutcome,
) -> CliResult<()> {
    match format {
        OutputFormat::Human => {
            for c in &result.changes {
                println!("✓ {}", c.render());
            }
            match outcome {
                UpdateOutcome::DryRun => println!("(dry run — nothing written)"),
                UpdateOutcome::NoChange => println!("no changes; bundle is up to date"),
                UpdateOutcome::Written { .. } => println!("wrote bundle (not committed)"),
                UpdateOutcome::Committed { oid, .. } => {
                    println!("committed {}", &oid[..oid.len().min(12)]);
                }
            }
        }
        OutputFormat::Yaml => {
            print!("{}", agenomic_detect::emit(&result.merged).genome);
        }
        OutputFormat::Json | OutputFormat::JsonPretty => {
            let (committed, bundle_hash, commit) = match outcome {
                UpdateOutcome::Committed { oid, bundle_hash } => {
                    (true, Some(bundle_hash.clone()), Some(oid.clone()))
                }
                UpdateOutcome::Written { bundle_hash } => (false, Some(bundle_hash.clone()), None),
                UpdateOutcome::DryRun | UpdateOutcome::NoChange => (false, None, None),
            };
            let value = serde_json::json!({
                "changed": result.changes.iter().map(|c| c.render()).collect::<Vec<_>>(),
                "frozen": result.frozen,
                "committed": committed,
                "bundle_hash": bundle_hash,
                "commit": commit,
            });
            let out = if matches!(format, OutputFormat::JsonPretty) {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            };
            println!("{}", out.map_err(|e| CliError::Internal(format!("{e}")))?);
        }
    }
    Ok(())
}

pub fn cmd_validate(
    args: &ValidateArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let level = match args.level {
        LevelArg::Basic => ValidationLevel::Basic,
        LevelArg::Strict => ValidationLevel::Strict,
        LevelArg::Ci => ValidationLevel::Ci,
    };
    let is_yaml_file = args.target.is_file()
        && args
            .target
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("yaml") || x.eq_ignore_ascii_case("yml"));
    let report = if args.target.is_dir() {
        validate_bundle(&args.target, level)?
    } else if is_yaml_file {
        // Standalone manifest (genome, workflow, or system) outside a bundle.
        validate_manifest_file(&args.target)?
    } else {
        validate_archive(&args.target, level)?
    };
    render(&report, format, no_color)?;
    if !report.valid {
        // Distinguish security violation from generic validation failure.
        if report
            .errors
            .iter()
            .any(|i| i.code.starts_with("agenomic::security::"))
        {
            return Ok(ExitCode::SecurityViolation);
        }
        return Ok(ExitCode::ValidationFailed);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_build(args: &BuildArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let opts = BuildBundleOptions {
        input_dir: args.input.clone(),
        output_file: args.output.clone(),
        compression_level: args.compression_level,
        strict: args.strict,
        include_attestations: false,
        ignore_file: None,
        allow_symlinks: args.allow_symlinks,
    };
    if args.strict {
        let r = validate_bundle(&args.input, ValidationLevel::Strict)?;
        if !r.valid {
            render(&r, format, no_color)?;
            return Ok(ExitCode::ValidationFailed);
        }
    }
    let result = build_bundle(opts)?;
    let summary = serde_json::json!({
        "output_file": result.output_file,
        "logical_bundle_hash": result.logical_bundle_hash,
        "archive_hash": result.archive_hash,
        "size_bytes": result.size_bytes,
        "file_count": result.manifest.file_count,
    });
    if matches!(format, OutputFormat::Human) {
        println!(
            "wrote {} ({} bytes, {} files)",
            result.output_file.display(),
            result.size_bytes,
            result.manifest.file_count
        );
        println!("logical_bundle_hash: {}", result.logical_bundle_hash);
        println!("archive_hash:        {}", result.archive_hash);
    } else {
        let s = serde_json::to_string_pretty(&summary)
            .map_err(|e| CliError::Internal(format!("{e}")))?;
        println!("{s}");
    }
    Ok(ExitCode::Success)
}

pub fn cmd_inspect(
    args: &InspectArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    if args.target.starts_with("agent://") {
        return os_inspect(args, format, no_color);
    }
    if args.local || args.bundle_path.is_some() {
        return Err(CliError::OsUriInvalid(
            "--local and --bundle-path require an agent:// reference; \
             pass a path target without them for bundle inspection"
                .into(),
        ));
    }
    let target = Path::new(&args.target);
    let s = inspect_bundle(target)?;
    render(&s, format, no_color)?;
    Ok(ExitCode::Success)
}

fn os_inspect(args: &InspectArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    use agenomic_os::{AgentReference, ExecutionContract};

    let reference: AgentReference = args
        .target
        .parse::<AgentReference>()
        .map_err(CliError::from)?;
    let resolved = resolve_reference(&reference, args.local, args.bundle_path.as_deref())?;

    let genome_path = resolved.bundle_path.join("genome.yaml");
    let yaml = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let contract = ExecutionContract::from_genome_yaml(&yaml).map_err(CliError::from)?;

    let body = serde_json::json!({
        "reference": reference.canonical(),
        "bundle_path": resolved.bundle_path,
        "signed": resolved.signature.is_some(),
        "execution": contract,
    });
    print_value(&body, format)?;
    let _ = no_color;
    Ok(ExitCode::Success)
}

fn print_value(value: &serde_json::Value, format: OutputFormat) -> CliResult<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match format {
        OutputFormat::Human | OutputFormat::JsonPretty => {
            let s = serde_json::to_string_pretty(value)
                .map_err(|e| CliError::Internal(format!("json: {e}")))?;
            out.write_all(s.as_bytes())
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|e| CliError::Internal(format!("write: {e}")))?;
        }
        OutputFormat::Json => {
            let s = serde_json::to_string(value)
                .map_err(|e| CliError::Internal(format!("json: {e}")))?;
            out.write_all(s.as_bytes())
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|e| CliError::Internal(format!("write: {e}")))?;
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(value)
                .map_err(|e| CliError::Internal(format!("yaml: {e}")))?;
            out.write_all(s.as_bytes())
                .map_err(|e| CliError::Internal(format!("write: {e}")))?;
        }
    }
    Ok(())
}

fn resolve_reference(
    reference: &agenomic_os::AgentReference,
    local: bool,
    bundle_path: Option<&Path>,
) -> CliResult<agenomic_os::ResolvedAgent> {
    use agenomic_os::{AgentResolver, CacheLocation, LocalResolver, ResolvedAgent};

    if let Some(p) = bundle_path {
        let genome = p.join("genome.yaml");
        if !genome.is_file() {
            return Err(CliError::OsResolverFailed(format!(
                "{} is not a bundle directory (no genome.yaml)",
                p.display()
            )));
        }
        return Ok(ResolvedAgent {
            reference: reference.clone(),
            bundle_path: p.to_path_buf(),
            signature: None,
        });
    }
    let cache = if local {
        let cwd = std::env::current_dir().map_err(|e| CliError::Internal(e.to_string()))?;
        CacheLocation::project_local(cwd)
    } else {
        CacheLocation::Global
    };
    let resolver = LocalResolver::new(cache);
    let rt = tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
    rt.block_on(resolver.resolve(reference))
        .map_err(CliError::from)
}

pub fn cmd_run(args: &RunArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    use agenomic_os::{launch_for_kind, AgentReference, ExecutionContract, LaunchPlan, Policy};

    let reference: AgentReference = args
        .reference
        .parse::<AgentReference>()
        .map_err(CliError::from)?;

    if reference.qualifier.is_none() && args.bundle_path.is_none() && !args.local {
        // Unqualified remote-style references resolve to nothing in the
        // local-only MVP; surface that explicitly rather than blame the cache.
        return Err(CliError::OsBundleUnsigned(reference.canonical()));
    }

    let resolved = resolve_reference(&reference, args.local, args.bundle_path.as_deref())?;

    let genome_path = resolved.bundle_path.join("genome.yaml");
    let yaml = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let contract = ExecutionContract::from_genome_yaml(&yaml).map_err(CliError::from)?;

    // Fail-closed OPA/Rego gate: if the bundle ships `policies/*.rego`, the
    // launch context must be explicitly allowed before we spawn anything. A
    // bundle without rego policies keeps the previous (advisory) behaviour.
    let policy_bundle =
        agenomic_policy::PolicyBundle::load(&resolved.bundle_path).map_err(CliError::from)?;
    if !policy_bundle.is_empty() {
        let agent_id = reference.canonical();
        let criticality = genome_criticality(&yaml);
        let input = launch_context_from_contract(&agent_id, &criticality, &contract);
        let decision = policy_bundle.evaluate(&input).map_err(CliError::from)?;
        if !decision.allowed {
            let reasons = if decision.denies.is_empty() {
                "policy did not allow this launch".to_string()
            } else {
                decision.denies.join("; ")
            };
            return Err(CliError::OsPolicyViolation(format!(
                "rego policy gate denied launch ({}): {reasons}",
                decision.policies.join(", ")
            )));
        }
    }

    let env_overrides = parse_env_overrides(&args.env)?;
    let policy = Policy::from_contract(&contract)
        .with_network_overrides(args.allow_network.iter().cloned())
        .with_env_overrides(env_overrides);

    let plan = LaunchPlan {
        reference: reference.clone(),
        bundle_path: resolved.bundle_path.clone(),
        contract,
        policy,
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
    let handle = rt.block_on(launch_for_kind(plan)).map_err(CliError::from)?;

    if !handle.stdout.is_empty() {
        print!("{}", handle.stdout);
    }
    if !handle.stderr.is_empty() {
        eprint!("{}", handle.stderr);
    }
    print_value(
        &serde_json::json!({
            "exit_code": handle.exit_code,
            "events": handle.trace.events.len(),
        }),
        format,
    )?;
    let _ = no_color;
    if handle.exit_code == 0 {
        Ok(ExitCode::Success)
    } else {
        Err(CliError::OsLauncherFailed(format!(
            "agent exited with code {}",
            handle.exit_code
        )))
    }
}

fn parse_env_overrides(
    entries: &[String],
) -> CliResult<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    for entry in entries {
        let (k, v) = entry.split_once('=').ok_or_else(|| {
            CliError::OsPolicyViolation(format!("--env value {entry:?} must be KEY=VALUE"))
        })?;
        if k.is_empty() {
            return Err(CliError::OsPolicyViolation(
                "--env KEY must not be empty".into(),
            ));
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

pub fn cmd_port(args: &PortArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let proposal = agenomic_os::port::propose(&args.path).map_err(CliError::from)?;

    let body = serde_json::json!({
        "source_path": proposal.source_path,
        "runtime_kind": proposal.runtime_kind.map(|k| k.label()),
        "framework": proposal.framework,
        "proposed_execution_yaml": proposal.proposed_execution_yaml,
        "gaps": proposal
            .gaps
            .iter()
            .map(|g| serde_json::json!({
                "field": g.field,
                "reason": g.reason,
                "severity": match g.severity {
                    agenomic_os::GapSeverity::Required => "required",
                    agenomic_os::GapSeverity::Recommended => "recommended",
                    agenomic_os::GapSeverity::Informational => "informational",
                },
            }))
            .collect::<Vec<_>>(),
    });
    print_value(&body, format)?;
    let _ = no_color;
    if proposal
        .gaps
        .iter()
        .any(|g| matches!(g.severity, agenomic_os::GapSeverity::Required))
    {
        return Ok(ExitCode::ValidationFailed);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_compile(
    args: &CompileArgs,
    format: OutputFormat,
    _no_color: bool,
) -> CliResult<ExitCode> {
    use agenomic_compile::CompileTarget;

    // Default to all targets when neither --target nor --all is given.
    let targets: Vec<CompileTarget> = if args.all || args.target.is_empty() {
        CompileTarget::ALL.to_vec()
    } else {
        let mut ts: Vec<CompileTarget> = args.target.iter().map(|t| t.to_target()).collect();
        ts.sort();
        ts.dedup();
        ts
    };

    let artifacts =
        agenomic_compile::compile_bundle(&args.bundle, &targets).map_err(CliError::from)?;

    let mut summaries = Vec::new();
    for artifact in &artifacts {
        let dest_root = match &args.output {
            Some(out) => out.join(artifact.target.dir_name()),
            None => args.bundle.join("runtime").join(artifact.target.dir_name()),
        };
        if !args.dry_run {
            artifact.emit_to_dir(&dest_root).map_err(CliError::from)?;
        }
        summaries.push(serde_json::json!({
            "target": artifact.target.label(),
            "output_dir": dest_root,
            "files": artifact.files.keys().collect::<Vec<_>>(),
            "written": !args.dry_run,
        }));
    }

    let body = serde_json::json!({
        "bundle": args.bundle,
        "targets": targets.iter().map(|t| t.label()).collect::<Vec<_>>(),
        "dry_run": args.dry_run,
        "artifacts": summaries,
    });

    if matches!(format, OutputFormat::Human) {
        for s in &summaries {
            let target = s["target"].as_str().unwrap_or("?");
            let dir = s["output_dir"].as_str().unwrap_or_default();
            let n = s["files"].as_array().map(|a| a.len()).unwrap_or(0);
            if args.dry_run {
                println!("would compile {target}: {n} files → {dir}");
            } else {
                println!("compiled {target}: {n} files → {dir}");
            }
        }
    } else {
        print_value(&body, format)?;
    }
    Ok(ExitCode::Success)
}

pub fn cmd_policy(
    args: &PolicyCommand,
    format: OutputFormat,
    _no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        PolicySub::Eval { bundle, input } => {
            let policy_bundle =
                agenomic_policy::PolicyBundle::load(bundle).map_err(CliError::from)?;

            let input_doc = match input {
                Some(path) => {
                    let raw = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
                    serde_json::from_str(&raw).map_err(|e| {
                        CliError::Schema(format!("policy input {}: {e}", path.display()))
                    })?
                }
                None => bundle_launch_context(bundle)?,
            };

            let decision = policy_bundle.evaluate(&input_doc).map_err(CliError::from)?;
            let body = serde_json::json!({
                "bundle": bundle,
                "policies": decision.policies,
                "allowed": decision.allowed,
                "allow_rule": decision.allow_rule,
                "denies": decision.denies,
                "input": input_doc,
            });
            print_value(&body, format)?;
            if decision.allowed {
                Ok(ExitCode::Success)
            } else {
                Ok(ExitCode::OsPolicyViolation)
            }
        }
    }
}

/// Derive a default policy input document from a bundle's `execution:` block:
/// the fields a `policies/*.rego` is most likely to gate on. Bundles without an
/// execution block yield a minimal `{agent_id}` context.
fn bundle_launch_context(bundle: &Path) -> CliResult<serde_json::Value> {
    use agenomic_os::ExecutionContract;

    let genome_path = bundle.join("genome.yaml");
    let yaml = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
    let agent_id = serde_yaml::from_str::<serde_yaml::Value>(&yaml)
        .ok()
        .and_then(|v| {
            v.get("agent")
                .and_then(|a| a.get("id"))
                .and_then(|i| i.as_str().map(String::from))
        })
        .unwrap_or_default();
    let criticality = genome_criticality(&yaml);

    match ExecutionContract::from_genome_yaml(&yaml) {
        Ok(contract) => Ok(launch_context_from_contract(
            &agent_id,
            &criticality,
            &contract,
        )),
        // No execution block: still provide what we know.
        Err(_) => Ok(serde_json::json!({
            "agent_id": agent_id,
            "criticality": criticality,
        })),
    }
}

/// Extract `agent.criticality` from a genome YAML string (empty when absent).
fn genome_criticality(yaml: &str) -> String {
    serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .ok()
        .and_then(|v| {
            v.get("agent")
                .and_then(|a| a.get("criticality"))
                .and_then(|c| c.as_str().map(String::from))
        })
        .unwrap_or_default()
}

/// Shared shape of the JSON `input` document fed to Rego, built from the
/// execution contract. Kept stable so policies can rely on the field names.
fn launch_context_from_contract(
    agent_id: &str,
    criticality: &str,
    contract: &agenomic_os::ExecutionContract,
) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent_id,
        "criticality": criticality,
        "runtime_kind": contract.runtime.kind.label(),
        "working_directory": contract.working_directory,
        "env_required": contract.env.required,
        "env_optional": contract.env.optional,
        "network_allow": contract.permissions.network.allow,
        "network_allow_count": contract.permissions.network.allow.len(),
        "fs_read": contract.permissions.filesystem.read,
        "fs_write": contract.permissions.filesystem.write,
    })
}

pub fn cmd_governance(
    args: &GovernanceCommand,
    format: OutputFormat,
    _no_color: bool,
) -> CliResult<ExitCode> {
    use agenomic_governance::{
        audit, cluster_descriptor, critique_descriptor, io::read_traces, proposal_descriptor,
        AdversarialReviewer, DiagnosticAgent, HypothesisAgent, Verdict,
    };

    match &args.command {
        GovernanceSub::Cluster { traces, emit } => {
            let loaded = read_traces(traces).map_err(CliError::from)?;
            let clusters = DiagnosticAgent::new().cluster(&loaded);
            let descriptors: Vec<_> = clusters.iter().map(cluster_descriptor).collect();
            let atep = emit_governance_events(emit, &descriptors)?;
            print_value(
                &with_atep(serde_json::json!({ "clusters": clusters }), atep),
                format,
            )?;
            Ok(ExitCode::Success)
        }
        GovernanceSub::Hypothesize { clusters, emit } => {
            let raw = read_governance_input(clusters)?;
            // Accept either a `{clusters: [...]}` envelope or a bare `[...]`.
            let parsed: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| CliError::Schema(format!("clusters JSON: {e}")))?;
            let inner = parsed.get("clusters").cloned().unwrap_or(parsed);
            let clusters: Vec<agenomic_governance::Cluster> = serde_json::from_value(inner)
                .map_err(|e| CliError::Schema(format!("clusters JSON: {e}")))?;
            let proposals = HypothesisAgent::new().hypothesize_many(&clusters);
            let descriptors: Vec<_> = proposals.iter().map(proposal_descriptor).collect();
            let atep = emit_governance_events(emit, &descriptors)?;
            print_value(
                &with_atep(serde_json::json!({ "proposals": proposals }), atep),
                format,
            )?;
            Ok(ExitCode::Success)
        }
        GovernanceSub::Critique { proposal, emit } => {
            let raw = read_governance_input(proposal)?;
            let p: agenomic_governance::Proposal = serde_json::from_str(&raw)
                .map_err(|e| CliError::Schema(format!("proposal JSON: {e}")))?;
            let critique = AdversarialReviewer::new().critique(&p);
            let blocked = matches!(critique.verdict, Verdict::Block);
            let atep = emit_governance_events(emit, &[critique_descriptor(&critique)])?;
            print_value(
                &with_atep(serde_json::json!({ "critique": critique }), atep),
                format,
            )?;
            if blocked {
                Ok(ExitCode::OsPolicyViolation)
            } else {
                Ok(ExitCode::Success)
            }
        }
        GovernanceSub::Audit {
            traces,
            fail_on_block,
            emit,
        } => {
            let loaded = read_traces(traces).map_err(CliError::from)?;
            let report = audit(&loaded);
            let blocked = report.has_blocking_findings();
            let descriptors = agenomic_governance::audit_descriptors(&report);
            let atep = emit_governance_events(emit, &descriptors)?;
            print_value(
                &with_atep(
                    serde_json::json!({
                        "clusters": report.clusters,
                        "proposals": report.proposals,
                        "critiques": report.critiques,
                        "blocked": blocked,
                    }),
                    atep,
                ),
                format,
            )?;
            if *fail_on_block && blocked {
                Ok(ExitCode::OsPolicyViolation)
            } else {
                Ok(ExitCode::Success)
            }
        }
    }
}

/// Merge an optional ATEP-emission summary into a governance result body
/// under the `atep` key (omitted when no emission happened).
fn with_atep(mut body: serde_json::Value, atep: Option<serde_json::Value>) -> serde_json::Value {
    if let (Some(obj), Some(summary)) = (body.as_object_mut(), atep) {
        obj.insert("atep".into(), summary);
    }
    body
}

/// Seal `descriptors` onto the ATEP `governance` stream of the store named by
/// `emit`, chaining each event onto the previous one (parents = prior causal
/// hash) and continuing the stream's `stream_seq`. Returns `None` when no
/// store was requested, or a JSON summary when events were appended.
///
/// This is the bridge that finally gives the (previously empty) `governance`
/// stream a signed, hash-linked audit trail: every diagnostic / hypothesis /
/// adversarial result becomes a sealed event.
fn emit_governance_events(
    emit: &AtepEmitArgs,
    descriptors: &[agenomic_governance::GovernanceEventDescriptor],
) -> CliResult<Option<serde_json::Value>> {
    use agenomic_atep::{
        load_signing_key, short_key_id, AtepEvent, AtepManifest, AtepStore, EventHeader,
        EventPayload, Hlc, StreamId,
    };

    let (store_dir, key_path) = match (&emit.atep, &emit.signing_key) {
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            return Err(CliError::Internal(
                "--atep and --signing-key must be provided together".into(),
            ))
        }
        (Some(d), Some(k)) => (d, k),
    };

    // The store dictates the agent_id; events must carry the same one.
    let manifest_path = store_dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
    let manifest: AtepManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| CliError::Internal(format!("atep manifest: {e}")))?;
    let mut store = AtepStore::open_or_init(store_dir, &manifest.agent_id)?;
    let sk = load_signing_key(key_path)?;
    let key_id = short_key_id(&sk.verifying_key());

    // Chain onto the existing governance head so the trail is tamper-evident.
    let head = store.stream_head(StreamId::Governance)?;
    let seq_start = head.as_ref().map(|(s, _)| s + 1).unwrap_or(0);
    let mut parent = head.map(|(_, h)| h);
    let now = chrono::Utc::now().timestamp_millis() as u64;

    let mut events = Vec::with_capacity(descriptors.len());
    for (seq, (i, d)) in (seq_start..).zip(descriptors.iter().enumerate()) {
        let header = EventHeader {
            schema_version: 1,
            event_id: ulid::Ulid::new().to_bytes(),
            agent_id: manifest.agent_id.clone(),
            stream: StreamId::Governance,
            stream_seq: seq,
            // Logical counter = batch index keeps intra-batch order stable even
            // within one millisecond.
            clock: Hlc::new(now, i as u32, 1),
            parents: parent.into_iter().collect(),
            event_type: d.event_type.clone(),
            payload_schema_uri: d.payload_schema_uri(),
        };
        let payload = EventPayload(json_to_cbor(d.payload.clone()));
        let event = AtepEvent::seal(header, payload, &sk, key_id.clone())?;
        parent = Some(event.causal_hash);
        events.push(event);
    }
    store.append_batch(StreamId::Governance, &events)?;

    Ok(Some(serde_json::json!({
        "store": store_dir,
        "agent_id": manifest.agent_id,
        "stream": "governance",
        "events_appended": events.len(),
        "stream_seq_start": seq_start,
        "signer_key_id": key_id,
        "store_merkle_root": hex::encode(store.store_merkle_root()),
    })))
}

/// Read a JSON file path, or stdin when path == "-". Used by the governance
/// sub-commands that take a single JSON document on the command line.
fn read_governance_input(path: &Path) -> CliResult<String> {
    use std::io::Read;
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| CliError::Internal(format!("read stdin: {e}")))?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| io_at(path, e))
    }
}

pub fn cmd_hash(args: &HashArgs, _format: OutputFormat, _no_color: bool) -> CliResult<ExitCode> {
    let manifest = if args.target.is_dir() {
        agenomic_hash::compute_manifest(&args.target)?
    } else {
        let pairs = agenomic_bundle::read_archive_to_pairs(&args.target)?;
        agenomic_hash::compute_manifest_from_pairs(pairs)?
    };
    let bytes = hex::decode(&manifest.root_hash).unwrap_or_default();
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        println!("{}", agenomic_hash::format_hash(&arr, args.prefix));
    } else {
        println!("{}", manifest.root_hash);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_diff(args: &DiffArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let opts = DiffOptions {
        fail_on: args.fail_on.to_severity(),
        include: vec![],
        ignore_prompts_whitespace: args.ignore_prompts_whitespace,
    };
    let report = diff_bundles(&args.baseline, &args.candidate, &opts)?;
    render(&report, format, no_color)?;
    if report.overall_risk >= args.fail_on.to_severity() && !report.changes.is_empty() {
        return Ok(ExitCode::DiffRiskExceeded);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_replay(args: &ReplayArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let opts = ReplayOptions {
        bundle: args.bundle.clone(),
        traces: args.traces.clone(),
        atep_store: args.from_atep.clone(),
        contract: args.contract.clone(),
        runs_per_trace: args.runs_per_trace,
        fail_on: args.fail_on.to_severity(),
    };
    let report = run_local_replay(opts)?;
    if let Some(out) = &args.output {
        let bytes =
            serde_json::to_vec_pretty(&report).map_err(|e| CliError::Internal(format!("{e}")))?;
        agenomic_fs::write_atomic(out, &bytes)?;
    }
    render(&report, format, no_color)?;
    if !report.contract_passed {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_attest(args: &AttestArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    if let Some(path) = &args.generate_key {
        let id = agenomic_atep::generate_signing_key(path)?;
        println!("generated key {id} at {}", path.display());
        return Ok(ExitCode::Success);
    }
    let sign_with = args.sign_with.as_ref().map(|p| SigningMode::LocalEd25519 {
        key_path: p.clone(),
    });
    let opts = AttestationOptions {
        bundle: args.bundle.clone(),
        replay_report: args.replay_report.clone(),
        atep_store: args.atep.clone(),
        atep_root_hash: None,
        sign_with,
        output: args.output.clone(),
        agent_id_override: None,
    };
    let att = create_attestation(opts)?;
    render(&att, format, no_color)?;
    Ok(ExitCode::Success)
}

pub fn cmd_verify(args: &VerifyArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    let result = verify_attestation(&args.attestation, args.atep.as_deref())?;
    render(&result, format, no_color)?;
    if !result.valid {
        return Ok(ExitCode::AttestationVerificationFailed);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_atep(args: &AtepCommand) -> CliResult<ExitCode> {
    use agenomic_atep::*;
    match &args.command {
        AtepSub::Init {
            path,
            agent_id,
            signing_key,
        } => {
            let _ = AtepStore::open_or_init(path, agent_id)?;
            if !signing_key.exists() {
                let id = generate_signing_key(signing_key)?;
                println!("created store at {} with new key {id}", path.display());
            } else {
                println!("opened store at {}", path.display());
            }
            Ok(ExitCode::Success)
        }
        AtepSub::Append {
            path,
            stream,
            event_type,
            payload_file,
            signing_key,
        } => {
            let manifest_path = path.join("manifest.json");
            let manifest_bytes =
                std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            let mut store = AtepStore::open_or_init(path, &manifest.agent_id)?;
            let sk = load_signing_key(signing_key)?;
            let stream = parse_stream(stream)?;
            let payload_value = match payload_file {
                Some(p) => {
                    let text = std::fs::read_to_string(p).map_err(|e| io_at(p, e))?;
                    let json: serde_json::Value = serde_json::from_str(&text)
                        .map_err(|e| CliError::Schema(format!("payload json: {e}")))?;
                    json_to_cbor(json)
                }
                None => ciborium::value::Value::Null,
            };
            let header = EventHeader {
                schema_version: 1,
                event_id: ulid::Ulid::new().to_bytes(),
                agent_id: manifest.agent_id.clone(),
                stream,
                stream_seq: 0,
                clock: Hlc::new(chrono::Utc::now().timestamp_millis() as u64, 0, 1),
                parents: vec![],
                event_type: event_type.clone(),
                payload_schema_uri: format!("atep://schemas/v1/{event_type}"),
            };
            let payload = EventPayload(payload_value);
            let event = AtepEvent::seal(header, payload, &sk, short_key_id(&sk.verifying_key()))?;
            store.append_event(event)?;
            println!(
                "appended event to {} stream {}",
                path.display(),
                stream.label()
            );
            Ok(ExitCode::Success)
        }
        AtepSub::Verify { path, public_key } => {
            let manifest_path = path.join("manifest.json");
            let manifest_bytes =
                std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            let store = AtepStore::open_or_init(path, &manifest.agent_id)?;
            let vk = load_verifying_key(public_key)?;
            let r = store.verify_all(&vk)?;
            let s =
                serde_json::to_string_pretty(&r).map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        AtepSub::Inspect { path } => {
            let manifest_path = path.join("manifest.json");
            let manifest_bytes =
                std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            let s = serde_json::to_string_pretty(&manifest)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        AtepSub::ReplayState { path, at, output } => {
            let manifest_path = path.join("manifest.json");
            let manifest_bytes =
                std::fs::read(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: agenomic_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            let store = AtepStore::open_or_init(path, &manifest.agent_id)?;
            let at_clock = match at {
                Some(s) => {
                    let ts = chrono::DateTime::parse_from_rfc3339(s)
                        .map_err(|e| CliError::Internal(format!("--at parse: {e}")))?;
                    Some(Hlc::new(ts.timestamp_millis() as u64, u32::MAX, u32::MAX))
                }
                None => None,
            };
            let state = store.replay_to_state(at_clock)?;
            let bytes = serde_json::to_vec_pretty(&state)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            match output {
                Some(p) => agenomic_fs::write_atomic(p, &bytes)?,
                None => println!("{}", String::from_utf8_lossy(&bytes)),
            }
            Ok(ExitCode::Success)
        }
    }
}

fn parse_stream(s: &str) -> CliResult<agenomic_atep::StreamId> {
    use agenomic_atep::StreamId::*;
    Ok(match s {
        "identity" => Identity,
        "capability" => Capability,
        "knowledge" => Knowledge,
        "policy" => Policy,
        "runtime" => Runtime,
        "interaction" => Interaction,
        "governance" => Governance,
        other => {
            return Err(CliError::Internal(format!(
                "unknown stream '{other}'; expected one of identity|capability|knowledge|policy|runtime|interaction|governance"
            )))
        }
    })
}

fn json_to_cbor(v: serde_json::Value) -> ciborium::value::Value {
    use ciborium::value::Value as C;
    match v {
        serde_json::Value::Null => C::Null,
        serde_json::Value::Bool(b) => C::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                C::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                C::Integer(u.into())
            } else if let Some(f) = n.as_f64() {
                C::Float(f)
            } else {
                C::Null
            }
        }
        serde_json::Value::String(s) => C::Text(s),
        serde_json::Value::Array(arr) => C::Array(arr.into_iter().map(json_to_cbor).collect()),
        serde_json::Value::Object(map) => C::Map(
            map.into_iter()
                .map(|(k, v)| (C::Text(k), json_to_cbor(v)))
                .collect(),
        ),
    }
}

pub fn cmd_doctor() -> CliResult<ExitCode> {
    let cfg = agenomic_config::load(None)?;
    let report = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::Internal(format!("runtime: {e}")))?
        .block_on(agenomic_diagnostics::run_diagnostics(&cfg))?;
    let s =
        serde_json::to_string_pretty(&report).map_err(|e| CliError::Internal(format!("{e}")))?;
    println!("{s}");
    if !report.overall_ok {
        return Ok(ExitCode::InternalError);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_completions(shell: clap_complete::Shell) -> CliResult<ExitCode> {
    use clap::CommandFactory;
    let mut cmd = crate::cli::Cli::command();
    let bin_name = "agenomic".to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(ExitCode::Success)
}

pub fn cmd_trace(args: &TraceCommand) -> CliResult<ExitCode> {
    match &args.command {
        TraceSub::Validate { path } => {
            let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            let traces = agenomic_contract::parse_traces_jsonl(&text)?;
            println!("{} traces parsed", traces.len());
            Ok(ExitCode::Success)
        }
        TraceSub::Summarize { path } => {
            let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            let traces = agenomic_contract::parse_traces_jsonl(&text)?;
            let agents: std::collections::BTreeSet<_> =
                traces.iter().map(|t| t.agent_id.clone()).collect();
            println!("traces: {}", traces.len());
            println!("agents: {}", agents.len());
            for a in agents {
                println!("  - {a}");
            }
            Ok(ExitCode::Success)
        }
    }
}

pub fn cmd_bundle(
    args: &BundleCommand,
    format: OutputFormat,
    _no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        BundleSub::Extract {
            archive,
            destination,
        } => {
            extract_bundle(ExtractOptions {
                archive: archive.clone(),
                destination: destination.clone(),
            })?;
            println!("extracted to {}", destination.display());
            Ok(ExitCode::Success)
        }
        BundleSub::Manifest { target } => {
            let manifest = if target.is_dir() {
                agenomic_hash::compute_manifest(target)?
            } else {
                let pairs = agenomic_bundle::read_archive_to_pairs(target)?;
                agenomic_hash::compute_manifest_from_pairs(pairs)?
            };
            let s = serde_json::to_string_pretty(&manifest)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        BundleSub::CompileRuntime {
            target,
            adapters,
            output_dir,
        } => {
            let result = compile_runtime_artifacts(CompileRuntimeOptions {
                input_dir: target.clone(),
                output_dir: output_dir.clone(),
                adapters: adapters.iter().map(|a| a.to_runtime_adapter()).collect(),
            })?;
            let summary = serde_json::json!({
                "output_dir": result.output_dir,
                "artifacts": result.artifacts.iter().map(|artifact| serde_json::json!({
                    "adapter": artifact.adapter.label(),
                    "path": artifact.path,
                    "ready": artifact.ready,
                    "warnings": artifact.warnings,
                })).collect::<Vec<_>>(),
            });
            match format {
                OutputFormat::Human => {
                    println!(
                        "compiled runtime artifacts into {}",
                        result.output_dir.display()
                    );
                    for artifact in &result.artifacts {
                        let status = if artifact.ready { "ready" } else { "partial" };
                        println!("  - {} ({status})", artifact.path.display());
                        for warning in &artifact.warnings {
                            println!("      warning: {warning}");
                        }
                    }
                }
                _ => print_value(&summary, format)?,
            }
            Ok(ExitCode::Success)
        }
    }
}

const DEFAULT_BUCKET_SLUG: &str = "default";

pub fn cmd_bucket(args: &BucketCommand, profile: Option<&str>) -> CliResult<ExitCode> {
    match &args.command {
        BucketSub::Use { name } => {
            let cfg = agenomic_config::load(profile)?;
            let profile_name = cfg.profile.name;
            let client = cloud_client_from_profile(profile)?;
            let rt =
                tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
            let bucket = rt.block_on(ensure_bucket(&client, name))?;
            agenomic_config::save_active_bucket(&profile_name, Some(&bucket.slug))?;
            println!(
                "active bucket for profile `{}` is now `{}`",
                profile_name, bucket.slug
            );
            Ok(ExitCode::Success)
        }
    }
}

pub fn cmd_cloud(args: &CloudCommand, profile: Option<&str>) -> CliResult<ExitCode> {
    use secrecy::SecretString;
    match &args.command {
        CloudSub::Login { endpoint, api_key } => {
            let profile_name = resolved_profile_name(profile)?;
            agenomic_config::save_profile(
                &profile_name,
                &agenomic_config::ProfileFileEntry {
                    mode: agenomic_config::ProfileMode::Cloud,
                    endpoint: Some(endpoint.clone()),
                    org: None,
                },
            )?;
            agenomic_config::save_credentials(
                &profile_name,
                &SecretString::new(api_key.clone().into_boxed_str()),
            )?;
            println!("logged in to {endpoint}");
            Ok(ExitCode::Success)
        }
        CloudSub::Whoami => {
            let client = cloud_client_from_profile(profile)?;
            let resp = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?
                .block_on(client.whoami())?;
            let s = serde_json::to_string_pretty(&resp)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        CloudSub::Logout => {
            let profile_name = resolved_profile_name(profile)?;
            agenomic_config::delete_credentials(&profile_name)?;
            println!("logged out");
            Ok(ExitCode::Success)
        }
        CloudSub::PushAgent {
            bundle,
            name,
            description,
            version,
            agent_id,
        } => {
            use agenomic_cloud_client::{CreateAgentRequest, CreateBundleRequest};
            use base64::{engine::general_purpose::STANDARD, Engine};

            let cfg = agenomic_config::load(profile)?;
            let client = cloud_client_from_profile(profile)?;

            // Cloud's `create_bundle` validates the supplied hash against
            // the canonical Merkle root recomputed from the archive; we must
            // pass the same `logical_bundle_hash` that `agenomic hash`
            // produces, NOT a raw blake3 of the tar.zst bytes.
            let summary = agenomic_bundle::inspect_bundle(bundle)?;
            // Cloud expects the algorithm prefix (e.g. `blake3:<hex>`) on the
            // wire even though `inspect_bundle` returns the bare hex.
            let logical_hash = if summary.logical_bundle_hash.contains(':') {
                summary.logical_bundle_hash.clone()
            } else {
                format!("blake3:{}", summary.logical_bundle_hash)
            };
            let bytes = std::fs::read(bundle).map_err(|e| agenomic_core::io_at(bundle, e))?;
            let archive_hash = blake3::hash(&bytes).to_hex().to_string();
            let archive_b64 = STANDARD.encode(&bytes);

            let rt =
                tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
            let target_bucket = rt.block_on(resolve_target_bucket(
                &client,
                cfg.profile.active_bucket_slug.as_deref(),
            ))?;

            // 1) resolve / create the agent
            let agent_id = match agent_id.clone() {
                Some(id) => {
                    // `--agent-id` reuses an *existing* cloud agent. The first
                    // call against that id (move-to-bucket) 404s with an opaque
                    // message when the agent was never pushed; rewrite that one
                    // case into actionable guidance.
                    let agent = rt
                        .block_on(client.move_agent_to_bucket(&id, Some(target_bucket.id.as_str())))
                        .map_err(|e| reuse_agent_not_found_hint(&id, e))?;
                    agent.id
                }
                None => {
                    let agent = rt.block_on(client.create_agent(CreateAgentRequest {
                        name: name.clone(),
                        description: description.clone(),
                    }))?;
                    let agent =
                        rt.block_on(ensure_agent_in_bucket(&client, agent, &target_bucket))?;
                    println!("created agent {} ({})", agent.id, agent.name);
                    agent.id
                }
            };

            // 2) upload the bundle
            let metadata = serde_json::json!({
                "owner": "agenomic-cli",
                "tags": ["pushed-by-cli"],
                "archive_blake3": archive_hash,
            });
            let bundle = rt.block_on(client.create_bundle(CreateBundleRequest {
                agent_id: agent_id.clone(),
                version: version.clone(),
                hash: logical_hash.clone(),
                metadata,
                archive_base64: Some(archive_b64),
            }))?;
            println!(
                "uploaded bundle {} (version={}, size={} bytes, hash={})",
                bundle.id, bundle.version, bundle.size_bytes, bundle.bundle_hash
            );
            Ok(ExitCode::Success)
        }
        CloudSub::PushRelease {
            agent_id,
            bundle_id,
            version,
            notes,
        } => {
            use agenomic_cloud_client::CreateReleaseRequest;
            let client = cloud_client_from_profile(profile)?;
            let rt =
                tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
            let release = rt.block_on(client.create_release(CreateReleaseRequest {
                agent_id: agent_id.clone(),
                bundle_id: bundle_id.clone(),
                version: version.clone(),
                notes: notes.clone(),
            }))?;
            println!(
                "created release {} (version={}, status={})",
                release.id, release.version, release.status
            );
            Ok(ExitCode::Success)
        }
        CloudSub::PushReplay {
            agent_id,
            release_id,
            trace_ids,
            mode,
        } => {
            use agenomic_cloud_client::CreateReplayJobRequest;
            let client = cloud_client_from_profile(profile)?;
            let rt =
                tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
            let job = rt.block_on(client.create_replay_job(CreateReplayJobRequest {
                agent_id: agent_id.clone(),
                release_id: release_id.clone(),
                trace_ids: trace_ids.clone(),
                mode: Some(mode.clone()),
            }))?;
            println!(
                "enqueued replay job {} (status={}, mode={}, traces={})",
                job.id,
                job.status,
                job.mode,
                job.trace_ids.len()
            );
            Ok(ExitCode::Success)
        }
        CloudSub::PushAttestation {
            release_id,
            replay_job_id,
        } => {
            use agenomic_cloud_client::CreateAttestationRequest;
            let client = cloud_client_from_profile(profile)?;
            let rt =
                tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
            let att = rt.block_on(client.create_attestation(CreateAttestationRequest {
                release_id: release_id.clone(),
                replay_job_id: replay_job_id.clone(),
            }))?;
            // replay_job_id is now Option (cloud allows release-only
            // attestations without a replay), so render the missing case.
            let replay_label = att.replay_job_id.as_deref().unwrap_or("(none)");
            println!(
                "created attestation {} (release={}, replay_job={}, created_at={})",
                att.id, att.release_id, replay_label, att.created_at
            );
            Ok(ExitCode::Success)
        }
    }
}

/// Build a `CloudClient` from the active profile, failing with the
/// canonical error if no key is configured. The endpoint falls back to
/// the hosted cloud (`agenomic_config::DEFAULT_ENDPOINT`) so pushes work
/// without ever specifying a URL.
fn cloud_client_from_profile(
    profile: Option<&str>,
) -> CliResult<agenomic_cloud_client::CloudClient> {
    let cfg = agenomic_config::load(profile)?;
    let endpoint = cfg
        .profile
        .endpoint
        .clone()
        .unwrap_or_else(|| agenomic_config::DEFAULT_ENDPOINT.to_string());
    let api_key = cfg.profile.api_key.clone().ok_or(CliError::AuthFailed)?;
    Ok(agenomic_cloud_client::CloudClient::new(endpoint, api_key))
}

fn resolved_profile_name(profile: Option<&str>) -> CliResult<String> {
    Ok(agenomic_config::load(profile)?.profile.name)
}

async fn resolve_target_bucket(
    client: &agenomic_cloud_client::CloudClient,
    active_bucket_slug: Option<&str>,
) -> CliResult<agenomic_cloud_client::BucketRecord> {
    ensure_bucket(client, selected_bucket_slug(active_bucket_slug)).await
}

fn selected_bucket_slug(active_bucket_slug: Option<&str>) -> &str {
    active_bucket_slug.unwrap_or(DEFAULT_BUCKET_SLUG)
}

async fn ensure_bucket(
    client: &agenomic_cloud_client::CloudClient,
    slug: &str,
) -> CliResult<agenomic_cloud_client::BucketRecord> {
    match client.get_bucket_by_slug(slug).await? {
        Some(bucket) => Ok(bucket),
        None => {
            client
                .create_bucket(agenomic_cloud_client::CreateBucketRequest {
                    name: slug.to_string(),
                    slug: Some(slug.to_string()),
                    description: None,
                })
                .await
        }
    }
}

async fn ensure_agent_in_bucket(
    client: &agenomic_cloud_client::CloudClient,
    agent: agenomic_cloud_client::AgentRecord,
    target_bucket: &agenomic_cloud_client::BucketRecord,
) -> CliResult<agenomic_cloud_client::AgentRecord> {
    if !should_move_agent_to_bucket(agent.bucket_id.as_deref(), target_bucket.id.as_str()) {
        return Ok(agent);
    }
    client
        .move_agent_to_bucket(&agent.id, Some(target_bucket.id.as_str()))
        .await
}

fn should_move_agent_to_bucket(current_bucket_id: Option<&str>, target_bucket_id: &str) -> bool {
    current_bucket_id != Some(target_bucket_id)
}

/// `push-agent --agent-id <id>` reuses an *existing* cloud agent. When that id
/// doesn't exist, the first call against it (`move_agent_to_bucket`) comes back
/// as an opaque `HTTP 404`, which reads like a server/bucket fault. Rewrite that
/// one case into guidance that names the real cause; pass every other error
/// (auth, 5xx, transport) through unchanged.
fn reuse_agent_not_found_hint(agent_id: &str, err: CliError) -> CliError {
    if let CliError::Network(msg) = &err {
        if msg.contains("HTTP 404") {
            return CliError::Network(format!(
                "agent id '{agent_id}' was not found in your org. `--agent-id` \
                 reuses an agent that already exists, but this one has never been \
                 pushed. Omit `--agent-id` to create it from `--name`, then pass \
                 `--agent-id` on subsequent pushes."
            ));
        }
    }
    err
}

// Severity is referenced via SeverityArg::to_severity; silence unused-import
fn _unused_severity(_s: Severity) {}

#[cfg(test)]
mod tests {
    use super::{selected_bucket_slug, should_move_agent_to_bucket, DEFAULT_BUCKET_SLUG};

    #[test]
    fn selected_bucket_slug_defaults_to_default() {
        assert_eq!(selected_bucket_slug(None), DEFAULT_BUCKET_SLUG);
    }

    #[test]
    fn selected_bucket_slug_uses_active_bucket() {
        assert_eq!(selected_bucket_slug(Some("bench")), "bench");
    }

    #[test]
    fn unbucketed_agent_is_moved() {
        assert!(should_move_agent_to_bucket(None, "bucket-1"));
    }

    #[test]
    fn agent_already_in_target_bucket_is_not_moved() {
        assert!(!should_move_agent_to_bucket(Some("bucket-1"), "bucket-1"));
    }

    #[test]
    fn reuse_agent_404_becomes_actionable() {
        use agenomic_core::CliError;
        // The opaque error push-agent gets back when `--agent-id` names an
        // agent that was never pushed.
        let err = CliError::Network("move_agent_to_bucket: HTTP 404 Not Found — ".into());
        let mapped = super::reuse_agent_not_found_hint("agent://treansai/dater-agent", err);
        let msg = format!("{mapped}");
        assert!(msg.contains("was not found"), "got: {msg}");
        assert!(msg.contains("Omit `--agent-id`"), "got: {msg}");
        assert!(msg.contains("agent://treansai/dater-agent"), "got: {msg}");
    }

    #[test]
    fn reuse_agent_non_404_passes_through() {
        use agenomic_core::CliError;
        // A 5xx or auth failure is unrelated to a missing agent id and must
        // not be masked by the "not found" guidance.
        let err = CliError::Network("move_agent_to_bucket: HTTP 500 Internal".into());
        let mapped = super::reuse_agent_not_found_hint("a", err);
        assert!(format!("{mapped}").contains("HTTP 500"));
    }
}
