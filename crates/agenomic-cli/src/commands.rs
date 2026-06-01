//! Thin command handlers. Each handler parses args, calls the relevant crate
//! function, renders, and returns an [`ExitCode`].

use std::path::Path;

use agenomic_attestation::{
    create_attestation, verify_attestation, AttestationOptions, SigningMode,
};
use agenomic_bundle::{
    build_bundle, extract_bundle, inspect_bundle, BuildBundleOptions, ExtractOptions,
};
use agenomic_core::{io_at, CliError, CliResult, ExitCode, Severity, ValidationLevel};
use agenomic_diff::{diff_bundles, DiffOptions};
use agenomic_replay_local::{run_local_replay, ReplayOptions};
use agenomic_validate::{validate_archive, validate_bundle};

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

    let only: Option<Vec<agenomic_detect::Source>> = if args.from.is_empty() {
        None
    } else {
        Some(args.from.iter().map(|s| s.to_source()).collect())
    };
    let opts = agenomic_detect::DetectOptions {
        only,
        no_detect: !detected,
        name_override: args.name.clone(),
        agent_id_override: args.agent_id.clone(),
    };

    let genome = agenomic_detect::run(dir, &opts)?;
    let bundle = agenomic_detect::emit(&genome);

    if args.dry_run {
        render_init(&genome, &bundle, format, true, dir)?;
        return Ok(ExitCode::Success);
    }

    agenomic_detect::write_bundle(dir, &bundle, args.force)?;
    if detected {
        let provenance = agenomic_detect::Provenance::from_detection(
            &genome,
            agenomic_detect::resolved_detected_at(),
        );
        agenomic_detect::write_provenance(dir, &provenance)?;
    }
    render_init(&genome, &bundle, format, false, dir)?;
    Ok(ExitCode::Success)
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

/// Branches on which `agm update` refuses to auto-commit by default (§3.6).
/// (Phase 8 will make this configurable via `agenomic.toml`.)
const DEFAULT_PROTECTED_BRANCHES: [&str; 3] = ["main", "master", "release/*"];

/// Paths whose working-tree changes do NOT trigger the §3.6 dirty refusal: the
/// bundle files themselves plus the detection-source manifests a user edits to
/// drive an update (so the §3.3 "edit pyproject, then update" flow works).
const UPDATE_DIRTY_IGNORE: &[&str] = &[
    "genome.yaml",
    "agent.lock.yaml",
    "behavior.contract.yaml",
    "prompts/system.md",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "agenomic.yaml",
    "README.md",
    "Dockerfile",
];

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

    if args.dry_run {
        render_update(&result, format, &UpdateOutcome::DryRun)?;
        return Ok(ExitCode::Success);
    }
    if result.is_noop() {
        render_update(&result, format, &UpdateOutcome::NoChange)?;
        return Ok(ExitCode::ValidationFailed); // exit 1 (§3.7)
    }

    // Decide on committing and run the §3.6 refusal checks BEFORE writing.
    let state = agenomic_detect::repo_state(dir)?;
    let should_commit = !args.no_commit && state.is_repo;
    if should_commit {
        if args.sign {
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
                if branch_protected(branch, &DEFAULT_PROTECTED_BRANCHES) {
                    return Err(CliError::UpdateRefused {
                        reason: format!("branch '{branch}' is protected; run on a feature branch"),
                    });
                }
            }
            let dirty_outside: Vec<&str> = state
                .changed
                .iter()
                .map(String::as_str)
                .filter(|p| !UPDATE_DIRTY_IGNORE.contains(p))
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
            build_commit_message(&step, &short_hash, &full_hash, &result.changes)
        });
        // Commit the four bundle files plus the provenance sidecar (which the
        // next merge needs); the sidecar is still excluded from the logical hash.
        let mut commit_files: Vec<&str> = agenomic_detect::BUNDLE_FILES.to_vec();
        commit_files.push(".agenomic/provenance.yaml");
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
    Ok(ExitCode::Success)
}

fn branch_protected(branch: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix("/*") {
        Some(prefix) => branch.starts_with(&format!("{prefix}/")),
        None => branch == *p,
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
    step: &str,
    short_hash: &str,
    full_hash: &str,
    changes: &[agenomic_detect::Change],
) -> String {
    let subject = if step.is_empty() {
        format!("chore(agenomic): update bundle ({short_hash})")
    } else {
        format!("chore(agenomic): update bundle ({step} {short_hash})")
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
    let report = if args.target.is_dir() {
        validate_bundle(&args.target, level)?
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
    let s = inspect_bundle(&args.target)?;
    render(&s, format, no_color)?;
    Ok(ExitCode::Success)
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

pub fn cmd_bundle(args: &BundleCommand) -> CliResult<ExitCode> {
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
    }
}

pub fn cmd_cloud(args: &CloudCommand) -> CliResult<ExitCode> {
    use secrecy::SecretString;
    match &args.command {
        CloudSub::Login { endpoint, api_key } => {
            agenomic_config::save_profile(
                "default",
                &agenomic_config::ProfileFileEntry {
                    mode: agenomic_config::ProfileMode::Cloud,
                    endpoint: Some(endpoint.clone()),
                    org: None,
                },
            )?;
            agenomic_config::save_credentials(
                "default",
                &SecretString::new(api_key.clone().into_boxed_str()),
            )?;
            println!("logged in to {endpoint}");
            Ok(ExitCode::Success)
        }
        CloudSub::Whoami => {
            let cfg = agenomic_config::load(None)?;
            let endpoint = cfg.profile.endpoint.clone().ok_or_else(|| {
                CliError::Internal(
                    "no endpoint configured; run `agenomic cloud login` first".into(),
                )
            })?;
            let api_key = cfg.profile.api_key.clone().ok_or(CliError::AuthFailed)?;
            let client = agenomic_cloud_client::CloudClient::new(endpoint, api_key);
            let resp = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?
                .block_on(client.whoami())?;
            let s = serde_json::to_string_pretty(&resp)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        CloudSub::Logout => {
            agenomic_config::delete_credentials("default")?;
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

            let client = cloud_client_from_profile()?;

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

            // 1) resolve / create the agent
            let agent_id = match agent_id.clone() {
                Some(id) => id,
                None => {
                    let agent = rt.block_on(client.create_agent(CreateAgentRequest {
                        name: name.clone(),
                        description: description.clone(),
                    }))?;
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
            let client = cloud_client_from_profile()?;
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
            let client = cloud_client_from_profile()?;
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
            let client = cloud_client_from_profile()?;
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
/// canonical error if no endpoint or key is configured.
fn cloud_client_from_profile() -> CliResult<agenomic_cloud_client::CloudClient> {
    let cfg = agenomic_config::load(None)?;
    let endpoint = cfg.profile.endpoint.clone().ok_or_else(|| {
        CliError::Internal("no endpoint configured; run `agenomic cloud login` first".into())
    })?;
    let api_key = cfg.profile.api_key.clone().ok_or(CliError::AuthFailed)?;
    Ok(agenomic_cloud_client::CloudClient::new(endpoint, api_key))
}

// Severity is referenced via SeverityArg::to_severity; silence unused-import
fn _unused_severity(_s: Severity) {}
