//! Thin command handlers. Each handler parses args, calls the relevant crate
//! function, renders, and returns an [`ExitCode`].

use std::path::Path;

use agentlock_attestation::{
    create_attestation, verify_attestation, AttestationOptions, SigningMode,
};
use agentlock_bundle::{
    build_bundle, extract_bundle, inspect_bundle, BuildBundleOptions, ExtractOptions,
};
use agentlock_core::{io_at, CliError, CliResult, ExitCode, Severity, ValidationLevel};
use agentlock_diff::{diff_bundles, DiffOptions};
use agentlock_replay_local::{run_local_replay, ReplayOptions};
use agentlock_validate::{validate_archive, validate_bundle};

use crate::cli::*;
use crate::render::render;

pub fn cmd_init(args: &InitArgs) -> CliResult<ExitCode> {
    let dir = &args.path;
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| io_at(dir, e))?;
    }
    let agent_id = args
        .agent_id
        .clone()
        .unwrap_or_else(|| "agent://example/new".to_string());

    let genome = format!(
        "spec_version: '0.1'\n\
         agent:\n  id: '{agent_id}'\n  name: '{}'\n  domain: 'general'\n  criticality: 'low'\n\
         runtime:\n  model_provider: 'openai'\n  model_id: 'gpt-4o'\n\
         tools: []\n\
         skills: []\n\
         knowledge: []\n\
         policies: []\n",
        args.name
    );
    write_if_missing(&dir.join("genome.yaml"), genome.as_bytes())?;

    let lock = format!(
        "spec_version: '0.1'\n\
         agent_id: '{agent_id}'\n\
         model:\n  provider: 'openai'\n  model_id: 'gpt-4o'\n\
         tools: []\n\
         knowledge: []\n"
    );
    write_if_missing(&dir.join("agent.lock.yaml"), lock.as_bytes())?;

    let contract = "spec_version: '0.1'\ncontract:\n  id: 'contract://example/v1'\n  rules: []\n";
    write_if_missing(&dir.join("behavior.contract.yaml"), contract.as_bytes())?;

    std::fs::create_dir_all(dir.join("prompts")).map_err(|e| io_at(&dir.join("prompts"), e))?;
    write_if_missing(
        &dir.join("prompts/system.md"),
        b"You are a helpful agent.\n",
    )?;

    println!("initialized bundle at {}", dir.display());
    Ok(ExitCode::Success)
}

fn write_if_missing(path: &Path, content: &[u8]) -> CliResult<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }
    agentlock_fs::write_atomic(path, content)
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
            .any(|i| i.code.starts_with("agentlock::security::"))
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
        agentlock_hash::compute_manifest(&args.target)?
    } else {
        let pairs = agentlock_bundle::read_archive_to_pairs(&args.target)?;
        agentlock_hash::compute_manifest_from_pairs(pairs.into_iter())?
    };
    let bytes = hex::decode(&manifest.root_hash).unwrap_or_default();
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        println!("{}", agentlock_hash::format_hash(&arr, args.prefix));
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
        agentlock_fs::write_atomic(out, &bytes)?;
    }
    render(&report, format, no_color)?;
    if !report.contract_passed {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

pub fn cmd_attest(args: &AttestArgs, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    if let Some(path) = &args.generate_key {
        let id = agentlock_atep::generate_signing_key(path)?;
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
    use agentlock_atep::*;
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
            let manifest: agentlock_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
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
            let manifest: agentlock_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
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
            let manifest: agentlock_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
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
            let manifest: agentlock_atep::AtepManifest = serde_json::from_slice(&manifest_bytes)
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
                Some(p) => agentlock_fs::write_atomic(p, &bytes)?,
                None => println!("{}", String::from_utf8_lossy(&bytes)),
            }
            Ok(ExitCode::Success)
        }
    }
}

fn parse_stream(s: &str) -> CliResult<agentlock_atep::StreamId> {
    use agentlock_atep::StreamId::*;
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
    let cfg = agentlock_config::load(None)?;
    let report = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::Internal(format!("runtime: {e}")))?
        .block_on(agentlock_diagnostics::run_diagnostics(&cfg))?;
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
    let bin_name = "agentlock".to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(ExitCode::Success)
}

pub fn cmd_trace(args: &TraceCommand) -> CliResult<ExitCode> {
    match &args.command {
        TraceSub::Validate { path } => {
            let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            let traces = agentlock_contract::parse_traces_jsonl(&text)?;
            println!("{} traces parsed", traces.len());
            Ok(ExitCode::Success)
        }
        TraceSub::Summarize { path } => {
            let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
            let traces = agentlock_contract::parse_traces_jsonl(&text)?;
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
                agentlock_hash::compute_manifest(target)?
            } else {
                let pairs = agentlock_bundle::read_archive_to_pairs(target)?;
                agentlock_hash::compute_manifest_from_pairs(pairs.into_iter())?
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
            agentlock_config::save_profile(
                "default",
                &agentlock_config::ProfileFileEntry {
                    mode: agentlock_config::ProfileMode::Cloud,
                    endpoint: Some(endpoint.clone()),
                    org: None,
                },
            )?;
            agentlock_config::save_credentials(
                "default",
                &SecretString::new(api_key.clone().into_boxed_str()),
            )?;
            println!("logged in to {endpoint}");
            Ok(ExitCode::Success)
        }
        CloudSub::Whoami => {
            let cfg = agentlock_config::load(None)?;
            let endpoint = cfg.profile.endpoint.clone().ok_or_else(|| {
                CliError::Internal(
                    "no endpoint configured; run `agentlock cloud login` first".into(),
                )
            })?;
            let api_key = cfg.profile.api_key.clone().ok_or(CliError::AuthFailed)?;
            let client = agentlock_cloud_client::CloudClient::new(endpoint, api_key);
            let resp = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?
                .block_on(client.whoami())?;
            let s = serde_json::to_string_pretty(&resp)
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
            Ok(ExitCode::Success)
        }
        CloudSub::Logout => {
            agentlock_config::delete_credentials("default")?;
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
            use agentlock_cloud_client::{CreateAgentRequest, CreateBundleRequest};
            use base64::{engine::general_purpose::STANDARD, Engine};

            let client = cloud_client_from_profile()?;

            // Cloud's `create_bundle` validates the supplied hash against
            // the canonical Merkle root recomputed from the archive; we must
            // pass the same `logical_bundle_hash` that `agentlock hash`
            // produces, NOT a raw blake3 of the tar.zst bytes.
            let summary = agentlock_bundle::inspect_bundle(bundle)?;
            // Cloud expects the algorithm prefix (e.g. `blake3:<hex>`) on the
            // wire even though `inspect_bundle` returns the bare hex.
            let logical_hash = if summary.logical_bundle_hash.contains(':') {
                summary.logical_bundle_hash.clone()
            } else {
                format!("blake3:{}", summary.logical_bundle_hash)
            };
            let bytes = std::fs::read(bundle).map_err(|e| agentlock_core::io_at(bundle, e))?;
            let archive_hash = blake3::hash(&bytes).to_hex().to_string();
            let archive_b64 = STANDARD.encode(&bytes);

            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?;

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
                "owner": "agentlock-cli",
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
            use agentlock_cloud_client::CreateReleaseRequest;
            let client = cloud_client_from_profile()?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?;
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
            use agentlock_cloud_client::CreateReplayJobRequest;
            let client = cloud_client_from_profile()?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?;
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
            use agentlock_cloud_client::CreateAttestationRequest;
            let client = cloud_client_from_profile()?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| CliError::Internal(format!("{e}")))?;
            let att = rt.block_on(client.create_attestation(CreateAttestationRequest {
                release_id: release_id.clone(),
                replay_job_id: replay_job_id.clone(),
            }))?;
            // replay_job_id is now Option (cloud allows release-only
            // attestations without a replay), so render the missing case.
            let replay_label = att
                .replay_job_id
                .as_deref()
                .unwrap_or("(none)");
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
fn cloud_client_from_profile() -> CliResult<agentlock_cloud_client::CloudClient> {
    let cfg = agentlock_config::load(None)?;
    let endpoint = cfg.profile.endpoint.clone().ok_or_else(|| {
        CliError::Internal("no endpoint configured; run `agentlock cloud login` first".into())
    })?;
    let api_key = cfg.profile.api_key.clone().ok_or(CliError::AuthFailed)?;
    Ok(agentlock_cloud_client::CloudClient::new(endpoint, api_key))
}

// Severity is referenced via SeverityArg::to_severity; silence unused-import
fn _unused_severity(_s: Severity) {}
