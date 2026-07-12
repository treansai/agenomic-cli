//! `agenomic track` — online tracking of production agents.
//!
//! Offline-first: every subcommand reads and writes a local [`SessionStore`]
//! (default `<cwd>/.agenomic/tracking`). The wire shapes are identical to the
//! cloud's, so a session recorded here can be replayed or uploaded later.

use std::io::Read;
use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult, ExitCode};
use agenomic_track::{
    baseline_from_genome_text, build_report, parse_tracking_config, BaselineKind, BaselineRef,
    DriftBaseline, HarnessInputs, SessionStatus, SessionStore, TrackingConfig, TrackingEngine,
    TrackingEvent, TrackingSession,
};

use crate::cli::{LedgerDirs, OutputFormat, SessionStatusArg, TrackCommand, TrackSub};
use crate::render::render;

/// `--ledger` options captured at `track start`.
pub(crate) struct LedgerOpts {
    pub enabled: bool,
    pub store: Option<PathBuf>,
    pub keys: Option<PathBuf>,
}

/// Sidecar (`<session dir>/ledger.json`) binding a session to the ledger.
/// Lives beside the session files, NOT inside the spec'd session/report
/// types — the tracking wire shapes stay untouched.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LedgerBinding {
    pub(crate) enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) store: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) keys: Option<PathBuf>,
}

impl LedgerBinding {
    pub(crate) fn dirs(&self) -> LedgerDirs {
        LedgerDirs {
            store: self.store.clone(),
            keys: self.keys.clone(),
        }
    }
}

pub(crate) fn binding_path(store: &SessionStore, session_id: &str) -> PathBuf {
    store.session_dir(session_id).join("ledger.json")
}

pub(crate) fn load_binding(store: &SessionStore, session_id: &str) -> Option<LedgerBinding> {
    let raw = std::fs::read_to_string(binding_path(store, session_id)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn cmd_track(args: &TrackCommand, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    match &args.command {
        TrackSub::Start {
            bundle,
            release,
            env,
            config,
            agent,
            store,
            ledger,
            ledger_store,
            ledger_keys,
        } => start(
            bundle,
            release,
            env,
            config,
            agent,
            store,
            LedgerOpts {
                enabled: *ledger,
                store: ledger_store.clone(),
                keys: ledger_keys.clone(),
            },
            format,
            no_color,
        ),
        TrackSub::Event {
            session,
            file,
            store,
        } => event(session, file, store, format, no_color),
        TrackSub::Tail {
            session,
            limit,
            store,
        } => tail(session, *limit, store, format),
        TrackSub::Status { session, store } => status(session, store, format, no_color),
        TrackSub::Report {
            session,
            output,
            store,
            include_ledger_proof,
        } => report(
            session,
            output,
            store,
            *include_ledger_proof,
            format,
            no_color,
        ),
        TrackSub::Stop {
            session,
            status,
            store,
        } => stop(session, *status, store, format, no_color),
    }
}

// ---- helpers --------------------------------------------------------------

pub(crate) fn store_for(store: &Option<PathBuf>) -> CliResult<SessionStore> {
    let root = match store {
        Some(p) => p.clone(),
        None => {
            let cwd =
                std::env::current_dir().map_err(|e| CliError::Internal(format!("cwd: {e}")))?;
            SessionStore::default_root(&cwd)
        }
    };
    Ok(SessionStore::new(root))
}

pub(crate) fn read_input(path: &Path) -> CliResult<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::Internal(format!("read stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| io_at(path, e))
    }
}

pub(crate) fn require_session(store: &SessionStore, id: &str) -> CliResult<TrackingSession> {
    if !store.exists(id) {
        return Err(CliError::Schema(format!(
            "unknown tracking session '{id}' (start one with `agenomic track start`)"
        )));
    }
    store.load_session(id)
}

/// Union two drift baselines (genome + lockfile), preferring `a` for scalars.
fn union_baseline(mut a: DriftBaseline, b: DriftBaseline) -> DriftBaseline {
    a.genome_hash = a.genome_hash.or(b.genome_hash);
    a.prompt_hash = a.prompt_hash.or(b.prompt_hash);
    a.model_provider = a.model_provider.or(b.model_provider);
    a.model_id = a.model_id.or(b.model_id);
    a.temperature = a.temperature.or(b.temperature);
    a.allowed_tools.extend(b.allowed_tools);
    for (k, v) in b.tool_permissions {
        a.tool_permissions.entry(k).or_default().extend(v);
    }
    a.policy_ids.extend(b.policy_ids);
    a.memory_schema_version = a.memory_schema_version.or(b.memory_schema_version);
    a.workflow_steps.extend(b.workflow_steps);
    a
}

/// Derive `(baseline, agent_id, genome_hash)` from a bundle directory.
pub(crate) fn load_bundle_baseline(
    bundle: &Path,
) -> CliResult<(DriftBaseline, Option<String>, Option<String>)> {
    let mut baseline = DriftBaseline::default();
    let mut agent_id: Option<String> = None;

    if bundle.is_dir() {
        let genome_path = bundle.join("genome.yaml");
        if genome_path.is_file() {
            let text = std::fs::read_to_string(&genome_path).map_err(|e| io_at(&genome_path, e))?;
            baseline = union_baseline(baseline, baseline_from_genome_text(&text)?);
            if let Ok(v) = serde_yaml::from_str::<serde_json::Value>(&text) {
                agent_id = agent_id.or_else(|| {
                    v.get("agent")
                        .and_then(|a| a.get("id"))
                        .and_then(|s| s.as_str())
                        .map(String::from)
                });
            }
        }
        let lock_path = bundle.join("agent.lock.yaml");
        if lock_path.is_file() {
            let text = std::fs::read_to_string(&lock_path).map_err(|e| io_at(&lock_path, e))?;
            baseline = union_baseline(baseline, baseline_from_genome_text(&text)?);
            if let Ok(v) = serde_yaml::from_str::<serde_json::Value>(&text) {
                agent_id = agent_id
                    .or_else(|| v.get("agent_id").and_then(|s| s.as_str()).map(String::from));
            }
        }
    }

    // Genome hash = bundle logical hash (blake3-merkle-v1).
    let genome_hash = if bundle.is_dir() {
        agenomic_hash::compute_manifest(bundle)
            .ok()
            .map(|m| format!("blake3-merkle-v1:{}", m.root_hash))
    } else {
        None
    };
    if baseline.genome_hash.is_none() {
        baseline.genome_hash = genome_hash.clone();
    }

    Ok((baseline, agent_id, genome_hash))
}

/// Load the optional harness inputs (behavior contract + policies) from the
/// bundle the session was started against.
pub(crate) fn load_harness_inputs(session: &TrackingSession) -> CliResult<HarnessInputs> {
    let mut inputs = HarnessInputs {
        fail_on: session.tracking_config.fail_on,
        ..Default::default()
    };
    let Some(reference) = &session.baseline.reference else {
        return Ok(inputs);
    };
    let bundle = Path::new(reference);
    if !bundle.is_dir() {
        return Ok(inputs);
    }
    let contract_path = bundle.join("behavior.contract.yaml");
    if contract_path.is_file() {
        // Fail closed: a declared but unreadable/invalid behavior contract must
        // not be silently skipped, or a release could report as passing without
        // its safety contract ever being evaluated.
        let text = std::fs::read_to_string(&contract_path).map_err(|e| io_at(&contract_path, e))?;
        inputs.contract = Some(agenomic_contract::parse_contract_yaml(&text)?);
    }
    if bundle.join("policies").is_dir() {
        if let Ok(policy) = agenomic_policy::PolicyBundle::load(bundle) {
            if !policy.is_empty() {
                inputs.policy = Some(policy);
            }
        }
    }
    Ok(inputs)
}

/// Build a full [`TrackingEvent`] from possibly-partial JSON input, filling the
/// auto fields (id, session, timestamp, sequence, agent) the producer omitted.
pub(crate) fn hydrate_event(
    raw: serde_json::Value,
    session: &TrackingSession,
    seq: u64,
) -> CliResult<TrackingEvent> {
    let mut obj = match raw {
        serde_json::Value::Object(m) => m,
        _ => return Err(CliError::Schema("event must be a JSON object".into())),
    };
    if !obj.contains_key("type") {
        return Err(CliError::Schema(
            "event requires a `type` field (e.g. \"tool.call.completed\")".into(),
        ));
    }
    obj.entry("event_id")
        .or_insert_with(|| serde_json::json!(ulid::Ulid::new().to_string()));
    obj.insert(
        "session_id".into(),
        serde_json::json!(session.session_id.clone()),
    );
    obj.entry("timestamp")
        .or_insert_with(|| serde_json::json!(chrono::Utc::now().to_rfc3339()));
    obj.entry("sequence_number")
        .or_insert_with(|| serde_json::json!(seq));
    obj.entry("agent_id")
        .or_insert_with(|| serde_json::json!(session.agent_id.clone()));
    serde_json::from_value(serde_json::Value::Object(obj))
        .map_err(|e| CliError::Schema(format!("invalid tracking event: {e}")))
}

// ---- subcommands ----------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn start(
    bundle: &Path,
    release: &Option<String>,
    env: &str,
    config: &Option<PathBuf>,
    agent: &Option<String>,
    store: &Option<PathBuf>,
    ledger: LedgerOpts,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = start_tracking_session(bundle, release, env, config, agent, &store, &ledger)?;
    render(&session, format, no_color)?;
    Ok(ExitCode::Success)
}

/// Create and persist a tracking session for a bundle. Shared by
/// `agenomic track start`, `agenomic monitor start`, and `agenomic rmp
/// start`; writes the ledger binding + session-started event when
/// `ledger.enabled`.
pub(crate) fn start_tracking_session(
    bundle: &Path,
    release: &Option<String>,
    env: &str,
    config: &Option<PathBuf>,
    agent: &Option<String>,
    store: &SessionStore,
    ledger: &LedgerOpts,
) -> CliResult<TrackingSession> {
    let (baseline, detected_agent, genome_hash) = load_bundle_baseline(bundle)?;
    let agent_id = agent.clone().or(detected_agent).ok_or_else(|| {
        CliError::Schema(
            "could not determine agent id from the bundle; pass --agent agent://org/name".into(),
        )
    })?;

    let tracking_config: TrackingConfig = match config {
        Some(p) => parse_tracking_config(&read_input(p)?)?,
        None => TrackingConfig::default(),
    };

    let mut session = TrackingSession::new(agent_id, env.to_string());
    session.release_id = release.clone();
    session.genome_hash = genome_hash.clone();
    session.tracking_config = tracking_config;
    session.baseline = BaselineRef {
        kind: Some(BaselineKind::Genome),
        reference: Some(bundle.display().to_string()),
        genome_hash,
        ..Default::default()
    };

    store.save_session(&session)?;
    store.save_baseline(&session.session_id, &baseline)?;

    if ledger.enabled {
        let binding = LedgerBinding {
            enabled: true,
            store: ledger.store.clone(),
            keys: ledger.keys.clone(),
        };
        let raw =
            serde_json::to_vec_pretty(&binding).map_err(|e| CliError::Internal(format!("{e}")))?;
        let path = binding_path(store, &session.session_id);
        std::fs::write(&path, raw).map_err(|e| io_at(&path, e))?;

        // Session lifecycle event (idempotent id: one per session).
        let mut draft = agenomic_ledger_local::LedgerEntryDraft::new(
            session.agent_id.clone(),
            session.session_id.clone(),
            "tracking.session.started",
            agenomic_ledger_local::PayloadCommitment::Inline(serde_json::json!({
                "session_id": session.session_id,
                "agent_id": session.agent_id,
                "environment": session.environment,
                "release_id": session.release_id,
                "genome_hash": session.genome_hash,
                "started_at": session.started_at,
            })),
            agenomic_ledger_local::IngestionSource::Tracking,
        );
        draft.event_id = Some(format!("{}-session-started", session.session_id));
        draft.session_id = Some(session.session_id.clone());
        draft.genome_hash = session.genome_hash.clone();
        crate::ledger::append_drafts(&binding.dirs(), vec![draft])?;
    }

    Ok(session)
}

fn event(
    session_id: &str,
    file: &Path,
    store: &Option<PathBuf>,
    format: OutputFormat,
    _no_color: bool,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = require_session(&store, session_id)?;
    if session.status.is_terminal() {
        return Err(CliError::Schema(format!(
            "session '{session_id}' is {} and cannot accept new events",
            session.status.label()
        )));
    }

    let events = store.load_events(session_id)?;
    let baseline = store.load_baseline(session_id)?;
    let seq = events.len() as u64;
    let mut engine = TrackingEngine::resume(session, events, baseline);

    let raw: serde_json::Value = serde_json::from_str(&read_input(file)?)
        .map_err(|e| CliError::Schema(format!("event json: {e}")))?;
    let ev = hydrate_event(raw, &engine.session, seq)?;

    let before = engine.events.len();
    let alerts = engine.ingest(ev);
    let appended = engine.events.len() > before;

    if appended {
        if let Some(stored) = engine.events.last() {
            store.append_events(session_id, std::slice::from_ref(stored))?;
            // Ledger-bound session: every ingested event is appended to the
            // ledger, committed by the tracking chain's own event hash.
            if let Some(binding) = load_binding(&store, session_id) {
                if binding.enabled {
                    let draft = agenomic_ledger_local::convert::from_tracking_event(stored)?;
                    crate::ledger::append_drafts(&binding.dirs(), vec![draft])?;
                }
            }
        }
    }
    store.save_session(&engine.session)?;

    // Output the alerts this event raised.
    match format {
        OutputFormat::Json | OutputFormat::JsonPretty => {
            let value = serde_json::json!({
                "session_id": session_id,
                "ingested": appended,
                "alerts": alerts,
            });
            let s = if matches!(format, OutputFormat::JsonPretty) {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            }
            .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
        }
        _ => {
            if !appended {
                println!("event already ingested (idempotent no-op)");
            } else if alerts.is_empty() {
                println!("event ingested — no alerts");
            } else {
                println!("event ingested — {} alert(s):", alerts.len());
                for a in &alerts {
                    println!("  [{}] {} — {}", a.severity.label(), a.title, a.message);
                }
            }
        }
    }

    if alerts.iter().any(|a| a.blocks_release) {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

fn tail(
    session_id: &str,
    limit: usize,
    store: &Option<PathBuf>,
    format: OutputFormat,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = require_session(&store, session_id)?;
    let events = store.load_events(session_id)?;
    let start = events.len().saturating_sub(limit);
    let tail = &events[start..];

    match format {
        OutputFormat::Json | OutputFormat::JsonPretty => {
            let value = serde_json::json!({
                "session_id": session_id,
                "status": session.status.label(),
                "events": tail,
                "alerts": session.alerts,
            });
            let s = if matches!(format, OutputFormat::JsonPretty) {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            }
            .map_err(|e| CliError::Internal(format!("{e}")))?;
            println!("{s}");
        }
        _ => {
            println!(
                "session {} [{}] — {} event(s), {} alert(s)",
                session_id,
                session.status.label(),
                events.len(),
                session.alerts.len()
            );
            for ev in tail {
                let detail = ev
                    .tool
                    .as_ref()
                    .map(|t| format!(" {}", t.name))
                    .or_else(|| {
                        ev.model
                            .as_ref()
                            .map(|m| format!(" {}/{}", m.provider, m.model))
                    })
                    .or_else(|| ev.workflow_step_id.as_ref().map(|s| format!(" step={s}")))
                    .unwrap_or_default();
                println!(
                    "  #{:<4} {}{}",
                    ev.sequence_number,
                    ev.event_type.as_str(),
                    detail
                );
            }
            if !session.alerts.is_empty() {
                println!("alerts:");
                for a in &session.alerts {
                    println!("  [{}] {} — {}", a.severity.label(), a.title, a.message);
                }
            }
        }
    }
    Ok(ExitCode::Success)
}

fn status(
    session_id: &str,
    store: &Option<PathBuf>,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = require_session(&store, session_id)?;
    render(&session, format, no_color)?;
    Ok(ExitCode::Success)
}

fn report(
    session_id: &str,
    output: &Option<PathBuf>,
    store: &Option<PathBuf>,
    include_ledger_proof: bool,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = require_session(&store, session_id)?;
    let events = store.load_events(session_id)?;
    let baseline = store.load_baseline(session_id)?;
    let inputs = load_harness_inputs(&session)?;

    let engine = TrackingEngine::resume(session, events, baseline);
    let harness = engine.run_harness(&inputs);
    let mut report = build_report(&engine.session, &engine.events, &harness);
    if include_ledger_proof {
        let binding = load_binding(&store, session_id)
            .filter(|b| b.enabled)
            .ok_or_else(|| {
                CliError::Schema(format!(
                    "session '{session_id}' is not ledger-bound; start with \
                     `agenomic track start --ledger`"
                ))
            })?;
        let proof = crate::ledger::build_proof(&binding.dirs(), session_id)?;
        report.ledger_proof =
            Some(serde_json::to_value(&proof).map_err(|e| CliError::Internal(format!("{e}")))?);
        // Recompute so the report hash covers the attached proof.
        report.report_hash = Some(report.compute_hash());
    }

    if let Some(out) = output {
        let bytes =
            serde_json::to_vec_pretty(&report).map_err(|e| CliError::Internal(format!("{e}")))?;
        std::fs::write(out, &bytes).map_err(|e| io_at(out, e))?;
    }
    store.save_report(&report)?;

    render(&report, format, no_color)?;
    if matches!(report.final_status, agenomic_track::FinalStatus::Fail) {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

fn stop(
    session_id: &str,
    status: SessionStatusArg,
    store: &Option<PathBuf>,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = store_for(store)?;
    let session = require_session(&store, session_id)?;
    let events = store.load_events(session_id)?;
    let baseline = store.load_baseline(session_id)?;
    let inputs = load_harness_inputs(&session)?;

    let mut engine = TrackingEngine::resume(session, events, baseline);
    let harness = engine.run_harness(&inputs);
    let new_status = match status {
        SessionStatusArg::Completed => SessionStatus::Completed,
        SessionStatusArg::Cancelled => SessionStatus::Cancelled,
        SessionStatusArg::Failed => SessionStatus::Failed,
    };
    engine.stop(new_status);

    let report = build_report(&engine.session, &engine.events, &harness);
    store.save_session(&engine.session)?;
    store.save_report(&report)?;

    if let Some(binding) = load_binding(&store, session_id) {
        if binding.enabled {
            let mut draft = agenomic_ledger_local::LedgerEntryDraft::new(
                engine.session.agent_id.clone(),
                session_id,
                "tracking.session.completed",
                agenomic_ledger_local::PayloadCommitment::Inline(serde_json::json!({
                    "session_id": session_id,
                    "status": engine.session.status.label(),
                    "event_count": engine.events.len(),
                    "final_status": report.final_status,
                    "report_hash": report.report_hash,
                })),
                agenomic_ledger_local::IngestionSource::Tracking,
            );
            draft.event_id = Some(format!("{session_id}-session-completed"));
            draft.session_id = Some(session_id.to_string());
            crate::ledger::append_drafts(&binding.dirs(), vec![draft])?;
        }
    }

    render(&report, format, no_color)?;
    if matches!(report.final_status, agenomic_track::FinalStatus::Fail) {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}
