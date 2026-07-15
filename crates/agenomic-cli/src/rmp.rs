//! `agenomic rmp` / `review` / `monitor` / `protect` — the Review · Monitor
//! · Protect loop.
//!
//! Offline-first: state lives in a local [`RmpStore`] (default
//! `<cwd>/.agenomic/rmp`), the live path reuses the tracking
//! [`SessionStore`] (default `<cwd>/.agenomic/tracking`), and the optional
//! cryptographic ledger reuses `agenomic ledger`'s layout and pipeline.

use std::io::Write;
use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult, ExitCode};
use agenomic_report::{RenderOptions, Renderable};
use agenomic_rmp::{
    build_rmp_report, export_evidence, proposals_from_findings, EvidenceExportOptions, Finding,
    MonitorConfig, MonitorEngine, MonitorSession, ProtectEngine, ProtectOutcome,
    ReleaseRecommendation, ReviewEngine, ReviewInputs, ReviewOutcome, RiskMatrix, RmpMode,
    RmpSession, RmpStore, ScenarioEnrichmentProposal, TestScenario,
};
use agenomic_track::{SessionStatus, SessionStore, TrackingEngine};

use crate::cli::{
    MonitorCliCommand, MonitorSub, OutputFormat, ProposalAction, ProtectCliCommand, ProtectSub,
    ReviewCliCommand, ReviewScenariosSub, ReviewSub, RmpCommand, RmpLedgerArgs, RmpStoreArgs,
    RmpSub, SessionStatusArg,
};
use crate::render::render;
use crate::track::{
    hydrate_event, load_binding, load_bundle_baseline, load_harness_inputs, read_input,
    require_session, start_tracking_session, LedgerOpts,
};

/// Scenario-corpus pseudo-session id inside a bundle's RMP store.
const CORPUS: &str = "corpus";

/// Sidecar (`<rmp session dir>/binding.json`) tying an RMP session to its
/// bundle, its tracking session, and the ledger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RmpBinding {
    bundle: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tracking_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tracking_store: Option<PathBuf>,
    #[serde(default)]
    ledger: Option<LedgerBindingMirror>,
}

/// Serializable mirror of the track-side ledger binding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LedgerBindingMirror {
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keys: Option<PathBuf>,
}

impl LedgerBindingMirror {
    fn dirs(&self) -> crate::cli::LedgerDirs {
        crate::cli::LedgerDirs {
            store: self.store.clone(),
            keys: self.keys.clone(),
        }
    }
}

// ---- store helpers ---------------------------------------------------------

fn rmp_store(stores: &RmpStoreArgs) -> CliResult<RmpStore> {
    let root = match &stores.store {
        Some(p) => p.clone(),
        None => {
            let cwd =
                std::env::current_dir().map_err(|e| CliError::Internal(format!("cwd: {e}")))?;
            RmpStore::default_root(&cwd)
        }
    };
    Ok(RmpStore::new(root))
}

/// Bundle-scoped RMP store (corpus + risk matrix live inside the bundle).
fn bundle_store(bundle: &Path, stores: &RmpStoreArgs) -> RmpStore {
    match &stores.store {
        Some(p) => RmpStore::new(p.clone()),
        None => RmpStore::new(RmpStore::default_root(bundle)),
    }
}

fn tracking_store(stores: &RmpStoreArgs) -> CliResult<SessionStore> {
    crate::track::store_for(&stores.tracking_store)
}

fn require_rmp_session(store: &RmpStore, id: &str) -> CliResult<RmpSession> {
    if !store.exists(id) {
        return Err(CliError::Schema(format!(
            "unknown RMP session '{id}' (start one with `agenomic rmp start`)"
        )));
    }
    store.load_session(id)
}

fn save_binding(store: &RmpStore, session_id: &str, binding: &RmpBinding) -> CliResult<()> {
    let dir = store.session_dir(session_id);
    std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
    let path = dir.join("binding.json");
    let raw = serde_json::to_vec_pretty(binding).map_err(|e| CliError::Internal(format!("{e}")))?;
    std::fs::write(&path, raw).map_err(|e| io_at(&path, e))?;
    Ok(())
}

fn load_rmp_binding(store: &RmpStore, session_id: &str) -> Option<RmpBinding> {
    let raw = std::fs::read_to_string(store.session_dir(session_id).join("binding.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> CliResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| CliError::Internal(format!("{e}")))?;
    std::fs::write(path, &bytes).map_err(|e| io_at(path, e))?;
    Ok(())
}

fn io(e: std::io::Error) -> CliError {
    CliError::Internal(format!("write output: {e}"))
}

fn write_json<T: serde::Serialize>(w: &mut dyn Write, v: &T, pretty: bool) -> CliResult<()> {
    let s = if pretty {
        serde_json::to_string_pretty(v).map_err(|e| CliError::Internal(format!("{e}")))?
    } else {
        serde_json::to_string(v).map_err(|e| CliError::Internal(format!("{e}")))?
    };
    w.write_all(s.as_bytes()).map_err(io)?;
    w.write_all(b"\n").map_err(io)?;
    Ok(())
}

/// Implement `Renderable` with a hand-written human view and JSON/markdown
/// derived from serde (same pattern as the ledger CLI).
macro_rules! impl_render_tail {
    ($ty:ty, $title:expr) => {
        impl Renderable for $ty {
            fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
                self.human(w, opts)
            }
            fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
                write_json(w, self, pretty)
            }
            fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
                writeln!(w, "# {}\n", $title).map_err(io)?;
                writeln!(w, "```json").map_err(io)?;
                write_json(w, self, true)?;
                writeln!(w, "```").map_err(io)?;
                Ok(())
            }
        }
    };
}

// ---- output views ----------------------------------------------------------

#[derive(serde::Serialize)]
struct RmpStatusView {
    session: RmpSession,
    review_done: bool,
    monitor_events: Option<u64>,
    monitor_alerts: Option<u64>,
    protect_done: bool,
    proposals: usize,
}

impl RmpStatusView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "RMP session {} — agent {} ({}, {})",
            self.session.session_id,
            self.session.agent_id,
            self.session.environment,
            self.session.mode.label()
        )
        .map_err(io)?;
        writeln!(
            w,
            "  review:  {}",
            if self.review_done { "done" } else { "pending" }
        )
        .map_err(io)?;
        match (self.monitor_events, self.monitor_alerts) {
            (Some(ev), Some(al)) => {
                writeln!(w, "  monitor: {ev} event(s), {al} alert(s)").map_err(io)?
            }
            _ => writeln!(w, "  monitor: not started").map_err(io)?,
        }
        writeln!(
            w,
            "  protect: {}",
            if self.protect_done { "done" } else { "pending" }
        )
        .map_err(io)?;
        writeln!(w, "  proposals: {}", self.proposals).map_err(io)?;
        writeln!(
            w,
            "  ledger: {}",
            if self.session.ledger_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )
        .map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(RmpStatusView, "RMP session status");

#[derive(serde::Serialize)]
struct ReviewView {
    #[serde(flatten)]
    outcome: ReviewOutcome,
}

impl ReviewView {
    fn from(outcome: ReviewOutcome) -> Self {
        Self { outcome }
    }

    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        let o = &self.outcome;
        writeln!(
            w,
            "review {} — {} (score {:.2}, risk {:.2}, coverage {:.0}%)",
            o.session.session_id,
            o.result.label(),
            o.score,
            o.release_risk_score,
            o.coverage.coverage_ratio * 100.0
        )
        .map_err(io)?;
        writeln!(w, "recommendation: {}", o.recommendation.label()).map_err(io)?;
        for f in &o.findings {
            writeln!(
                w,
                "  [{}] {} — {}",
                f.severity.label(),
                f.kind.label(),
                f.title
            )
            .map_err(io)?;
        }
        if !o.required_changes.is_empty() {
            writeln!(w, "required changes:").map_err(io)?;
            for c in &o.required_changes {
                writeln!(w, "  - {c}").map_err(io)?;
            }
        }
        Ok(())
    }
}
impl_render_tail!(ReviewView, "Review outcome");

#[derive(serde::Serialize)]
struct FindingsView {
    session_id: String,
    findings: Vec<Finding>,
}

impl FindingsView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "session {} — {} finding(s)",
            self.session_id,
            self.findings.len()
        )
        .map_err(io)?;
        for f in &self.findings {
            writeln!(
                w,
                "  [{}] {} — {} ({})",
                f.severity.label(),
                f.kind.label(),
                f.title,
                f.finding_id
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(FindingsView, "Monitor findings");

#[derive(serde::Serialize)]
struct ProposalsView {
    proposals: Vec<ScenarioEnrichmentProposal>,
}

impl ProposalsView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(w, "{} enrichment proposal(s)", self.proposals.len()).map_err(io)?;
        for p in &self.proposals {
            writeln!(
                w,
                "  {} [{}] {} — {} (approval {})",
                p.proposal_id,
                p.severity.label(),
                p.proposed_scenario.title,
                p.status.label(),
                if p.human_approval_required {
                    "required"
                } else {
                    "optional"
                }
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(ProposalsView, "Scenario enrichment proposals");

#[derive(serde::Serialize)]
struct ProtectView {
    rmp_session_id: String,
    #[serde(flatten)]
    outcome: ProtectOutcome,
}

impl ProtectView {
    fn from(rmp_session_id: String, outcome: ProtectOutcome) -> Self {
        Self {
            rmp_session_id,
            outcome,
        }
    }

    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "protect {} — {} alert(s), {} recommendation(s), {} action plan(s)",
            self.rmp_session_id,
            self.outcome.alerts.len(),
            self.outcome.recommendations.len(),
            self.outcome.action_plans.len()
        )
        .map_err(io)?;
        for a in &self.outcome.alerts {
            let routes: Vec<String> = a
                .routes
                .iter()
                .map(|r| format!("{}:{}", r.channel, r.target))
                .collect();
            writeln!(
                w,
                "  [{}] {} ×{} → {} ({}){}",
                a.severity.label(),
                a.title,
                a.occurrence_count,
                routes.join(", "),
                a.alert_id,
                if a.throttled { " [throttled]" } else { "" }
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(ProtectView, "Protect outcome");

#[derive(serde::Serialize)]
struct ScenariosView {
    scenarios: Vec<TestScenario>,
}

impl ScenariosView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(w, "{} scenario(s)", self.scenarios.len()).map_err(io)?;
        for s in &self.scenarios {
            writeln!(
                w,
                "  {} [{}] {} (source: {}, risks: {})",
                s.scenario_id,
                s.severity.label(),
                s.title,
                s.source.label(),
                s.risk_ids.len()
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(ScenariosView, "Test scenarios");

#[derive(serde::Serialize)]
struct MatrixView {
    #[serde(flatten)]
    matrix: RiskMatrix,
}

impl MatrixView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(
            w,
            "risk matrix {} — {} item(s), release risk {:.2}, coverage {:.0}%",
            self.matrix.matrix_id,
            self.matrix.items.len(),
            self.matrix.release_risk_score(),
            self.matrix.coverage_ratio() * 100.0
        )
        .map_err(io)?;
        for item in &self.matrix.items {
            writeln!(
                w,
                "  [{}] {} — L{:.1}×I{:.1} = {:.2} ({}, {} scenario(s))",
                item.severity().label(),
                item.title,
                item.likelihood,
                item.impact,
                item.score(),
                item.status,
                item.covered_by_scenarios.len()
            )
            .map_err(io)?;
        }
        Ok(())
    }
}
impl_render_tail!(MatrixView, "Risk matrix");

#[derive(serde::Serialize)]
struct ReportView {
    #[serde(flatten)]
    report: agenomic_rmp::RmpReport,
}

impl ReportView {
    fn human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        write!(w, "{}", agenomic_rmp::render_markdown(&self.report)).map_err(io)?;
        Ok(())
    }
}
impl_render_tail!(ReportView, "RMP report");

// ---- shared stage logic ------------------------------------------------------

/// Build review inputs from a bundle + explicit files + the bundle corpus.
fn review_inputs(
    bundle: &Path,
    scenario_files: &[PathBuf],
    risk_matrix_file: &Option<PathBuf>,
    traces: &Option<PathBuf>,
    corpus_store: &RmpStore,
) -> CliResult<ReviewInputs> {
    let (_baseline, agent, genome_hash) = load_bundle_baseline(bundle)?;
    let agent_id = agent.ok_or_else(|| {
        CliError::Schema(
            "could not determine agent id from the bundle; add agent.id to genome.yaml".into(),
        )
    })?;

    let mut scenarios: Vec<TestScenario> = corpus_store.load_scenarios(CORPUS)?;
    for file in scenario_files {
        scenarios.extend(agenomic_rmp::parse_scenarios(&read_input(file)?)?);
    }

    let risk_matrix: Option<RiskMatrix> = match risk_matrix_file {
        Some(p) => Some(
            serde_json::from_str(&read_input(p)?)
                .map_err(|e| CliError::Schema(format!("risk matrix: {e}")))?,
        ),
        None => corpus_store.load_risk_matrix(CORPUS)?,
    };

    // Default traces: the bundle's traces/ fixtures, when present.
    let traces = traces.clone().or_else(|| {
        let dir = bundle.join("traces");
        if !dir.is_dir() {
            return None;
        }
        std::fs::read_dir(&dir).ok().and_then(|entries| {
            let mut files: Vec<PathBuf> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect();
            files.sort();
            files.into_iter().next()
        })
    });

    Ok(ReviewInputs {
        bundle: Some(bundle.to_path_buf()),
        agent_id,
        genome_hash,
        release_id: None,
        risk_matrix,
        scenarios,
        traces,
        ..ReviewInputs::default()
    })
}

/// Load the approved-but-not-yet-applied proposals of a session (feedback
/// loop input). Applied proposals are excluded: `proposals apply` already
/// persisted their scenario into the Review corpus, so injecting them again
/// would run the same scenario twice and inflate coverage counts.
fn approved_proposals(
    store: &RmpStore,
    session_id: &str,
) -> CliResult<Vec<ScenarioEnrichmentProposal>> {
    Ok(store
        .load_proposals(session_id)?
        .into_iter()
        .filter(|p| p.status == agenomic_rmp::EnrichmentStatus::Approved)
        .collect())
}

/// Record one enrichment-lifecycle event on the session's ledger when the
/// session is bound with `--ledger`. No-op otherwise (the store is always
/// the source of truth; the ledger is the tamper-evident audit trail).
fn record_enrichment_event(
    store: &RmpStore,
    session: &RmpSession,
    event_type: &str,
    proposal: &ScenarioEnrichmentProposal,
    extra: serde_json::Value,
) -> CliResult<()> {
    let Some(binding) = load_rmp_binding(store, &session.session_id) else {
        return Ok(());
    };
    let tracking_run = binding.tracking_session_id.clone();
    let Some(ledger) = binding.ledger.filter(|l| l.enabled) else {
        return Ok(());
    };
    let mut payload = serde_json::json!({
        "proposal_id": proposal.proposal_id,
        "scenario_id": proposal.proposed_scenario.scenario_id,
        "source_finding_id": proposal.source_finding_id,
        "status": proposal.status.label(),
    });
    if let (Some(obj), Some(ex)) = (payload.as_object_mut(), extra.as_object()) {
        for (k, v) in ex {
            obj.insert(k.clone(), v.clone());
        }
    }
    let mut ev = agenomic_rmp::RmpLedgerEvent::new(
        event_type,
        &session.session_id,
        &session.agent_id,
        payload,
    );
    ev.genome_hash = session.genome_hash.clone();
    ev.release_id = session.release_id.clone();
    ev.evidence_refs = proposal.source_event_ids.clone();
    // The report proof and evidence export are built for the bound tracking
    // run; keep the enrichment lifecycle inside that audit scope.
    if let Some(run) = tracking_run {
        ev.run_id = run;
    }
    crate::ledger::append_drafts(&ledger.dirs(), vec![ev.to_draft()])?;
    Ok(())
}

/// `agm rmp proposals <action>` — the human-approval surface that closes the
/// continuous safety loop. Proposals are append-only in the session store
/// (last record wins); each transition also lands on the ledger when bound.
fn cmd_proposals(
    action: &ProposalAction,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match action {
        ProposalAction::List { session, stores } => {
            let store = rmp_store(stores)?;
            require_rmp_session(&store, session)?;
            let proposals = store.load_proposals(session)?;
            render(&ProposalsView { proposals }, format, no_color)?;
            Ok(ExitCode::Success)
        }
        ProposalAction::Approve {
            proposal_id,
            session,
            reviewer,
            stores,
        } => proposal_transition(
            session,
            proposal_id,
            reviewer.as_deref(),
            stores,
            ProposalOp::Approve,
            format,
            no_color,
        ),
        ProposalAction::Reject {
            proposal_id,
            session,
            reviewer,
            stores,
        } => proposal_transition(
            session,
            proposal_id,
            reviewer.as_deref(),
            stores,
            ProposalOp::Reject,
            format,
            no_color,
        ),
        ProposalAction::Apply {
            proposal_id,
            session,
            stores,
        } => proposal_apply(session, proposal_id, stores, format, no_color),
    }
}

#[derive(Clone, Copy)]
enum ProposalOp {
    Approve,
    Reject,
}

/// Load a session proposal by id, or a helpful error listing what exists.
fn load_one_proposal(
    store: &RmpStore,
    session_id: &str,
    proposal_id: &str,
) -> CliResult<ScenarioEnrichmentProposal> {
    store
        .load_proposals(session_id)?
        .into_iter()
        .find(|p| p.proposal_id == proposal_id)
        .ok_or_else(|| {
            CliError::Schema(format!(
                "no proposal '{proposal_id}' in session '{session_id}'"
            ))
        })
}

/// Approve/reject a proposal. A fresh draft is auto-submitted so a single
/// command moves draft → approved/rejected; the state machine itself is
/// unchanged (submit then approve).
fn proposal_transition(
    session_id: &str,
    proposal_id: &str,
    reviewer: Option<&str>,
    stores: &RmpStoreArgs,
    op: ProposalOp,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let session = require_rmp_session(&store, session_id)?;
    let mut proposal = load_one_proposal(&store, session_id, proposal_id)?;
    let reviewer = reviewer.unwrap_or("").to_string();

    if proposal.status == agenomic_rmp::EnrichmentStatus::Draft {
        proposal.submit()?;
    }
    match op {
        ProposalOp::Approve => proposal.approve(&reviewer)?,
        ProposalOp::Reject => proposal.reject(&reviewer)?,
    }
    store.append_proposals(session_id, std::slice::from_ref(&proposal))?;

    if matches!(op, ProposalOp::Approve) {
        record_enrichment_event(
            &store,
            &session,
            agenomic_rmp::event_types::RMP_ENRICHMENT_APPROVED,
            &proposal,
            serde_json::json!({ "reviewed_by": proposal.reviewed_by }),
        )?;
    }
    render(
        &ProposalsView {
            proposals: vec![proposal],
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

/// Apply an approved proposal: persist its scenario into the Review corpus
/// (so the next review covers the incident) and mark it applied.
fn proposal_apply(
    session_id: &str,
    proposal_id: &str,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let session = require_rmp_session(&store, session_id)?;
    let mut proposal = load_one_proposal(&store, session_id, proposal_id)?;

    // Resolve the corpus store from the session's bundle binding, falling
    // back to the session store root when the bundle path is unavailable.
    let corpus_store = load_rmp_binding(&store, session_id)
        .map(|b| bundle_store(&b.bundle, stores))
        .unwrap_or_else(|| rmp_store(stores).unwrap_or_else(|_| store.clone()));

    proposal.mark_applied()?; // errors unless status == approved
    corpus_store.save_scenario(CORPUS, &proposal.proposed_scenario)?;
    store.append_proposals(session_id, std::slice::from_ref(&proposal))?;

    record_enrichment_event(
        &store,
        &session,
        agenomic_rmp::event_types::REVIEW_TEST_SCENARIO_CREATED,
        &proposal,
        serde_json::json!({ "source": "scenario_enrichment" }),
    )?;
    record_enrichment_event(
        &store,
        &session,
        agenomic_rmp::event_types::RMP_ENRICHMENT_APPLIED,
        &proposal,
        serde_json::json!({}),
    )?;
    render(
        &ProposalsView {
            proposals: vec![proposal],
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

/// Derive the monitor findings of a tracking session (resume, read-only).
fn monitor_findings(
    tstore: &SessionStore,
    tracking_session_id: &str,
) -> CliResult<(MonitorSession, Vec<Finding>)> {
    let session = require_session(tstore, tracking_session_id)?;
    let events = tstore.load_events(tracking_session_id)?;
    let baseline = tstore.load_baseline(tracking_session_id)?;
    let msession = MonitorSession::from_tracking(&session, RmpMode::DurableLowLatency, false);
    let engine = MonitorEngine::resume(
        msession.clone(),
        session,
        events,
        baseline,
        MonitorConfig::default(),
        None,
    );
    Ok((msession, engine.findings().to_vec()))
}

/// All findings of an RMP session: monitor findings + stored review findings.
fn session_findings(
    store: &RmpStore,
    stores: &RmpStoreArgs,
    session_id: &str,
) -> CliResult<Vec<Finding>> {
    let mut findings = Vec::new();
    if let Some(review) = store.load_review(session_id)? {
        findings.extend(review.findings);
    }
    if let Some(binding) = load_rmp_binding(store, session_id) {
        if let Some(tid) = &binding.tracking_session_id {
            let tstore = match &binding.tracking_store {
                Some(p) => SessionStore::new(p.clone()),
                None => tracking_store(stores)?,
            };
            if tstore.exists(tid) {
                let (_m, monitor) = monitor_findings(&tstore, tid)?;
                findings.extend(monitor);
            }
        }
    }
    Ok(findings)
}

/// Run Protect over a session's findings and persist the outcome.
fn run_protect(
    store: &RmpStore,
    stores: &RmpStoreArgs,
    session_id: &str,
) -> CliResult<ProtectOutcome> {
    let session = require_rmp_session(store, session_id)?;
    let findings = session_findings(store, stores, session_id)?;
    let matrix = store
        .load_review(session_id)?
        .and_then(|r| r.risk_matrix)
        .or(store.load_risk_matrix(session_id)?);
    let outcome = ProtectEngine::default().run(&session.agent_id, &findings, matrix.as_ref())?;
    store.save_protect(session_id, &outcome)?;
    store.append_proposals(session_id, &outcome.scenario_proposals)?;

    // Record protect events on the ledger when the session is bound.
    if let Some(binding) = load_rmp_binding(store, session_id) {
        let tracking_run = binding.tracking_session_id.clone();
        if let Some(ledger) = binding.ledger.filter(|l| l.enabled) {
            let mut drafts = Vec::new();
            for alert in &outcome.alerts {
                let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                    agenomic_rmp::event_types::PROTECT_ALERT_CREATED,
                    session_id,
                    &session.agent_id,
                    serde_json::json!({
                        "alert_id": alert.alert_id,
                        "severity": alert.severity,
                        "title": alert.title,
                        "dedup_key": alert.dedup_key,
                        "occurrences": alert.occurrence_count,
                    }),
                );
                ev.genome_hash = session.genome_hash.clone();
                ev.release_id = session.release_id.clone();
                ev.evidence_refs = alert.evidence_refs.clone();
                drafts.push(ev.to_draft());
            }
            for rec in &outcome.recommendations {
                let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                    agenomic_rmp::event_types::PROTECT_RECOMMENDATION_CREATED,
                    session_id,
                    &session.agent_id,
                    serde_json::json!({
                        "recommendation_id": rec.recommendation_id,
                        "kind": rec.kind.label(),
                        "requires_human_approval": rec.requires_human_approval,
                        "title": rec.title,
                    }),
                );
                ev.genome_hash = session.genome_hash.clone();
                drafts.push(ev.to_draft());
            }
            for proposal in &outcome.scenario_proposals {
                let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                    agenomic_rmp::event_types::RMP_ENRICHMENT_PROPOSED,
                    session_id,
                    &session.agent_id,
                    serde_json::json!({
                        "proposal_id": proposal.proposal_id,
                        "scenario_id": proposal.proposed_scenario.scenario_id,
                        "source_finding_id": proposal.source_finding_id,
                        "severity": proposal.severity,
                        "human_approval_required": proposal.human_approval_required,
                    }),
                );
                ev.genome_hash = session.genome_hash.clone();
                ev.evidence_refs = proposal.source_event_ids.clone();
                // Same audit scope as the approval/apply events: the report
                // proof is built for the bound tracking run.
                if let Some(run) = &tracking_run {
                    ev.run_id = run.clone();
                }
                drafts.push(ev.to_draft());
            }
            crate::ledger::append_drafts(&ledger.dirs(), drafts)?;
        }
    }
    Ok(outcome)
}

/// Load-or-run the protect outcome for a session.
fn protect_outcome(
    store: &RmpStore,
    stores: &RmpStoreArgs,
    session_id: &str,
) -> CliResult<ProtectOutcome> {
    match store.load_protect(session_id)? {
        Some(outcome) => Ok(outcome),
        None => run_protect(store, stores, session_id),
    }
}

// ---- rmp -------------------------------------------------------------------

/// Dispatch for `agenomic rmp`.
pub fn cmd_rmp(args: &RmpCommand, format: OutputFormat, no_color: bool) -> CliResult<ExitCode> {
    match &args.command {
        RmpSub::Start {
            bundle,
            release,
            env,
            agent,
            stores,
            ledger,
        } => rmp_start(
            bundle, release, env, agent, stores, ledger, format, no_color,
        ),
        RmpSub::Status { session, stores } => rmp_status(session, stores, format, no_color),
        RmpSub::Report {
            session,
            output,
            include_ledger_proof,
            stores,
        } => rmp_report(
            session,
            output,
            *include_ledger_proof,
            stores,
            format,
            no_color,
        ),
        RmpSub::Review {
            bundle,
            session,
            scenarios,
            risk_matrix,
            traces,
            stores,
        } => rmp_review(
            bundle,
            session.as_deref(),
            scenarios,
            risk_matrix,
            traces,
            stores,
            format,
            no_color,
        ),
        RmpSub::Monitor { session, stores } => rmp_monitor(session, stores, format, no_color),
        RmpSub::Protect { session, stores } => {
            let store = rmp_store(stores)?;
            let outcome = run_protect(&store, stores, session)?;
            render(
                &ProtectView::from(session.clone(), outcome),
                format,
                no_color,
            )?;
            Ok(ExitCode::Success)
        }
        RmpSub::EnrichScenarios {
            from_findings,
            output,
        } => enrich_from_file(from_findings, output, format, no_color),
        RmpSub::Proposals { action } => cmd_proposals(action, format, no_color),
        RmpSub::ActionPlan {
            alert,
            session,
            stores,
        } => action_plan(alert, session, stores, format, no_color),
        RmpSub::ExportEvidence {
            session,
            output,
            include_ledger,
            stores,
        } => export_session_evidence(session, output, *include_ledger, stores, format, no_color),
    }
}

#[allow(clippy::too_many_arguments)]
fn rmp_start(
    bundle: &Path,
    release: &Option<String>,
    env: &str,
    agent: &Option<String>,
    stores: &RmpStoreArgs,
    ledger: &RmpLedgerArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let tstore = tracking_store(stores)?;

    // The live path: an underlying tracking session.
    let tracking = start_tracking_session(
        bundle,
        release,
        env,
        &None,
        agent,
        &tstore,
        &LedgerOpts {
            enabled: ledger.ledger,
            store: ledger.ledger_store.clone(),
            keys: ledger.ledger_keys.clone(),
        },
    )?;

    let mut session = RmpSession::new(tracking.agent_id.clone(), env.to_string());
    session.genome_hash = tracking.genome_hash.clone();
    session.release_id = release.clone();
    session.ledger_enabled = ledger.ledger;
    session.monitor_session_id = Some(tracking.session_id.clone());
    store.save_session(&session)?;
    save_binding(
        &store,
        &session.session_id,
        &RmpBinding {
            bundle: bundle.to_path_buf(),
            tracking_session_id: Some(tracking.session_id.clone()),
            tracking_store: stores.tracking_store.clone(),
            ledger: Some(LedgerBindingMirror {
                enabled: ledger.ledger,
                store: ledger.ledger_store.clone(),
                keys: ledger.ledger_keys.clone(),
            }),
        },
    )?;

    if ledger.ledger {
        let mut ev = agenomic_rmp::RmpLedgerEvent::new(
            agenomic_rmp::event_types::RMP_SESSION_STARTED,
            &session.session_id,
            &session.agent_id,
            serde_json::json!({
                "environment": session.environment,
                "release_id": session.release_id,
                "monitor_session_id": session.monitor_session_id,
                "mode": session.mode.label(),
            }),
        );
        ev.genome_hash = session.genome_hash.clone();
        ev.release_id = session.release_id.clone();
        let dirs = crate::cli::LedgerDirs {
            store: ledger.ledger_store.clone(),
            keys: ledger.ledger_keys.clone(),
        };
        crate::ledger::append_drafts(&dirs, vec![ev.to_draft()])?;
    }

    let view = RmpStatusView {
        session,
        review_done: false,
        monitor_events: Some(0),
        monitor_alerts: Some(0),
        protect_done: false,
        proposals: 0,
    };
    render(&view, format, no_color)?;
    Ok(ExitCode::Success)
}

fn rmp_status(
    session_id: &str,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let session = require_rmp_session(&store, session_id)?;
    let binding = load_rmp_binding(&store, session_id);
    let (monitor_events, monitor_alerts) = match binding
        .as_ref()
        .and_then(|b| b.tracking_session_id.as_deref())
    {
        Some(tid) => {
            // An explicit --tracking-store flag wins; otherwise use the
            // store recorded in the binding at `rmp start`, then the
            // default location.
            let recorded = binding.as_ref().and_then(|b| b.tracking_store.clone());
            let tstore = match (&stores.tracking_store, recorded) {
                (Some(_), _) | (None, None) => tracking_store(stores)?,
                (None, Some(p)) => SessionStore::new(p),
            };
            if tstore.exists(tid) {
                let tsession = tstore.load_session(tid)?;
                let events = tstore.load_events(tid)?;
                (
                    Some(events.len() as u64),
                    Some(tsession.alerts.len() as u64),
                )
            } else {
                (None, None)
            }
        }
        None => (None, None),
    };
    let view = RmpStatusView {
        review_done: store.load_review(session_id)?.is_some(),
        protect_done: store.load_protect(session_id)?.is_some(),
        proposals: store.load_proposals(session_id)?.len(),
        monitor_events,
        monitor_alerts,
        session,
    };
    render(&view, format, no_color)?;
    Ok(ExitCode::Success)
}

/// Build the monitor outcome of a session on demand (read-only resume).
fn monitor_outcome_for(
    store: &RmpStore,
    stores: &RmpStoreArgs,
    session_id: &str,
) -> CliResult<Option<agenomic_rmp::MonitorOutcome>> {
    let Some(binding) = load_rmp_binding(store, session_id) else {
        return Ok(None);
    };
    let Some(tid) = binding.tracking_session_id.as_deref() else {
        return Ok(None);
    };
    let tstore = match &binding.tracking_store {
        Some(p) => SessionStore::new(p.clone()),
        None => tracking_store(stores)?,
    };
    if !tstore.exists(tid) {
        return Ok(None);
    }
    let tsession = require_session(&tstore, tid)?;
    let events = tstore.load_events(tid)?;
    let baseline = tstore.load_baseline(tid)?;
    let harness_inputs = load_harness_inputs(&tsession)?;
    let msession = MonitorSession::from_tracking(
        &tsession,
        RmpMode::DurableLowLatency,
        binding.ledger.as_ref().is_some_and(|l| l.enabled),
    );
    let status = tsession.status;
    let engine = MonitorEngine::resume(
        msession,
        tsession,
        events,
        baseline,
        MonitorConfig::default(),
        None,
    );
    let terminal = match status {
        SessionStatus::Cancelled => SessionStatus::Cancelled,
        SessionStatus::Failed => SessionStatus::Failed,
        _ => SessionStatus::Completed,
    };
    Ok(Some(engine.stop(&harness_inputs, terminal)?))
}

fn rmp_report(
    session_id: &str,
    output: &Option<PathBuf>,
    include_ledger_proof: bool,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let session = require_rmp_session(&store, session_id)?;
    let review = store.load_review(session_id)?;
    let monitor = monitor_outcome_for(&store, stores, session_id)?;
    let protect = store.load_protect(session_id)?;

    let ledger_proof = if include_ledger_proof {
        let binding = load_rmp_binding(&store, session_id).and_then(|b| {
            b.ledger
                .filter(|l| l.enabled)
                .map(|l| (b.tracking_session_id, l))
        });
        let Some((tracking_id, ledger)) = binding else {
            return Err(CliError::Schema(format!(
                "session '{session_id}' is not ledger-bound; start with `agenomic rmp start --ledger`"
            )));
        };
        let run_id = tracking_id.unwrap_or_else(|| session_id.to_string());
        let proof = crate::ledger::build_proof(&ledger.dirs(), &run_id)?;
        Some(serde_json::to_value(&proof).map_err(|e| CliError::Internal(format!("{e}")))?)
    } else {
        None
    };

    let report = build_rmp_report(session.clone(), review, monitor, protect, ledger_proof)?;
    store.save_report(session_id, &report)?;
    if let Some(out) = output {
        write_json_file(out, &report)?;
    }

    // Record report generation on the ledger when bound.
    if let Some(binding) = load_rmp_binding(&store, session_id) {
        if let Some(ledger) = binding.ledger.filter(|l| l.enabled) {
            let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                agenomic_rmp::event_types::RMP_REPORT_GENERATED,
                session_id,
                &session.agent_id,
                serde_json::json!({
                    "report_hash": report.report_hash,
                    "release_recommendation": report.release_recommendation.label(),
                    "final_risk_score": report.final_risk_score,
                }),
            );
            ev.genome_hash = session.genome_hash.clone();
            crate::ledger::append_drafts(&ledger.dirs(), vec![ev.to_draft()])?;
        }
    }

    let blocked = report.release_recommendation == ReleaseRecommendation::Block;
    render(&ReportView { report }, format, no_color)?;
    if blocked {
        return Ok(ExitCode::ValidationFailed);
    }
    Ok(ExitCode::Success)
}

#[allow(clippy::too_many_arguments)]
fn rmp_review(
    bundle: &Path,
    session_id: Option<&str>,
    scenario_files: &[PathBuf],
    risk_matrix_file: &Option<PathBuf>,
    traces: &Option<PathBuf>,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    // Attach to the given RMP session, or create a standalone one.
    let (mut session, owned) = match session_id {
        Some(id) => (require_rmp_session(&store, id)?, false),
        None => {
            let (_b, agent, genome_hash) = load_bundle_baseline(bundle)?;
            let agent_id = agent.ok_or_else(|| {
                CliError::Schema("could not determine agent id from the bundle".into())
            })?;
            let mut s = RmpSession::new(agent_id, "review");
            s.genome_hash = genome_hash;
            (s, true)
        }
    };

    // The corpus follows the user's --store like every other artifact;
    // hardcoding defaults here used to leak .agenomic/rmp/corpus/ into the
    // bundle directory even when a store was given.
    let corpus_store = bundle_store(bundle, stores);
    let mut inputs = review_inputs(
        bundle,
        scenario_files,
        risk_matrix_file,
        traces,
        &corpus_store,
    )?;
    inputs.release_id = session.release_id.clone();
    inputs.approved_proposals = approved_proposals(&store, &session.session_id)?;
    inputs.carried_findings =
        session_findings(&store, stores, &session.session_id).unwrap_or_default();

    let outcome = ReviewEngine::default().run(inputs)?;

    session.review_session_id = Some(outcome.session.session_id.clone());
    if owned {
        save_binding(
            &store,
            &session.session_id,
            &RmpBinding {
                bundle: bundle.to_path_buf(),
                tracking_session_id: None,
                tracking_store: None,
                ledger: None,
            },
        )?;
    }
    store.save_session(&session)?;
    store.save_review(&session.session_id, &outcome)?;
    store.append_findings(&session.session_id, &outcome.findings)?;
    if let Some(matrix) = &outcome.risk_matrix {
        store.save_risk_matrix(&session.session_id, matrix)?;
        corpus_store.save_risk_matrix(CORPUS, matrix)?;
    }

    // Ledger events when bound.
    if let Some(binding) = load_rmp_binding(&store, &session.session_id) {
        if let Some(ledger) = binding.ledger.filter(|l| l.enabled) {
            let mut drafts = Vec::new();
            let mut started = agenomic_rmp::RmpLedgerEvent::new(
                agenomic_rmp::event_types::REVIEW_SESSION_STARTED,
                &session.session_id,
                &session.agent_id,
                serde_json::json!({
                    "review_session_id": outcome.session.session_id,
                    "scenarios": outcome.coverage.total_scenarios,
                }),
            );
            started.genome_hash = session.genome_hash.clone();
            drafts.push(started.to_draft());
            for f in &outcome.findings {
                let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                    agenomic_rmp::event_types::REVIEW_FINDING_CREATED,
                    &session.session_id,
                    &session.agent_id,
                    serde_json::json!({
                        "finding_id": f.finding_id,
                        "kind": f.kind.label(),
                        "severity": f.severity,
                        "title": f.title,
                    }),
                );
                ev.evidence_refs = f.evidence_refs.clone();
                drafts.push(ev.to_draft());
            }
            crate::ledger::append_drafts(&ledger.dirs(), drafts)?;
        }
    }

    let failed = matches!(outcome.result, agenomic_rmp::EvaluationResult::Fail);
    render(&ReviewView::from(outcome), format, no_color)?;
    if failed {
        return Ok(ExitCode::ValidationFailed);
    }
    Ok(ExitCode::Success)
}

fn rmp_monitor(
    session_id: &str,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    require_rmp_session(&store, session_id)?;
    let binding = load_rmp_binding(&store, session_id).ok_or_else(|| {
        CliError::Schema(format!("session '{session_id}' has no monitor binding"))
    })?;
    let tid = binding.tracking_session_id.ok_or_else(|| {
        CliError::Schema(format!(
            "session '{session_id}' has no live monitor session"
        ))
    })?;
    let tstore = match &binding.tracking_store {
        Some(p) => SessionStore::new(p.clone()),
        None => tracking_store(stores)?,
    };
    let (_msession, findings) = monitor_findings(&tstore, &tid)?;
    render(
        &FindingsView {
            session_id: tid,
            findings,
        },
        format,
        no_color,
    )?;
    Ok(ExitCode::Success)
}

fn enrich_from_file(
    from_findings: &Path,
    output: &Option<PathBuf>,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let raw: serde_json::Value = serde_json::from_str(&read_input(from_findings)?)
        .map_err(|e| CliError::Schema(format!("findings json: {e}")))?;
    let findings: Vec<Finding> = if raw.is_array() {
        serde_json::from_value(raw).map_err(|e| CliError::Schema(format!("findings: {e}")))?
    } else if let Some(inner) = raw.get("findings") {
        serde_json::from_value(inner.clone())
            .map_err(|e| CliError::Schema(format!("findings: {e}")))?
    } else {
        return Err(CliError::Schema(
            "expected a findings array or an object with a `findings` field".into(),
        ));
    };
    let proposals = proposals_from_findings(&findings);
    if let Some(out) = output {
        write_json_file(out, &proposals)?;
    }
    render(&ProposalsView { proposals }, format, no_color)?;
    Ok(ExitCode::Success)
}

fn action_plan(
    alert_id: &str,
    session_id: &str,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    require_rmp_session(&store, session_id)?;
    let outcome = protect_outcome(&store, stores, session_id)?;
    let alert = outcome
        .alerts
        .iter()
        .find(|a| a.alert_id == alert_id)
        .ok_or_else(|| {
            CliError::Schema(format!(
                "unknown alert '{alert_id}' in session '{session_id}' \
                 (list alerts with `agenomic protect alerts --session {session_id}`)"
            ))
        })?;
    let plan = outcome
        .action_plans
        .iter()
        .find(|p| p.alert_id == alert_id)
        .cloned()
        .unwrap_or_else(|| {
            ProtectEngine::default().action_plan(
                alert,
                &outcome.recommendations,
                &outcome.scenario_proposals,
            )
        });
    render_plain_json(&plan, format)?;
    let _ = no_color;
    Ok(ExitCode::Success)
}

/// Render a serializable value: JSON in json modes, pretty JSON otherwise.
fn render_plain_json<T: serde::Serialize>(value: &T, format: OutputFormat) -> CliResult<()> {
    let pretty = !matches!(format, OutputFormat::Json);
    let s = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .map_err(|e| CliError::Internal(format!("{e}")))?;
    println!("{s}");
    Ok(())
}

fn export_session_evidence(
    session_id: &str,
    output: &Path,
    include_ledger: bool,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let store = rmp_store(stores)?;
    let session = require_rmp_session(&store, session_id)?;
    // Ensure a report exists (build one on demand, with proof when asked).
    let report = match store.load_report(session_id)? {
        Some(r) if !include_ledger || r.ledger_proof.is_some() => r,
        _ => {
            let review = store.load_review(session_id)?;
            let monitor = monitor_outcome_for(&store, stores, session_id)?;
            let protect = store.load_protect(session_id)?;
            let ledger_proof = if include_ledger {
                let binding = load_rmp_binding(&store, session_id).and_then(|b| {
                    b.ledger
                        .filter(|l| l.enabled)
                        .map(|l| (b.tracking_session_id, l))
                });
                match binding {
                    Some((tracking_id, ledger)) => {
                        let run_id = tracking_id.unwrap_or_else(|| session_id.to_string());
                        let proof = crate::ledger::build_proof(&ledger.dirs(), &run_id)?;
                        Some(
                            serde_json::to_value(&proof)
                                .map_err(|e| CliError::Internal(format!("{e}")))?,
                        )
                    }
                    None => {
                        return Err(CliError::Schema(format!(
                            "session '{session_id}' is not ledger-bound; cannot --include-ledger"
                        )))
                    }
                }
            } else {
                None
            };
            let r = build_rmp_report(session.clone(), review, monitor, protect, ledger_proof)?;
            store.save_report(session_id, &r)?;
            r
        }
    };

    let manifest = export_evidence(
        output,
        &report,
        &EvidenceExportOptions {
            include_markdown: true,
        },
    )?;

    // Record the export on the ledger when bound.
    if let Some(binding) = load_rmp_binding(&store, session_id) {
        if let Some(ledger) = binding.ledger.filter(|l| l.enabled) {
            let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                agenomic_rmp::event_types::PROTECT_EVIDENCE_EXPORTED,
                session_id,
                &session.agent_id,
                serde_json::json!({
                    "output": output.display().to_string(),
                    "files": manifest.files.len(),
                    "rmp_report_hash": manifest.rmp_report_hash,
                }),
            );
            ev.genome_hash = session.genome_hash.clone();
            crate::ledger::append_drafts(&ledger.dirs(), vec![ev.to_draft()])?;
        }
    }

    match format {
        OutputFormat::Json | OutputFormat::JsonPretty => render_plain_json(&manifest, format)?,
        _ => {
            println!(
                "evidence bundle written to {} ({} file(s))",
                output.display(),
                manifest.files.len()
            );
            for f in &manifest.files {
                println!("  {} ({})", f.path, f.hash);
            }
        }
    }
    let _ = no_color;
    Ok(ExitCode::Success)
}

// ---- review ------------------------------------------------------------------

/// Dispatch for `agenomic review`.
pub fn cmd_review(
    args: &ReviewCliCommand,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        ReviewSub::Run {
            bundle,
            scenarios,
            risk_matrix,
            traces,
            output,
            stores,
        } => {
            let corpus_store = bundle_store(bundle, stores);
            let inputs = review_inputs(bundle, scenarios, risk_matrix, traces, &corpus_store)?;
            let outcome = ReviewEngine::default().run(inputs)?;
            if let Some(out) = output {
                write_json_file(out, &outcome)?;
            }
            // Persist under the review session id so `review report` works.
            let store = corpus_store;
            let mut session =
                RmpSession::new(outcome.session.agent_id.clone(), "review".to_string());
            session.session_id = outcome.session.session_id.clone();
            session.genome_hash = outcome.session.genome_hash.clone();
            store.save_session(&session)?;
            store.save_review(&session.session_id, &outcome)?;
            if let Some(matrix) = &outcome.risk_matrix {
                store.save_risk_matrix(CORPUS, matrix)?;
            }
            let failed = matches!(outcome.result, agenomic_rmp::EvaluationResult::Fail);
            render(&ReviewView::from(outcome), format, no_color)?;
            if failed {
                return Ok(ExitCode::ValidationFailed);
            }
            Ok(ExitCode::Success)
        }
        ReviewSub::Scenarios(sc) => match &sc.command {
            ReviewScenariosSub::List { bundle, stores } => {
                let store = bundle_store(bundle, stores);
                let scenarios = store.load_scenarios(CORPUS)?;
                render(&ScenariosView { scenarios }, format, no_color)?;
                Ok(ExitCode::Success)
            }
            ReviewScenariosSub::Add {
                bundle,
                file,
                stores,
            } => {
                let store = bundle_store(bundle, stores);
                let scenarios = agenomic_rmp::parse_scenarios(&read_input(file)?)?;
                for scenario in &scenarios {
                    store.save_scenario(CORPUS, scenario)?;
                }
                render(&ScenariosView { scenarios }, format, no_color)?;
                Ok(ExitCode::Success)
            }
        },
        ReviewSub::RiskMatrix { bundle, stores } => {
            let store = bundle_store(bundle, stores);
            let matrix = match store.load_risk_matrix(CORPUS)? {
                Some(m) => m,
                None => {
                    let (_b, agent, genome_hash) = load_bundle_baseline(bundle)?;
                    let agent_id = agent.unwrap_or_else(|| "agent://unknown/unknown".into());
                    let mut m = RiskMatrix::new(agent_id);
                    m.genome_hash = genome_hash;
                    store.save_risk_matrix(CORPUS, &m)?;
                    m
                }
            };
            render(&MatrixView { matrix }, format, no_color)?;
            Ok(ExitCode::Success)
        }
        ReviewSub::Report { session, stores } => {
            let store = rmp_store(stores)?;
            let outcome = store.load_review(session)?.ok_or_else(|| {
                CliError::Schema(format!("no review outcome stored for session '{session}'"))
            })?;
            render(&ReviewView::from(outcome), format, no_color)?;
            Ok(ExitCode::Success)
        }
    }
}

// ---- monitor -----------------------------------------------------------------

/// Dispatch for `agenomic monitor`.
pub fn cmd_monitor(
    args: &MonitorCliCommand,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        MonitorSub::Start {
            bundle,
            release,
            env,
            config,
            agent,
            stores,
            ledger,
        } => {
            let tstore = tracking_store(stores)?;
            let tracking = start_tracking_session(
                bundle,
                release,
                env,
                config,
                agent,
                &tstore,
                &LedgerOpts {
                    enabled: ledger.ledger,
                    store: ledger.ledger_store.clone(),
                    keys: ledger.ledger_keys.clone(),
                },
            )?;
            if ledger.ledger {
                let msession =
                    MonitorSession::from_tracking(&tracking, RmpMode::DurableLowLatency, true);
                let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                    agenomic_rmp::event_types::MONITOR_SESSION_STARTED,
                    &msession.session_id,
                    &msession.agent_id,
                    serde_json::json!({
                        "tracking_session_id": tracking.session_id,
                        "environment": msession.environment,
                        "mode": msession.mode.label(),
                    }),
                );
                ev.genome_hash = msession.genome_hash.clone();
                ev.run_id = tracking.session_id.clone();
                let dirs = crate::cli::LedgerDirs {
                    store: ledger.ledger_store.clone(),
                    keys: ledger.ledger_keys.clone(),
                };
                crate::ledger::append_drafts(&dirs, vec![ev.to_draft()])?;
            }
            render(&tracking, format, no_color)?;
            Ok(ExitCode::Success)
        }
        MonitorSub::Event {
            session,
            file,
            stores,
        } => monitor_event(session, file, stores, format),
        MonitorSub::Tail {
            session,
            limit,
            stores,
        } => {
            // Same view as `track tail`.
            let tstore = tracking_store(stores)?;
            let tsession = require_session(&tstore, session)?;
            let events = tstore.load_events(session)?;
            let start = events.len().saturating_sub(*limit);
            let value = serde_json::json!({
                "session_id": session,
                "status": tsession.status.label(),
                "events": &events[start..],
                "alerts": tsession.alerts,
            });
            render_plain_json(&value, format)?;
            Ok(ExitCode::Success)
        }
        MonitorSub::Findings { session, stores } => {
            let tstore = tracking_store(stores)?;
            let (_m, findings) = monitor_findings(&tstore, session)?;
            render(
                &FindingsView {
                    session_id: session.clone(),
                    findings,
                },
                format,
                no_color,
            )?;
            Ok(ExitCode::Success)
        }
        MonitorSub::EnrichReview {
            session,
            output,
            stores,
        } => {
            let tstore = tracking_store(stores)?;
            let (_m, findings) = monitor_findings(&tstore, session)?;
            let proposals = proposals_from_findings(&findings);
            if let Some(out) = output {
                write_json_file(out, &proposals)?;
            }
            render(&ProposalsView { proposals }, format, no_color)?;
            Ok(ExitCode::Success)
        }
        MonitorSub::Stop {
            session,
            status,
            stores,
        } => monitor_stop(session, *status, stores, format, no_color),
    }
}

fn monitor_event(
    session_id: &str,
    file: &Path,
    stores: &RmpStoreArgs,
    format: OutputFormat,
) -> CliResult<ExitCode> {
    let tstore = tracking_store(stores)?;
    let session = require_session(&tstore, session_id)?;
    if session.status.is_terminal() {
        return Err(CliError::Schema(format!(
            "session '{session_id}' is {} and cannot accept new events",
            session.status.label()
        )));
    }
    let events = tstore.load_events(session_id)?;
    let baseline = tstore.load_baseline(session_id)?;
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
            tstore.append_events(session_id, std::slice::from_ref(stored))?;
            if let Some(binding) = load_binding(&tstore, session_id) {
                if binding.enabled {
                    let draft = agenomic_ledger_local::convert::from_tracking_event(stored)?;
                    crate::ledger::append_drafts(&binding.dirs(), vec![draft])?;
                }
            }
        }
    }
    tstore.save_session(&engine.session)?;

    // Findings raised by this event (monitor view of the alerts).
    let msession =
        MonitorSession::from_tracking(&engine.session, RmpMode::DurableLowLatency, false);
    let session_ref = &msession;
    let findings: Vec<Finding> = alerts
        .iter()
        .map(|a| {
            let kind = match a.kind {
                agenomic_track::AlertKind::Drift => agenomic_rmp::FindingKind::Drift,
                agenomic_track::AlertKind::Loop => agenomic_rmp::FindingKind::Loop,
                agenomic_track::AlertKind::Intent => agenomic_rmp::FindingKind::IntentShift,
                agenomic_track::AlertKind::Harness => agenomic_rmp::FindingKind::HarnessViolation,
                agenomic_track::AlertKind::Policy => agenomic_rmp::FindingKind::PolicyViolation,
                agenomic_track::AlertKind::Security => agenomic_rmp::FindingKind::Anomaly,
            };
            Finding::new(
                "monitor",
                &session_ref.session_id,
                &session_ref.agent_id,
                kind,
                a.severity.to_platform(),
                a.title.clone(),
                a.message.clone(),
            )
            .with_evidence(a.evidence_event_ids.iter().cloned())
        })
        .collect();

    // Ledger-bound session: findings join the audit chain alongside the raw
    // event, on the same run (same mapping as MonitorEngine's finding
    // events).
    if !findings.is_empty() {
        if let Some(binding) = load_binding(&tstore, session_id).filter(|b| b.enabled) {
            let drafts: Vec<_> = findings
                .iter()
                .map(|f| {
                    let event_type = match f.kind {
                        agenomic_rmp::FindingKind::Drift => {
                            agenomic_rmp::event_types::MONITOR_DRIFT_DETECTED
                        }
                        agenomic_rmp::FindingKind::Loop => {
                            agenomic_rmp::event_types::MONITOR_LOOP_DETECTED
                        }
                        agenomic_rmp::FindingKind::IntentShift => {
                            agenomic_rmp::event_types::MONITOR_INTENT_SHIFTED
                        }
                        agenomic_rmp::FindingKind::Failure
                        | agenomic_rmp::FindingKind::RepeatedFailure => {
                            agenomic_rmp::event_types::MONITOR_FAILURE_DETECTED
                        }
                        _ => agenomic_rmp::event_types::MONITOR_FINDING_CREATED,
                    };
                    let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                        event_type,
                        &msession.session_id,
                        &msession.agent_id,
                        serde_json::json!({
                            "finding_id": f.finding_id,
                            "kind": f.kind.label(),
                            "severity": f.severity,
                            "title": f.title,
                            "evidence_refs": f.evidence_refs,
                        }),
                    );
                    ev.genome_hash = msession.genome_hash.clone();
                    ev.release_id = msession.release_id.clone();
                    ev.run_id = session_id.to_string();
                    ev.to_draft()
                })
                .collect();
            crate::ledger::append_drafts(&binding.dirs(), drafts)?;
        }
    }

    let value = serde_json::json!({
        "session_id": session_id,
        "ingested": appended,
        "alerts": alerts,
        "findings": findings,
    });
    render_plain_json(&value, format)?;

    if alerts.iter().any(|a| a.blocks_release) {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

fn monitor_stop(
    session_id: &str,
    status: SessionStatusArg,
    stores: &RmpStoreArgs,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    let tstore = tracking_store(stores)?;
    let tsession = require_session(&tstore, session_id)?;
    let events = tstore.load_events(session_id)?;
    let baseline = tstore.load_baseline(session_id)?;
    let harness_inputs = load_harness_inputs(&tsession)?;
    let ledger_enabled = load_binding(&tstore, session_id).is_some_and(|b| b.enabled);
    let msession =
        MonitorSession::from_tracking(&tsession, RmpMode::DurableLowLatency, ledger_enabled);
    let engine = MonitorEngine::resume(
        msession,
        tsession,
        events,
        baseline,
        MonitorConfig::default(),
        None,
    );
    let terminal = match status {
        SessionStatusArg::Completed => SessionStatus::Completed,
        SessionStatusArg::Cancelled => SessionStatus::Cancelled,
        SessionStatusArg::Failed => SessionStatus::Failed,
    };
    let outcome = engine.stop(&harness_inputs, terminal)?;

    // Persist the terminal tracking session + report.
    let mut tsession = require_session(&tstore, session_id)?;
    tsession.status = terminal;
    tsession.ended_at = Some(chrono::Utc::now());
    tstore.save_session(&tsession)?;
    tstore.save_report(&outcome.report)?;

    let view = FindingsView {
        session_id: session_id.to_string(),
        findings: outcome.findings.clone(),
    };
    render(&view, format, no_color)?;
    if matches!(
        outcome.report.final_status,
        agenomic_track::FinalStatus::Fail
    ) {
        return Ok(ExitCode::ContractFailed);
    }
    Ok(ExitCode::Success)
}

// ---- protect -------------------------------------------------------------------

/// Dispatch for `agenomic protect`.
pub fn cmd_protect(
    args: &ProtectCliCommand,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<ExitCode> {
    match &args.command {
        ProtectSub::Alerts { session, stores } => {
            let store = rmp_store(stores)?;
            require_rmp_session(&store, session)?;
            let outcome = protect_outcome(&store, stores, session)?;
            render(
                &ProtectView::from(session.clone(), outcome),
                format,
                no_color,
            )?;
            Ok(ExitCode::Success)
        }
        ProtectSub::ActionPlan {
            alert,
            session,
            stores,
        } => action_plan(alert, session, stores, format, no_color),
        ProtectSub::Recommendations { session, stores } => {
            let store = rmp_store(stores)?;
            require_rmp_session(&store, session)?;
            let outcome = protect_outcome(&store, stores, session)?;
            render_plain_json(&outcome.recommendations, format)?;
            Ok(ExitCode::Success)
        }
        ProtectSub::Notify {
            alert,
            session,
            stores,
        } => {
            let store = rmp_store(stores)?;
            let rmp_session = require_rmp_session(&store, session)?;
            let outcome = protect_outcome(&store, stores, session)?;
            let alert_obj = outcome
                .alerts
                .iter()
                .find(|a| &a.alert_id == alert)
                .ok_or_else(|| {
                    CliError::Schema(format!("unknown alert '{alert}' in session '{session}'"))
                })?;
            if let Some(binding) = load_rmp_binding(&store, session) {
                if let Some(ledger) = binding.ledger.filter(|l| l.enabled) {
                    let mut ev = agenomic_rmp::RmpLedgerEvent::new(
                        agenomic_rmp::event_types::PROTECT_NOTIFICATION_ROUTED,
                        session,
                        &rmp_session.agent_id,
                        serde_json::json!({
                            "alert_id": alert_obj.alert_id,
                            "routes": alert_obj.routes,
                            "throttled": alert_obj.throttled,
                        }),
                    );
                    ev.evidence_refs = alert_obj.evidence_refs.clone();
                    crate::ledger::append_drafts(&ledger.dirs(), vec![ev.to_draft()])?;
                }
            }
            match format {
                OutputFormat::Json | OutputFormat::JsonPretty => {
                    render_plain_json(&alert_obj.routes, format)?
                }
                _ => {
                    println!(
                        "alert {} [{}] routes:",
                        alert_obj.alert_id,
                        alert_obj.severity.label()
                    );
                    for r in &alert_obj.routes {
                        println!("  {} → {}", r.channel, r.target);
                    }
                    if alert_obj.throttled {
                        println!("  (throttled: occurrence count exceeded the limit)");
                    }
                }
            }
            Ok(ExitCode::Success)
        }
    }
}
