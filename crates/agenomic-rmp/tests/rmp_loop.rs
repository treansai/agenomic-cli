//! End-to-end test of the continuous safety loop:
//! Review → Monitor → Protect → Review, with the durable ledger enabled.

use std::time::Duration;

use agenomic_ledger_local::{
    FileKeyStore, FileLedgerStore, LedgerConfig, LedgerPipeline, LedgerStore,
};
use agenomic_rmp::{
    build_rmp_report, export_evidence, EvidenceExportOptions, MonitorConfig, MonitorEngine,
    ProtectEngine, ReviewEngine, ReviewInputs, RmpSession, RmpStore,
};
use agenomic_track::{
    DriftBaseline, HarnessInputs, SessionStatus, ToolMeta, TrackingEvent, TrackingEventType,
};

fn tool_event(session_id: &str, seq: u64, tool: &str) -> TrackingEvent {
    let mut ev = TrackingEvent::new(
        session_id,
        "agent://acme/claims",
        TrackingEventType::ToolCallCompleted,
        seq,
    );
    ev.tool = Some(ToolMeta {
        name: tool.into(),
        ..Default::default()
    });
    ev
}

#[test]
fn full_loop_with_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let store_dir = tmp.path().join("ledger/store");
    let wal_dir = tmp.path().join("ledger/wal");
    let dl_dir = tmp.path().join("ledger/dead-letter");
    let keys_dir = tmp.path().join("keys");
    let mut keys = FileKeyStore::open(&keys_dir).unwrap();
    keys.generate().unwrap();
    let (pipeline, _recovery) = LedgerPipeline::start(
        FileLedgerStore::open(&store_dir).unwrap(),
        keys,
        Some(&wal_dir),
        Some(&dl_dir),
        None,
        LedgerConfig::default(), // durable_low_latency
    )
    .unwrap();

    // ---- 1. Review (pre-release): clean pass -------------------------
    let review1 = ReviewEngine::default()
        .run(ReviewInputs {
            agent_id: "agent://acme/claims".into(),
            ..ReviewInputs::default()
        })
        .unwrap();
    assert_eq!(
        review1.recommendation,
        agenomic_rmp::ReleaseRecommendation::Approve
    );

    // ---- 2. Monitor (production): a drift incident --------------------
    let mut baseline = DriftBaseline::default();
    baseline.allowed_tools.insert("claims_db.lookup".into());
    let mut monitor = MonitorEngine::start(
        "agent://acme/claims",
        "production",
        baseline,
        MonitorConfig::default(),
        Some(Box::new(pipeline)),
    )
    .unwrap();
    let sid = monitor.session().tracking_session_id.clone();
    monitor
        .ingest(tool_event(&sid, 0, "claims_db.lookup"))
        .unwrap();
    monitor.ingest(tool_event(&sid, 1, "shell.exec")).unwrap();
    assert!(monitor.protect_triggered());
    let monitor_outcome = monitor
        .stop(&HarnessInputs::default(), SessionStatus::Completed)
        .unwrap();
    assert!(!monitor_outcome.findings.is_empty());
    assert!(!monitor_outcome.scenario_proposals.is_empty());

    // ---- 3. Protect: alerts, recommendations, action plans ------------
    let protect_outcome = ProtectEngine::default()
        .run(
            "agent://acme/claims",
            &monitor_outcome.findings,
            review1.risk_matrix.as_ref(),
        )
        .unwrap();
    assert!(!protect_outcome.alerts.is_empty());
    assert!(!protect_outcome.recommendations.is_empty());

    // ---- 4. Feedback: approve a proposal, re-run Review ---------------
    let mut proposal = monitor_outcome.scenario_proposals[0].clone();
    proposal.submit().unwrap();
    proposal.approve("reviewer@acme.test").unwrap();
    let review2 = ReviewEngine::default()
        .run(ReviewInputs {
            agent_id: "agent://acme/claims".into(),
            approved_proposals: vec![proposal.clone()],
            carried_findings: monitor_outcome.findings.clone(),
            evaluation_history: vec![review1.history_entry.clone()],
            ..ReviewInputs::default()
        })
        .unwrap();
    assert_eq!(review2.coverage.total_scenarios, 1, "enriched corpus");

    // ---- 5. Unified report + evidence ----------------------------------
    let mut session = RmpSession::new("agent://acme/claims", "production");
    session.ledger_enabled = true;
    let report = build_rmp_report(
        session,
        Some(review2),
        Some(monitor_outcome),
        Some(protect_outcome),
        None,
    )
    .unwrap();
    assert!(report.report_hash.is_some());
    // Production drift was critical → the loop blocks the release.
    assert_eq!(
        report.release_recommendation,
        agenomic_rmp::ReleaseRecommendation::Block
    );

    let out = tmp.path().join("evidence");
    let manifest = export_evidence(
        &out,
        &report,
        &EvidenceExportOptions {
            include_markdown: true,
        },
    )
    .unwrap();
    assert!(manifest
        .files
        .iter()
        .any(|f| f.path == "monitor_report.json"));
    assert!(manifest.files.iter().any(|f| f.path == "action_plan.md"));

    // ---- 6. Store persistence -----------------------------------------
    let store = RmpStore::new(tmp.path().join("rmp"));
    store.save_session(&report.session).unwrap();
    store
        .save_report(&report.session.session_id, &report)
        .unwrap();
    store
        .append_proposals(&report.session.session_id, &[proposal])
        .unwrap();
    assert!(store.exists(&report.session.session_id));

    // ---- 7. Ledger durability: events survived, chain verifies --------
    // The pipeline was moved into the monitor; re-open the store directly.
    std::thread::sleep(Duration::from_millis(200));
    let entries = FileLedgerStore::open(&store_dir)
        .unwrap()
        .read_all()
        .unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.event_type == "monitor.session.started"),
        "lifecycle event in ledger"
    );
    assert!(
        entries.iter().any(|e| e.event_type.starts_with("monitor.")
            && e.event_type.contains("detected")
            || e.event_type == "monitor.finding.created"),
        "finding events in ledger"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.event_type == "tool.call.completed"),
        "raw tracking events committed"
    );
}

#[test]
fn crash_recovery_replays_wal() {
    // Simulate a crash between the WAL append and sealing: write with a
    // worker that never runs, then restart the pipeline and observe the
    // recovery replaying WAL records into the ledger.
    let tmp = tempfile::tempdir().unwrap();
    let store_dir = tmp.path().join("ledger/store");
    let wal_dir = tmp.path().join("ledger/wal");
    let dl_dir = tmp.path().join("ledger/dead-letter");
    let keys_dir = tmp.path().join("keys");

    {
        let mut keys = FileKeyStore::open(&keys_dir).unwrap();
        keys.generate().unwrap();
        let config = LedgerConfig {
            // Slow worker so entries stay in the WAL when we "crash".
            worker_delay_ms: 60_000,
            ..LedgerConfig::default()
        };
        let (pipeline, _r) = LedgerPipeline::start(
            FileLedgerStore::open(&store_dir).unwrap(),
            FileKeyStore::open(&keys_dir).unwrap(),
            Some(&wal_dir),
            Some(&dl_dir),
            None,
            config,
        )
        .unwrap();
        let ev = agenomic_rmp::RmpLedgerEvent::new(
            agenomic_rmp::event_types::RMP_SESSION_STARTED,
            "rmp_crash",
            "agent://acme/claims",
            serde_json::json!({"environment": "production"}),
        );
        let outcome = agenomic_rmp::record_rmp_event(&pipeline, &ev).unwrap();
        assert!(matches!(
            outcome,
            agenomic_ledger_local::AppendOutcome::WalPersisted { .. }
        ));
        // Drop without flush/shutdown — the simulated crash.
        std::mem::forget(pipeline);
    }

    let (pipeline2, recovery) = LedgerPipeline::start(
        FileLedgerStore::open(&store_dir).unwrap(),
        FileKeyStore::open(&keys_dir).unwrap(),
        Some(&wal_dir),
        Some(&dl_dir),
        None,
        LedgerConfig::default(),
    )
    .unwrap();
    assert_eq!(recovery.replayed, 1, "WAL record replayed after crash");
    let entries = pipeline2.read_all().unwrap();
    assert!(entries
        .iter()
        .any(|e| e.event_type == "rmp.session.started"));
    pipeline2.shutdown(Duration::from_secs(5)).unwrap();
}
