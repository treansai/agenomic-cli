//! End-to-end fixtures for the online-tracking engine.
//!
//! Each test drives a full session (start → ingest → harness → report) for a
//! sample "claims" agent and asserts the resulting findings, mirroring the
//! fixtures listed in the feature spec: a normal run, prompt drift, tool
//! permission drift, a repeated-tool loop, a no-progress loop, a forbidden
//! intent shift, a policy violation, and a valid JSON report export.

use agenomic_track::{
    build_report, AlertKind, AlertSeverity, DriftBaseline, FinalStatus, HarnessInputs,
    SessionStatus, ToolMeta, TrackingConfig, TrackingEngine, TrackingEvent, TrackingEventType,
    TrackingReport, TrackingSession,
};

/// A claims-agent baseline: two permitted tools, a pinned model, a known prompt.
fn claims_baseline() -> DriftBaseline {
    let doc = serde_json::json!({
        "runtime": { "model_provider": "openai", "model_id": "gpt-4o" },
        "tools": [{ "name": "classify_claim" }, { "name": "compensation_lookup" }],
        "policies": [{ "id": "no-final-decision-without-approval" }],
        "memory": { "runtime_memory_schema_version": "1.0.0" },
        "prompt_hash": "blake3:baseline-prompt",
    });
    DriftBaseline::from_genome_value(&doc)
}

fn session(config: TrackingConfig) -> TrackingSession {
    let mut s = TrackingSession::new("agent://treans/claims-agent", "production");
    s.release_id = Some("release_123".into());
    s.tracking_config = config;
    s
}

fn engine() -> TrackingEngine {
    TrackingEngine::new(session(TrackingConfig::default()), claims_baseline())
}

fn ev(t: TrackingEventType) -> TrackingEvent {
    TrackingEvent::new("", "agent://treans/claims-agent", t, 0)
}

fn tool(name: &str, input: &str) -> TrackingEvent {
    let mut e = ev(TrackingEventType::ToolCallCompleted);
    e.tool = Some(ToolMeta {
        name: name.into(),
        ..Default::default()
    });
    e.input_hash = Some(format!("blake3:{input}"));
    e
}

fn finalize(mut engine: TrackingEngine) -> (TrackingEngine, TrackingReport) {
    let harness = engine.run_harness(&HarnessInputs::default());
    engine.stop(SessionStatus::Completed);
    let report = build_report(&engine.session, &engine.events, &harness);
    (engine, report)
}

#[test]
fn fixture_normal_successful_run() {
    let mut e = engine();
    e.ingest({
        let mut s = ev(TrackingEventType::AgentStarted);
        s.redacted_preview = Some(serde_json::json!({ "claim_id": "[redacted]" }));
        s
    });
    e.ingest(tool("classify_claim", "h1"));
    e.ingest(tool("compensation_lookup", "h2"));
    e.ingest({
        let mut c = ev(TrackingEventType::AgentCompleted);
        c.redacted_preview = Some(serde_json::json!({ "decision": "[redacted]" }));
        c
    });

    let (_e, report) = finalize(e);
    assert_eq!(report.final_status, FinalStatus::Pass);
    assert_eq!(report.alert_counts.critical, 0);
    assert_eq!(report.event_count, 4);
    assert!(report.harness.passed);
}

#[test]
fn fixture_prompt_drift() {
    let mut e = engine();
    let mut m = ev(TrackingEventType::ModelCallCompleted);
    m.metadata = Some(serde_json::json!({ "prompt_hash": "blake3:tampered-prompt" }));
    e.ingest(m);
    let (_e, report) = finalize(e);
    assert!(report
        .drift_findings
        .iter()
        .any(|a| a.details.as_ref().unwrap()["drift_type"] == "prompt"));
}

#[test]
fn fixture_tool_permission_drift() {
    let mut e = engine();
    e.ingest(tool("shell.exec", "x"));
    let (_e, report) = finalize(e);
    assert_eq!(report.final_status, FinalStatus::Fail);
    let drift = report
        .drift_findings
        .iter()
        .find(|a| a.details.as_ref().unwrap()["drift_type"] == "tool_permission")
        .expect("tool_permission drift");
    assert_eq!(drift.severity, AlertSeverity::Critical);
    assert!(drift.blocks_release);
}

#[test]
fn fixture_repeated_tool_loop() {
    let mut cfg = TrackingConfig::default();
    cfg.loops.max_same_tool_calls = 2;
    let mut e = TrackingEngine::new(session(cfg), claims_baseline());
    for _ in 0..4 {
        e.ingest(tool("classify_claim", "same"));
    }
    let (_e, report) = finalize(e);
    assert!(report
        .loop_findings
        .iter()
        .any(|a| a.details.as_ref().unwrap()["loop_type"] == "repeated_tool_call"));
}

#[test]
fn fixture_workflow_no_progress_loop() {
    let mut cfg = TrackingConfig::default();
    cfg.loops.no_progress_window = 3;
    let mut e = TrackingEngine::new(session(cfg), claims_baseline());
    for i in 0..6 {
        let mut s = ev(TrackingEventType::AgentStepCompleted);
        s.sequence_number = i;
        s.output_hash = Some("blake3:stuck".into());
        e.ingest(s);
    }
    let (_e, report) = finalize(e);
    assert!(report
        .loop_findings
        .iter()
        .any(|a| a.details.as_ref().unwrap()["loop_type"] == "no_progress"));
}

#[test]
fn fixture_forbidden_intent_shift() {
    let mut cfg = TrackingConfig::default();
    cfg.intent.forbidden_intents = vec!["exfiltrate_data".into()];
    let mut e = TrackingEngine::new(session(cfg), claims_baseline());
    let mut i = ev(TrackingEventType::IntentDetected);
    i.intent = Some("exfiltrate_data".into());
    e.ingest(i);
    let (_e, report) = finalize(e);
    let intent = report
        .intent_findings
        .iter()
        .find(|a| a.details.as_ref().unwrap()["intent_issue"] == "forbidden_intent")
        .expect("forbidden_intent finding");
    assert_eq!(intent.severity, AlertSeverity::Critical);
    assert_eq!(report.final_status, FinalStatus::Fail);
}

#[test]
fn fixture_policy_violation() {
    let mut e = engine();
    let mut p = ev(TrackingEventType::PolicyEvaluated);
    p.policy_result = Some(agenomic_track::PolicyResult {
        policy_id: Some("no-final-decision-without-approval".into()),
        outcome: "deny".into(),
        denies: vec!["final decision without human approval".into()],
    });
    e.ingest(p);
    let (_e, report) = finalize(e);
    assert!(report
        .policy_violations
        .iter()
        .any(|a| a.kind == AlertKind::Policy && a.severity == AlertSeverity::Critical));
    assert_eq!(report.final_status, FinalStatus::Fail);
    assert!(!report.harness.passed);
}

#[test]
fn fixture_valid_report_export() {
    let mut e = engine();
    e.ingest(tool("classify_claim", "h1"));
    let (_e, report) = finalize(e);

    // JSON export round-trips and the embedded report hash verifies.
    let json = serde_json::to_string_pretty(&report).unwrap();
    let back: TrackingReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert_eq!(back.report_hash.as_ref().unwrap(), &back.compute_hash());
    assert_eq!(back.report_version, "agenomic.track/v0.1");
}

#[test]
fn fixture_events_are_hash_chained_and_tamper_evident() {
    let mut e = engine();
    e.ingest(tool("classify_claim", "h1"));
    e.ingest(tool("compensation_lookup", "h2"));
    // every stored event verifies, and they form a chain
    assert!(e.events.iter().all(|ev| ev.hash_is_valid()));
    assert_eq!(e.events[1].prev_event_hash, e.events[0].event_hash);
}
