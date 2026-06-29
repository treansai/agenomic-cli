//! The Online Tracking Report.
//!
//! [`TrackingReport`] is the exportable, signable roll-up of a session — the
//! tracking analogue of [`agenomic_replay_local::ReplayReport`]. It is JSON
//! first, carries a `report_version`, aggregates alerts by severity and kind,
//! embeds the harness result, and content-addresses itself with a
//! `report_hash` over its canonical form.

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::event::TrackingEvent;
use crate::harness::HarnessResult;
use crate::session::{SessionStatus, TrackingSession};

/// Report schema/version identifier.
pub const REPORT_VERSION: &str = "agenomic.track/v0.1";

/// The overall verdict of a tracking session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalStatus {
    Pass,
    Warn,
    Fail,
}

impl FinalStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// Alert counts grouped by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AlertCounts {
    pub info: u64,
    pub warning: u64,
    pub critical: u64,
}

/// Alert counts grouped by kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AlertsByKind {
    pub drift: u64,
    #[serde(rename = "loop")]
    pub loop_: u64,
    pub intent: u64,
    pub harness: u64,
    pub policy: u64,
    pub security: u64,
}

/// The full, exportable online-tracking report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackingReport {
    pub report_version: String,
    pub session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    pub environment: String,
    pub status: SessionStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub event_count: u64,
    pub alert_counts: AlertCounts,
    pub alerts_by_kind: AlertsByKind,
    pub drift_findings: Vec<Alert>,
    pub loop_findings: Vec<Alert>,
    pub intent_findings: Vec<Alert>,
    pub policy_violations: Vec<Alert>,
    pub harness: HarnessResult,
    pub summary_metrics: crate::session::SessionSummary,
    pub recommendations: Vec<String>,
    pub final_status: FinalStatus,
    pub evidence_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_hash: Option<String>,
}

const REPORT_DOMAIN: &[u8] = b"AGENOMIC-TRACK-REPORT-v1\0";

/// Build a [`TrackingReport`] from a finalized session, its event log, and the
/// harness result.
pub fn build_report(
    session: &TrackingSession,
    events: &[TrackingEvent],
    harness: &HarnessResult,
) -> TrackingReport {
    // Aggregate over the union of detector alerts (on the session) and the
    // harness alerts (contract / policy / approval / security) from this run.
    let all_alerts: Vec<Alert> = session
        .alerts
        .iter()
        .cloned()
        .chain(harness.alerts.iter().cloned())
        .collect();

    let by_kind = |k: AlertKind| -> Vec<Alert> {
        all_alerts.iter().filter(|a| a.kind == k).cloned().collect()
    };

    let mut counts = AlertCounts::default();
    let mut kinds = AlertsByKind::default();
    for a in &all_alerts {
        match a.severity {
            AlertSeverity::Info => counts.info += 1,
            AlertSeverity::Warning => counts.warning += 1,
            AlertSeverity::Critical => counts.critical += 1,
        }
        match a.kind {
            AlertKind::Drift => kinds.drift += 1,
            AlertKind::Loop => kinds.loop_ += 1,
            AlertKind::Intent => kinds.intent += 1,
            AlertKind::Harness => kinds.harness += 1,
            AlertKind::Policy => kinds.policy += 1,
            AlertKind::Security => kinds.security += 1,
        }
    }

    let final_status = if counts.critical > 0 || !harness.passed {
        FinalStatus::Fail
    } else if counts.warning > 0 {
        FinalStatus::Warn
    } else {
        FinalStatus::Pass
    };

    // Deduplicated recommendations from blocking/review-worthy alerts.
    let mut recommendations: Vec<String> = Vec::new();
    for a in &all_alerts {
        if let Some(action) = &a.recommended_action {
            if (a.blocks_release || a.requires_human_review)
                && !recommendations.contains(action)
            {
                recommendations.push(action.clone());
            }
        }
    }
    if recommendations.is_empty() && matches!(final_status, FinalStatus::Pass) {
        recommendations.push("No action required; behaviour matched the tracked baseline.".into());
    }

    // Deduplicated union of all evidence event IDs.
    let mut evidence: Vec<String> = Vec::new();
    for a in &all_alerts {
        for e in &a.evidence_event_ids {
            if !evidence.contains(e) {
                evidence.push(e.clone());
            }
        }
    }

    let mut report = TrackingReport {
        report_version: REPORT_VERSION.to_string(),
        session_id: session.session_id.clone(),
        agent_id: session.agent_id.clone(),
        bundle_id: session.bundle_id.clone(),
        release_id: session.release_id.clone(),
        genome_hash: session.genome_hash.clone(),
        environment: session.environment.clone(),
        status: session.status,
        started_at: session.started_at,
        ended_at: session.ended_at,
        generated_at: chrono::Utc::now(),
        event_count: events.len() as u64,
        alert_counts: counts,
        alerts_by_kind: kinds,
        drift_findings: by_kind(AlertKind::Drift),
        loop_findings: by_kind(AlertKind::Loop),
        intent_findings: by_kind(AlertKind::Intent),
        policy_violations: by_kind(AlertKind::Policy),
        harness: harness.clone(),
        summary_metrics: session.summary.clone(),
        recommendations,
        final_status,
        evidence_event_ids: evidence,
        report_hash: None,
    };
    report.report_hash = Some(report.compute_hash());
    report
}

impl TrackingReport {
    /// Content hash over the canonical report (excluding `report_hash` itself).
    pub fn compute_hash(&self) -> String {
        let mut bare = self.clone();
        bare.report_hash = None;
        let body = serde_json::to_vec(&bare).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(REPORT_DOMAIN);
        hasher.update(&body);
        format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Alert;
    use crate::harness::HarnessResult;
    use crate::session::TrackingSession;

    fn harness_pass() -> HarnessResult {
        HarnessResult {
            passed: true,
            checks: vec![],
            alerts: vec![],
        }
    }

    #[test]
    fn clean_session_reports_pass() {
        let session = TrackingSession::new("agent://a/b", "production");
        let r = build_report(&session, &[], &harness_pass());
        assert_eq!(r.final_status, FinalStatus::Pass);
        assert_eq!(r.report_version, REPORT_VERSION);
        assert!(r.report_hash.is_some());
        assert_eq!(r.compute_hash(), r.report_hash.clone().unwrap());
    }

    #[test]
    fn critical_alert_reports_fail() {
        let mut session = TrackingSession::new("agent://a/b", "production");
        let mut a = Alert::new(
            session.session_id.clone(),
            AlertKind::Drift,
            AlertSeverity::Critical,
            "t",
            "m",
        );
        a.evidence_event_ids.push("e1".into());
        a.recommended_action = Some("roll back".into());
        session.alerts.push(a);
        let r = build_report(&session, &[], &harness_pass());
        assert_eq!(r.final_status, FinalStatus::Fail);
        assert_eq!(r.alert_counts.critical, 1);
        assert_eq!(r.drift_findings.len(), 1);
        assert!(r.recommendations.contains(&"roll back".to_string()));
        assert!(r.evidence_event_ids.contains(&"e1".to_string()));
    }

    #[test]
    fn warning_session_reports_warn() {
        let mut session = TrackingSession::new("agent://a/b", "production");
        session.alerts.push(Alert::new(
            session.session_id.clone(),
            AlertKind::Loop,
            AlertSeverity::Warning,
            "t",
            "m",
        ));
        let r = build_report(&session, &[], &harness_pass());
        assert_eq!(r.final_status, FinalStatus::Warn);
        assert_eq!(r.alerts_by_kind.loop_, 1);
    }

    #[test]
    fn report_round_trips_json() {
        let session = TrackingSession::new("agent://a/b", "production");
        let r = build_report(&session, &[], &harness_pass());
        let json = serde_json::to_string(&r).unwrap();
        let back: TrackingReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
