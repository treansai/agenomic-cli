//! The unified RMP report: one document tying Review, Monitor, and Protect
//! together for a session, with a content hash and optional ledger proof.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::Severity;

use crate::enrich::ScenarioEnrichmentProposal;
use crate::monitor::MonitorOutcome;
use crate::protect::ProtectOutcome;
use crate::review::{ReleaseRecommendation, ReviewOutcome};
use crate::types::RmpSession;

/// Version stamped on RMP reports.
pub const RMP_REPORT_VERSION: &str = "agenomic.rmp.report/v0.1";

/// Domain separator for the report hash.
const REPORT_DOMAIN: &[u8] = b"AGENOMIC-RMP-REPORT-v1\0";

/// The unified Review · Monitor · Protect report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmpReport {
    pub report_version: String,
    pub session: RmpSession,
    /// 0.0 ..= 1.0 — the release risk score after all three loops.
    pub final_risk_score: f64,
    pub release_recommendation: ReleaseRecommendation,
    /// Findings across all loops, worst first, capped at the source data.
    pub finding_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<MonitorOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect: Option<ProtectOutcome>,
    /// Enrichment proposals from every stage, deduplicated by id.
    #[serde(default)]
    pub scenario_proposals: Vec<ScenarioEnrichmentProposal>,
    /// Deterministic evidence references collected across the loops.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Ledger proof block (`agenomic.ledger.proof/v0.1`) when the session
    /// ran with the ledger enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_proof: Option<serde_json::Value>,
    /// `verified` | `unverified` | `failed` — ledger verification status.
    pub verification_status: String,
    pub generated_at: DateTime<Utc>,
    /// `blake3:`-prefixed hash of the report body (computed with this field
    /// unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_hash: Option<String>,
}

impl RmpReport {
    /// Compute the canonical content hash of this report with the
    /// `report_hash` field cleared.
    pub fn compute_hash(&self) -> agenomic_core::CliResult<String> {
        let mut clone = self.clone();
        clone.report_hash = None;
        let json = serde_json::to_vec(&clone)
            .map_err(|e| agenomic_core::CliError::Internal(format!("serialize report: {e}")))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REPORT_DOMAIN);
        hasher.update(&json);
        Ok(format!("blake3:{}", hasher.finalize().to_hex()))
    }
}

/// Assemble the unified report from whatever stages ran. The report hash is
/// stamped; the ledger proof can be attached by the caller before hashing
/// via the `ledger_proof` parameter.
pub fn build_rmp_report(
    session: RmpSession,
    review: Option<ReviewOutcome>,
    monitor: Option<MonitorOutcome>,
    protect: Option<ProtectOutcome>,
    ledger_proof: Option<serde_json::Value>,
) -> agenomic_core::CliResult<RmpReport> {
    let mut finding_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut evidence_refs: Vec<String> = Vec::new();
    let mut proposals: Vec<ScenarioEnrichmentProposal> = Vec::new();

    let mut worst_severity: Option<Severity> = None;
    let count = |findings: &[crate::types::Finding],
                 finding_counts: &mut BTreeMap<String, u64>,
                 evidence_refs: &mut Vec<String>,
                 worst: &mut Option<Severity>| {
        for f in findings {
            *finding_counts
                .entry(f.kind.label().to_string())
                .or_default() += 1;
            evidence_refs.extend(f.evidence_refs.iter().cloned());
            *worst = Some(worst.map_or(f.severity, |w| w.max(f.severity)));
        }
    };

    if let Some(r) = &review {
        count(
            &r.findings,
            &mut finding_counts,
            &mut evidence_refs,
            &mut worst_severity,
        );
    }
    if let Some(m) = &monitor {
        count(
            &m.findings,
            &mut finding_counts,
            &mut evidence_refs,
            &mut worst_severity,
        );
        proposals.extend(m.scenario_proposals.iter().cloned());
        if let Some(hash) = &m.report.report_hash {
            evidence_refs.push(format!("track-report:{hash}"));
        }
    }
    if let Some(p) = &protect {
        count(
            &p.anomaly_findings,
            &mut finding_counts,
            &mut evidence_refs,
            &mut worst_severity,
        );
        proposals.extend(p.scenario_proposals.iter().cloned());
        for alert in &p.alerts {
            evidence_refs.extend(alert.evidence_refs.iter().cloned());
        }
    }
    evidence_refs.sort();
    evidence_refs.dedup();
    {
        let mut seen = std::collections::HashSet::new();
        proposals.retain(|p| seen.insert(p.proposal_id.clone()));
    }

    // Final risk: review's matrix score when present, escalated by the
    // worst production finding.
    let review_risk = review.as_ref().map(|r| r.release_risk_score).unwrap_or(0.0);
    let severity_floor = match worst_severity {
        Some(Severity::Critical) => 0.8,
        Some(Severity::High) => 0.6,
        Some(Severity::Medium) => 0.35,
        Some(Severity::Low) => 0.15,
        _ => 0.0,
    };
    let final_risk_score = review_risk.max(severity_floor);

    let release_recommendation = if let Some(r) = &review {
        // Escalate the review recommendation when production evidence is worse.
        match (r.recommendation, worst_severity) {
            (_, Some(Severity::Critical)) => ReleaseRecommendation::Block,
            (ReleaseRecommendation::Approve, Some(Severity::High)) => {
                ReleaseRecommendation::HumanReviewRequired
            }
            (rec, _) => rec,
        }
    } else {
        match worst_severity {
            Some(Severity::Critical) => ReleaseRecommendation::Block,
            Some(Severity::High) => ReleaseRecommendation::HumanReviewRequired,
            Some(_) => ReleaseRecommendation::ApproveWithConditions,
            None => ReleaseRecommendation::Approve,
        }
    };

    let verification_status = match &ledger_proof {
        Some(p) => {
            if p.get("verification_passed").and_then(|v| v.as_bool()) == Some(true) {
                "verified".to_string()
            } else {
                "failed".to_string()
            }
        }
        None => "unverified".to_string(),
    };

    let mut report = RmpReport {
        report_version: RMP_REPORT_VERSION.into(),
        session,
        final_risk_score,
        release_recommendation,
        finding_counts,
        review,
        monitor,
        protect,
        scenario_proposals: proposals,
        evidence_refs,
        ledger_proof,
        verification_status,
        generated_at: Utc::now(),
        report_hash: None,
    };
    report.report_hash = Some(report.compute_hash()?);
    Ok(report)
}

/// Render the report as operator-facing Markdown.
pub fn render_markdown(report: &RmpReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# RMP Report — {}\n\n", report.session.agent_id));
    md.push_str(&format!(
        "- Session: `{}`\n- Environment: {}\n- Release: {}\n- Genome: {}\n\
         - Final risk score: **{:.2}**\n- Recommendation: **{}**\n- Ledger: {}\n\n",
        report.session.session_id,
        report.session.environment,
        report.session.release_id.as_deref().unwrap_or("-"),
        report.session.genome_hash.as_deref().unwrap_or("-"),
        report.final_risk_score,
        report.release_recommendation.label(),
        report.verification_status,
    ));
    if !report.finding_counts.is_empty() {
        md.push_str("## Findings\n\n");
        for (kind, count) in &report.finding_counts {
            md.push_str(&format!("- {kind}: {count}\n"));
        }
        md.push('\n');
    }
    if let Some(review) = &report.review {
        md.push_str(&format!(
            "## Review\n\n- Result: {}\n- Score: {:.2}\n- Coverage: {:.0}%\n\n",
            review.result.label(),
            review.score,
            review.coverage.coverage_ratio * 100.0
        ));
    }
    if let Some(monitor) = &report.monitor {
        md.push_str(&format!(
            "## Monitor\n\n- Events: {}\n- Critical alerts: {}\n- Protect triggered: {}\n\n",
            monitor.report.event_count,
            monitor.report.alert_counts.critical,
            monitor.protect_triggered
        ));
    }
    if let Some(protect) = &report.protect {
        md.push_str(&format!(
            "## Protect\n\n- Alerts: {}\n- Recommendations: {}\n- Action plans: {}\n\n",
            protect.alerts.len(),
            protect.recommendations.len(),
            protect.action_plans.len()
        ));
    }
    if !report.scenario_proposals.is_empty() {
        md.push_str(&format!(
            "## Scenario enrichment proposals ({})\n\n",
            report.scenario_proposals.len()
        ));
        for p in &report.scenario_proposals {
            md.push_str(&format!(
                "- `{}` [{}] {} (status: {})\n",
                p.proposal_id,
                p.severity.label(),
                p.proposed_scenario.title,
                p.status.label()
            ));
        }
        md.push('\n');
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RmpSession;

    #[test]
    fn empty_report_recommends_approve() {
        let session = RmpSession::new("agent://acme/claims", "production");
        let report = build_rmp_report(session, None, None, None, None).unwrap();
        assert_eq!(
            report.release_recommendation,
            ReleaseRecommendation::Approve
        );
        assert_eq!(report.verification_status, "unverified");
        assert!(report
            .report_hash
            .as_deref()
            .unwrap()
            .starts_with("blake3:"));
    }

    #[test]
    fn hash_is_stable_and_self_verifying() {
        let session = RmpSession::new("agent://acme/claims", "production");
        let report = build_rmp_report(session, None, None, None, None).unwrap();
        let recomputed = report.compute_hash().unwrap();
        assert_eq!(report.report_hash.as_deref(), Some(recomputed.as_str()));
    }

    #[test]
    fn ledger_proof_sets_verification_status() {
        let session = RmpSession::new("agent://acme/claims", "production");
        let proof = serde_json::json!({"verification_passed": true});
        let report = build_rmp_report(session, None, None, None, Some(proof)).unwrap();
        assert_eq!(report.verification_status, "verified");
    }

    #[test]
    fn markdown_renders() {
        let session = RmpSession::new("agent://acme/claims", "production");
        let report = build_rmp_report(session, None, None, None, None).unwrap();
        let md = render_markdown(&report);
        assert!(md.contains("# RMP Report"));
        assert!(md.contains("approve"));
    }
}
