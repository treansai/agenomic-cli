//! Audit-ready evidence export for an RMP session.
//!
//! Produces the file set described in `docs/rmp/evidence.md`:
//!
//! ```text
//! <out>/
//!   rmp_report.json          the unified report
//!   review_report.json       when Review ran
//!   monitor_report.json      when Monitor ran (tracking report inside)
//!   protect_report.json      when Protect ran
//!   risk_matrix.json         when present
//!   test_scenarios.json      the scenario corpus
//!   proposals.json           scenario enrichment proposals
//!   action_plan.md           rendered action plans
//!   recommendations.md       rendered recommendations
//!   manifest.json            file list + hashes (EvidenceManifest)
//! ```
//!
//! When the session ran with the ledger enabled, the caller additionally
//! exports the ledger proof bundle next to these files via
//! `agenomic evidence export --include-ledger` (reusing
//! [`agenomic_ledger_local::assemble_bundle`] — not duplicated here).

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::{io_at, CliError, CliResult};

use crate::report::{render_markdown, RmpReport};

/// Options for an evidence export.
#[derive(Debug, Clone, Default)]
pub struct EvidenceExportOptions {
    /// Also write `rmp_report.md` (human-readable summary).
    pub include_markdown: bool,
}

/// One exported file with its content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub path: String,
    /// `blake3:`-prefixed hash of the file bytes.
    pub hash: String,
    pub bytes: u64,
}

/// The manifest written as `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub manifest_version: String,
    pub session_id: String,
    pub agent_id: String,
    pub generated_at: DateTime<Utc>,
    pub files: Vec<EvidenceFile>,
    /// Hash of the RMP report the bundle is anchored to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rmp_report_hash: Option<String>,
    pub ledger_included: bool,
}

/// Manifest version constant.
pub const EVIDENCE_MANIFEST_VERSION: &str = "agenomic.rmp.evidence/v0.1";

fn write_file(
    out_dir: &Path,
    name: &str,
    bytes: &[u8],
    files: &mut Vec<EvidenceFile>,
) -> CliResult<()> {
    let path = out_dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }
    std::fs::write(&path, bytes).map_err(|e| io_at(&path, e))?;
    files.push(EvidenceFile {
        path: name.to_string(),
        hash: format!("blake3:{}", blake3::hash(bytes).to_hex()),
        bytes: bytes.len() as u64,
    });
    Ok(())
}

fn json_bytes<T: Serialize>(value: &T, what: &str) -> CliResult<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|e| CliError::Internal(format!("serialize {what}: {e}")))
}

/// Export the evidence bundle for a session into `out_dir`. Returns the
/// manifest (also written as `manifest.json`).
pub fn export_evidence(
    out_dir: &Path,
    report: &RmpReport,
    options: &EvidenceExportOptions,
) -> CliResult<EvidenceManifest> {
    std::fs::create_dir_all(out_dir).map_err(|e| io_at(out_dir, e))?;
    let mut files: Vec<EvidenceFile> = Vec::new();

    write_file(
        out_dir,
        "rmp_report.json",
        &json_bytes(report, "rmp report")?,
        &mut files,
    )?;
    if let Some(review) = &report.review {
        write_file(
            out_dir,
            "review_report.json",
            &json_bytes(review, "review report")?,
            &mut files,
        )?;
        if let Some(matrix) = &review.risk_matrix {
            write_file(
                out_dir,
                "risk_matrix.json",
                &json_bytes(matrix, "risk matrix")?,
                &mut files,
            )?;
        }
        if let Some(replay) = &review.replay_report {
            write_file(
                out_dir,
                "replay_reports/review_replay.json",
                &json_bytes(replay, "replay report")?,
                &mut files,
            )?;
        }
    }
    if let Some(monitor) = &report.monitor {
        write_file(
            out_dir,
            "monitor_report.json",
            &json_bytes(monitor, "monitor report")?,
            &mut files,
        )?;
        write_file(
            out_dir,
            "tracking_report.json",
            &json_bytes(&monitor.report, "tracking report")?,
            &mut files,
        )?;
    }
    if let Some(protect) = &report.protect {
        write_file(
            out_dir,
            "protect_report.json",
            &json_bytes(protect, "protect report")?,
            &mut files,
        )?;
        // Rendered action plans + recommendations for auditors.
        let mut plans_md = String::from("# Action plans\n\n");
        for plan in &protect.action_plans {
            plans_md.push_str(&format!(
                "## {} ({})\n\n",
                plan.title,
                plan.severity.label()
            ));
            for step in &plan.steps {
                plans_md.push_str(&format!(
                    "{}. [{}] {}{}\n",
                    step.order,
                    step.phase,
                    step.title,
                    if step.requires_human_approval {
                        " **(human approval required)**"
                    } else {
                        ""
                    }
                ));
            }
            plans_md.push('\n');
        }
        write_file(out_dir, "action_plan.md", plans_md.as_bytes(), &mut files)?;

        let mut recs_md = String::from("# Recommendations\n\n");
        for rec in &protect.recommendations {
            recs_md.push_str(&format!(
                "- [{}] **{}** — {}{}\n",
                rec.kind.label(),
                rec.title,
                rec.rationale,
                if rec.requires_human_approval {
                    " *(requires human approval)*"
                } else {
                    ""
                }
            ));
        }
        write_file(
            out_dir,
            "recommendations.md",
            recs_md.as_bytes(),
            &mut files,
        )?;
    }
    if !report.scenario_proposals.is_empty() {
        write_file(
            out_dir,
            "proposals.json",
            &json_bytes(&report.scenario_proposals, "proposals")?,
            &mut files,
        )?;
    }
    // Scenario corpus executed by Review.
    if let Some(review) = &report.review {
        write_file(
            out_dir,
            "test_scenarios.json",
            &json_bytes(&review.session.scenario_ids, "scenario ids")?,
            &mut files,
        )?;
    }
    if options.include_markdown {
        write_file(
            out_dir,
            "rmp_report.md",
            render_markdown(report).as_bytes(),
            &mut files,
        )?;
    }
    if let Some(proof) = &report.ledger_proof {
        write_file(
            out_dir,
            "ledger_proof.json",
            &json_bytes(proof, "ledger proof")?,
            &mut files,
        )?;
    }

    let manifest = EvidenceManifest {
        manifest_version: EVIDENCE_MANIFEST_VERSION.into(),
        session_id: report.session.session_id.clone(),
        agent_id: report.session.agent_id.clone(),
        generated_at: Utc::now(),
        files,
        rmp_report_hash: report.report_hash.clone(),
        ledger_included: report.ledger_proof.is_some(),
    };
    let manifest_bytes = json_bytes(&manifest, "manifest")?;
    let path = out_dir.join("manifest.json");
    std::fs::write(&path, &manifest_bytes).map_err(|e| io_at(&path, e))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::build_rmp_report;
    use crate::types::RmpSession;

    #[test]
    fn export_writes_manifest_and_report() {
        let tmp = tempfile::tempdir().unwrap();
        let session = RmpSession::new("agent://acme/claims", "production");
        let report = build_rmp_report(session, None, None, None, None).unwrap();
        let manifest = export_evidence(
            tmp.path(),
            &report,
            &EvidenceExportOptions {
                include_markdown: true,
            },
        )
        .unwrap();
        assert!(tmp.path().join("rmp_report.json").exists());
        assert!(tmp.path().join("rmp_report.md").exists());
        assert!(tmp.path().join("manifest.json").exists());
        assert!(manifest.files.iter().any(|f| f.path == "rmp_report.json"));
        for f in &manifest.files {
            assert!(f.hash.starts_with("blake3:"));
        }
        assert!(!manifest.ledger_included);
    }
}
