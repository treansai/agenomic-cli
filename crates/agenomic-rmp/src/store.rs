//! Filesystem persistence for RMP sessions, mirroring the tracking
//! [`agenomic_track::SessionStore`] layout.
//!
//! ```text
//! <root>/                          (default <cwd>/.agenomic/rmp)
//!   <session_id>/
//!     session.json                 RmpSession
//!     review.json                  ReviewOutcome
//!     monitor.json                 MonitorOutcome
//!     protect.json                 ProtectOutcome
//!     report.json                  RmpReport
//!     proposals.jsonl              ScenarioEnrichmentProposal (append)
//!     findings.jsonl               Finding (append)
//!     scenarios/<scenario_id>.json TestScenario corpus
//!     risk-matrix.json             RiskMatrix
//! ```
//!
//! Files are written atomically (temp + rename). Historical records are
//! never mutated in place: proposals and findings are append-only JSONL;
//! status changes append a new full record whose latest occurrence wins.

use std::io::Write;
use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult};

use crate::enrich::ScenarioEnrichmentProposal;
use crate::monitor::MonitorOutcome;
use crate::protect::ProtectOutcome;
use crate::report::RmpReport;
use crate::review::ReviewOutcome;
use crate::risk::RiskMatrix;
use crate::scenario::TestScenario;
use crate::types::{Finding, RmpSession};

/// Filesystem store rooted at a directory.
#[derive(Debug, Clone)]
pub struct RmpStore {
    root: PathBuf,
}

impl RmpStore {
    /// Open a store rooted at `root` (created lazily on first write).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The default root under a base directory: `<base>/.agenomic/rmp`.
    pub fn default_root(base: &Path) -> PathBuf {
        base.join(".agenomic").join("rmp")
    }

    /// Directory of one session.
    pub fn session_dir(&self, session_id: &str) -> PathBuf {
        self.root.join(session_id)
    }

    /// Whether a session exists.
    pub fn exists(&self, session_id: &str) -> bool {
        self.session_dir(session_id).join("session.json").exists()
    }

    /// List all session ids (directory names), sorted.
    pub fn list_sessions(&self) -> CliResult<Vec<String>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(|e| io_at(&self.root, e))? {
            let entry = entry.map_err(|e| io_at(&self.root, e))?;
            if entry.path().join("session.json").exists() {
                out.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Persist the session descriptor.
    pub fn save_session(&self, session: &RmpSession) -> CliResult<()> {
        self.write_json(&session.session_id, "session.json", session)
    }

    /// Load the session descriptor.
    pub fn load_session(&self, session_id: &str) -> CliResult<RmpSession> {
        self.read_json(session_id, "session.json")
    }

    /// Persist a stage outcome.
    pub fn save_review(&self, session_id: &str, outcome: &ReviewOutcome) -> CliResult<()> {
        self.write_json(session_id, "review.json", outcome)
    }

    /// Load the review outcome, if the stage ran.
    pub fn load_review(&self, session_id: &str) -> CliResult<Option<ReviewOutcome>> {
        self.read_json_opt(session_id, "review.json")
    }

    /// Persist the monitor outcome.
    pub fn save_monitor(&self, session_id: &str, outcome: &MonitorOutcome) -> CliResult<()> {
        self.write_json(session_id, "monitor.json", outcome)
    }

    /// Load the monitor outcome, if the stage ran.
    pub fn load_monitor(&self, session_id: &str) -> CliResult<Option<MonitorOutcome>> {
        self.read_json_opt(session_id, "monitor.json")
    }

    /// Persist the protect outcome.
    pub fn save_protect(&self, session_id: &str, outcome: &ProtectOutcome) -> CliResult<()> {
        self.write_json(session_id, "protect.json", outcome)
    }

    /// Load the protect outcome, if the stage ran.
    pub fn load_protect(&self, session_id: &str) -> CliResult<Option<ProtectOutcome>> {
        self.read_json_opt(session_id, "protect.json")
    }

    /// Persist the unified report.
    pub fn save_report(&self, session_id: &str, report: &RmpReport) -> CliResult<()> {
        self.write_json(session_id, "report.json", report)
    }

    /// Load the unified report, if generated.
    pub fn load_report(&self, session_id: &str) -> CliResult<Option<RmpReport>> {
        self.read_json_opt(session_id, "report.json")
    }

    /// Persist the risk matrix.
    pub fn save_risk_matrix(&self, session_id: &str, matrix: &RiskMatrix) -> CliResult<()> {
        self.write_json(session_id, "risk-matrix.json", matrix)
    }

    /// Load the risk matrix, if present.
    pub fn load_risk_matrix(&self, session_id: &str) -> CliResult<Option<RiskMatrix>> {
        self.read_json_opt(session_id, "risk-matrix.json")
    }

    /// Append proposals (append-only; a later record for the same
    /// `proposal_id` supersedes earlier ones).
    pub fn append_proposals(
        &self,
        session_id: &str,
        proposals: &[ScenarioEnrichmentProposal],
    ) -> CliResult<()> {
        self.append_jsonl(session_id, "proposals.jsonl", proposals)
    }

    /// Load proposals with last-record-wins semantics, preserving first-seen
    /// order.
    pub fn load_proposals(&self, session_id: &str) -> CliResult<Vec<ScenarioEnrichmentProposal>> {
        let records: Vec<ScenarioEnrichmentProposal> =
            self.read_jsonl(session_id, "proposals.jsonl")?;
        let mut order: Vec<String> = Vec::new();
        let mut latest: std::collections::HashMap<String, ScenarioEnrichmentProposal> =
            std::collections::HashMap::new();
        for record in records {
            if !latest.contains_key(&record.proposal_id) {
                order.push(record.proposal_id.clone());
            }
            latest.insert(record.proposal_id.clone(), record);
        }
        Ok(order.into_iter().filter_map(|id| latest.remove(&id)).collect())
    }

    /// Append findings (append-only).
    pub fn append_findings(&self, session_id: &str, findings: &[Finding]) -> CliResult<()> {
        self.append_jsonl(session_id, "findings.jsonl", findings)
    }

    /// Load all recorded findings.
    pub fn load_findings(&self, session_id: &str) -> CliResult<Vec<Finding>> {
        self.read_jsonl(session_id, "findings.jsonl")
    }

    /// Save a scenario into the session's corpus.
    pub fn save_scenario(&self, session_id: &str, scenario: &TestScenario) -> CliResult<()> {
        crate::scenario::validate_scenario(scenario)?;
        self.write_json(
            session_id,
            &format!("scenarios/{}.json", scenario.scenario_id),
            scenario,
        )
    }

    /// Load the scenario corpus.
    pub fn load_scenarios(&self, session_id: &str) -> CliResult<Vec<TestScenario>> {
        let dir = self.session_dir(session_id).join("scenarios");
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| io_at(&dir, e))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
            let scenario: TestScenario = serde_json::from_str(&text)
                .map_err(|e| CliError::Schema(format!("{}: {e}", path.display())))?;
            out.push(scenario);
        }
        Ok(out)
    }

    // ---- primitives ------------------------------------------------------

    fn write_json<T: serde::Serialize>(
        &self,
        session_id: &str,
        rel: &str,
        value: &T,
    ) -> CliResult<()> {
        let path = self.session_dir(session_id).join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
        }
        let json = serde_json::to_string_pretty(value)
            .map_err(|e| CliError::Internal(format!("serialize {rel}: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes()).map_err(|e| io_at(&tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
        Ok(())
    }

    fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        session_id: &str,
        rel: &str,
    ) -> CliResult<T> {
        let path = self.session_dir(session_id).join(rel);
        let text = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
        serde_json::from_str(&text)
            .map_err(|e| CliError::Schema(format!("{}: {e}", path.display())))
    }

    fn read_json_opt<T: serde::de::DeserializeOwned>(
        &self,
        session_id: &str,
        rel: &str,
    ) -> CliResult<Option<T>> {
        let path = self.session_dir(session_id).join(rel);
        if !path.exists() {
            return Ok(None);
        }
        self.read_json(session_id, rel).map(Some)
    }

    fn append_jsonl<T: serde::Serialize>(
        &self,
        session_id: &str,
        rel: &str,
        values: &[T],
    ) -> CliResult<()> {
        if values.is_empty() {
            return Ok(());
        }
        let path = self.session_dir(session_id).join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_at(&path, e))?;
        for value in values {
            let line = serde_json::to_string(value)
                .map_err(|e| CliError::Internal(format!("serialize {rel}: {e}")))?;
            writeln!(file, "{line}").map_err(|e| io_at(&path, e))?;
        }
        file.sync_all().map_err(|e| io_at(&path, e))?;
        Ok(())
    }

    fn read_jsonl<T: serde::de::DeserializeOwned>(
        &self,
        session_id: &str,
        rel: &str,
    ) -> CliResult<Vec<T>> {
        let path = self.session_dir(session_id).join(rel);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: T = serde_json::from_str(line).map_err(|e| {
                CliError::Schema(format!("{} line {}: {e}", path.display(), i + 1))
            })?;
            out.push(value);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{ScenarioSource, TestScenario};
    use agenomic_core::Severity;

    #[test]
    fn session_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RmpStore::new(tmp.path());
        let session = RmpSession::new("agent://acme/claims", "production");
        store.save_session(&session).unwrap();
        let loaded = store.load_session(&session.session_id).unwrap();
        assert_eq!(loaded.agent_id, session.agent_id);
        assert_eq!(store.list_sessions().unwrap(), vec![session.session_id]);
    }

    #[test]
    fn proposals_last_record_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RmpStore::new(tmp.path());
        let finding = Finding::new(
            "monitor",
            "s",
            "agent://a/b",
            crate::types::FindingKind::Loop,
            Severity::Low,
            "t",
            "m",
        );
        let mut p = crate::enrich::proposals_from_findings(&[finding]).remove(0);
        store.append_proposals("sess", &[p.clone()]).unwrap();
        p.submit().unwrap();
        store.append_proposals("sess", &[p.clone()]).unwrap();
        let loaded = store.load_proposals("sess").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, crate::enrich::EnrichmentStatus::PendingReview);
    }

    #[test]
    fn scenario_corpus_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RmpStore::new(tmp.path());
        let scenario = TestScenario::new(
            "agent://acme/claims",
            "payout bounds",
            ScenarioSource::Manual,
            Severity::High,
        );
        store.save_scenario("sess", &scenario).unwrap();
        let loaded = store.load_scenarios("sess").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].scenario_id, scenario.scenario_id);
    }
}
