//! Local, offline session storage.
//!
//! A [`SessionStore`] persists sessions under a root directory, one directory
//! per session:
//!
//! ```text
//! <root>/<session_id>/
//!   session.json     # the TrackingSession (status, config, summary, alerts)
//!   events.jsonl     # append-only event log, one TrackingEvent per line
//!   report.json      # the last exported TrackingReport (optional)
//! ```
//!
//! This is the offline counterpart to cloud storage; the wire shapes are
//! identical so a session can move between the two.

use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult};

use crate::drift::DriftBaseline;
use crate::event::TrackingEvent;
use crate::report::TrackingReport;
use crate::session::TrackingSession;

/// A filesystem-backed store for tracking sessions.
#[derive(Debug, Clone)]
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    /// Open (or lazily create) a store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory holding one session's artifacts.
    pub fn session_dir(&self, session_id: &str) -> PathBuf {
        self.root.join(session_id)
    }

    fn session_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join("session.json")
    }

    fn events_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join("events.jsonl")
    }

    fn report_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join("report.json")
    }

    fn baseline_path(&self, session_id: &str) -> PathBuf {
        self.session_dir(session_id).join("baseline.json")
    }

    /// Persist the drift baseline derived at session start so the stateless CLI
    /// can rebuild detector state on each subsequent event.
    pub fn save_baseline(&self, session_id: &str, baseline: &DriftBaseline) -> CliResult<()> {
        let dir = self.session_dir(session_id);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        let path = self.baseline_path(session_id);
        let bytes = serde_json::to_vec_pretty(baseline)
            .map_err(|e| CliError::Internal(format!("serialize baseline: {e}")))?;
        std::fs::write(&path, &bytes).map_err(|e| io_at(&path, e))
    }

    /// Load the drift baseline (an empty baseline if none was persisted).
    pub fn load_baseline(&self, session_id: &str) -> CliResult<DriftBaseline> {
        let path = self.baseline_path(session_id);
        if !path.is_file() {
            return Ok(DriftBaseline::default());
        }
        let bytes = std::fs::read(&path).map_err(|e| io_at(&path, e))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CliError::Schema(format!("parse baseline {session_id}: {e}")))
    }

    /// True if a session with this id already exists on disk.
    pub fn exists(&self, session_id: &str) -> bool {
        self.session_path(session_id).is_file()
    }

    /// Persist a session document (creating its directory if needed).
    pub fn save_session(&self, session: &TrackingSession) -> CliResult<()> {
        let dir = self.session_dir(&session.session_id);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        let path = self.session_path(&session.session_id);
        let bytes = serde_json::to_vec_pretty(session)
            .map_err(|e| CliError::Internal(format!("serialize session: {e}")))?;
        std::fs::write(&path, &bytes).map_err(|e| io_at(&path, e))
    }

    /// Load a session document.
    pub fn load_session(&self, session_id: &str) -> CliResult<TrackingSession> {
        let path = self.session_path(session_id);
        let bytes = std::fs::read(&path).map_err(|e| io_at(&path, e))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CliError::Schema(format!("parse session {session_id}: {e}")))
    }

    /// Append events to the session's append-only log.
    pub fn append_events(&self, session_id: &str, events: &[TrackingEvent]) -> CliResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let dir = self.session_dir(session_id);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        let path = self.events_path(session_id);
        let mut buf = String::new();
        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| CliError::Internal(format!("serialize event: {e}")))?;
            buf.push_str(&line);
            buf.push('\n');
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_at(&path, e))?;
        f.write_all(buf.as_bytes()).map_err(|e| io_at(&path, e))
    }

    /// Load the full event log for a session (empty if none recorded yet).
    pub fn load_events(&self, session_id: &str) -> CliResult<Vec<TrackingEvent>> {
        let path = self.events_path(session_id);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let ev: TrackingEvent = serde_json::from_str(line)
                .map_err(|e| CliError::Schema(format!("parse event line {}: {e}", i + 1)))?;
            out.push(ev);
        }
        Ok(out)
    }

    /// Write a report artifact for a session.
    pub fn save_report(&self, report: &TrackingReport) -> CliResult<()> {
        let dir = self.session_dir(&report.session_id);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        let path = self.report_path(&report.session_id);
        let bytes = serde_json::to_vec_pretty(report)
            .map_err(|e| CliError::Internal(format!("serialize report: {e}")))?;
        std::fs::write(&path, &bytes).map_err(|e| io_at(&path, e))
    }

    /// List the session IDs known to this store, sorted.
    pub fn list_sessions(&self) -> CliResult<Vec<String>> {
        let mut ids = Vec::new();
        if !self.root.is_dir() {
            return Ok(ids);
        }
        for entry in std::fs::read_dir(&self.root).map_err(|e| io_at(&self.root, e))? {
            let entry = entry.map_err(|e| io_at(&self.root, e))?;
            if entry.path().is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                if self.exists(&id) {
                    ids.push(id);
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// The default store root: `<base>/.agenomic/tracking`.
    pub fn default_root(base: &Path) -> PathBuf {
        base.join(".agenomic").join("tracking")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::TrackingEventType;
    use crate::session::TrackingSession;
    use tempfile::tempdir;

    #[test]
    fn round_trips_session_and_events() {
        let dir = tempdir().unwrap();
        let store = SessionStore::new(dir.path());
        let session = TrackingSession::new("agent://acme/claims", "production");
        let id = session.session_id.clone();
        store.save_session(&session).unwrap();
        assert!(store.exists(&id));

        let mut e1 = TrackingEvent::new(
            &id,
            "agent://acme/claims",
            TrackingEventType::AgentStarted,
            0,
        );
        e1.link_after(None);
        let mut e2 = TrackingEvent::new(
            &id,
            "agent://acme/claims",
            TrackingEventType::AgentCompleted,
            1,
        );
        e2.link_after(e1.event_hash.clone());
        store.append_events(&id, &[e1.clone()]).unwrap();
        store.append_events(&id, &[e2.clone()]).unwrap();

        let loaded = store.load_session(&id).unwrap();
        assert_eq!(loaded.session_id, id);
        let events = store.load_events(&id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], e1);
        assert_eq!(events[1], e2);

        let ids = store.list_sessions().unwrap();
        assert_eq!(ids, vec![id]);
    }

    #[test]
    fn missing_events_is_empty() {
        let dir = tempdir().unwrap();
        let store = SessionStore::new(dir.path());
        assert!(store.load_events("nope").unwrap().is_empty());
        assert!(store.list_sessions().unwrap().is_empty());
    }
}
