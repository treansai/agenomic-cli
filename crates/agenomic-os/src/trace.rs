//! In-memory execution trace.
//!
//! The trace is the substrate replay and chain-of-custody will eventually
//! consume. At MVP it is a flat list of events captured during a single
//! launcher run; persistence and signing land in later PRs (see
//! `docs/BACKEND_GAPS.md`).

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Events emitted by the launcher during a single run, in chronological order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceEvent {
    PolicyApplied {
        at: DateTime<Utc>,
        required_env: Vec<String>,
        optional_env_set: Vec<String>,
        allow_network: Vec<String>,
        allow_fs_read: Vec<PathBuf>,
        allow_fs_write: Vec<PathBuf>,
    },
    ProcessStarted {
        at: DateTime<Utc>,
        command: String,
        args: Vec<String>,
        working_directory: PathBuf,
    },
    StdoutLine {
        at: DateTime<Utc>,
        line: String,
    },
    StderrLine {
        at: DateTime<Utc>,
        line: String,
    },
    ProcessExited {
        at: DateTime<Utc>,
        code: i32,
        duration_ms: u64,
    },
}

impl TraceEvent {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            TraceEvent::PolicyApplied { at, .. }
            | TraceEvent::ProcessStarted { at, .. }
            | TraceEvent::StdoutLine { at, .. }
            | TraceEvent::StderrLine { at, .. }
            | TraceEvent::ProcessExited { at, .. } => *at,
        }
    }
}

/// A run's trace plus its summary metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub events: Vec<TraceEvent>,
}

impl Trace {
    pub fn new(started_at: DateTime<Utc>) -> Self {
        Self {
            started_at,
            ended_at: None,
            events: Vec::new(),
        }
    }

    pub fn push(&mut self, event: TraceEvent) {
        if let TraceEvent::ProcessExited { at, .. } = &event {
            self.ended_at = Some(*at);
        }
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_updates_ended_at_only_on_exit() {
        let start = Utc::now();
        let mut t = Trace::new(start);
        t.push(TraceEvent::PolicyApplied {
            at: start,
            required_env: vec![],
            optional_env_set: vec![],
            allow_network: vec![],
            allow_fs_read: vec![],
            allow_fs_write: vec![],
        });
        assert!(t.ended_at.is_none());
        let end = Utc::now();
        t.push(TraceEvent::ProcessExited {
            at: end,
            code: 0,
            duration_ms: 1,
        });
        assert_eq!(t.ended_at, Some(end));
    }

    #[test]
    fn events_serialize_round_trip() {
        let now = Utc::now();
        let evt = TraceEvent::StdoutLine {
            at: now,
            line: "hello".into(),
        };
        let s = serde_json::to_string(&evt).unwrap();
        let back: TraceEvent = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, TraceEvent::StdoutLine { ref line, .. } if line == "hello"));
    }
}
