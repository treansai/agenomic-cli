//! The online-tracking session: the durable, serializable record of a tracked
//! production run.
//!
//! A [`TrackingSession`] binds an agent release/genome to a stream of live
//! events and the alerts raised against it. It is the tracking analogue of a
//! replay [`agenomic_replay_local::ReplayReport`] — same naming conventions,
//! same `chrono` timestamps, same snake_case wire format — but it is *open*
//! (mutated as events arrive) until `status` leaves [`SessionStatus::Active`].

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, AlertSeverity};
use crate::drift::DriftConfig;
use crate::intent::IntentConfig;
use crate::loops::LoopConfig;

/// The lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    Cancelled,
}

impl SessionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// Which kind of reference the live behaviour is tracked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    Genome,
    ReplayReport,
    BehaviorContract,
    ReleaseAttestation,
}

/// A reference to the baseline a session is tracked against.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BaselineRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<BaselineKind>,
    /// A path, URI, or hash locating the baseline artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_report_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_id: Option<String>,
}

/// The full tracking configuration for a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackingConfig {
    #[serde(default)]
    pub drift: DriftConfig,
    #[serde(default)]
    pub loops: LoopConfig,
    #[serde(default)]
    pub intent: IntentConfig,
    /// Severity at or above which the harness fails the session.
    #[serde(default = "default_fail_on")]
    pub fail_on: AlertSeverity,
}

fn default_fail_on() -> AlertSeverity {
    AlertSeverity::Critical
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            drift: DriftConfig::default(),
            loops: LoopConfig::default(),
            intent: IntentConfig::default(),
            fail_on: default_fail_on(),
        }
    }
}

/// Rolling summary metrics for a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SessionSummary {
    pub event_count: u64,
    pub alert_count: u64,
    pub drift_count: u64,
    pub loop_count: u64,
    pub intent_count: u64,
    pub harness_failures: u64,
    pub info: u64,
    pub warning: u64,
    pub critical: u64,
}

impl SessionSummary {
    /// Worst severity seen, or `None` for a clean session.
    pub fn max_severity(&self) -> Option<AlertSeverity> {
        if self.critical > 0 {
            Some(AlertSeverity::Critical)
        } else if self.warning > 0 {
            Some(AlertSeverity::Warning)
        } else if self.info > 0 {
            Some(AlertSeverity::Info)
        } else {
            None
        }
    }
}

/// Schema/spec version stamped on every session document.
pub const SESSION_SPEC_VERSION: &str = "agenomic/v0.3";

/// The durable record of one online-tracking session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackingSession {
    pub spec_version: String,
    pub session_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    pub environment: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: SessionStatus,
    pub tracking_config: TrackingConfig,
    #[serde(default)]
    pub baseline: BaselineRef,
    #[serde(default)]
    pub summary: SessionSummary,
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

impl TrackingSession {
    /// Start a new active session. The `session_id` is a fresh ULID.
    pub fn new(agent_id: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            spec_version: SESSION_SPEC_VERSION.to_string(),
            session_id: ulid::Ulid::new().to_string(),
            agent_id: agent_id.into(),
            bundle_id: None,
            genome_hash: None,
            release_id: None,
            environment: environment.into(),
            started_at: chrono::Utc::now(),
            ended_at: None,
            status: SessionStatus::Active,
            tracking_config: TrackingConfig::default(),
            baseline: BaselineRef::default(),
            summary: SessionSummary::default(),
            alerts: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_active_and_versioned() {
        let s = TrackingSession::new("agent://acme/claims", "production");
        assert_eq!(s.status, SessionStatus::Active);
        assert!(!s.status.is_terminal());
        assert_eq!(s.spec_version, SESSION_SPEC_VERSION);
        assert_eq!(s.environment, "production");
    }

    #[test]
    fn session_round_trips_json() {
        let s = TrackingSession::new("agent://acme/claims", "production");
        let json = serde_json::to_string(&s).unwrap();
        let back: TrackingSession = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn summary_max_severity() {
        let mut sum = SessionSummary::default();
        assert_eq!(sum.max_severity(), None);
        sum.warning = 2;
        assert_eq!(sum.max_severity(), Some(AlertSeverity::Warning));
        sum.critical = 1;
        assert_eq!(sum.max_severity(), Some(AlertSeverity::Critical));
    }
}
