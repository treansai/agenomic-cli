//! Alerts produced by the online-tracking detectors.
//!
//! Every detector (drift, loop, intent, harness) emits a uniform [`Alert`].
//! Alerts carry their own three-level [`AlertSeverity`] (`info`, `warning`,
//! `critical`) — the vocabulary the product surfaces to operators — and map
//! losslessly onto the platform-wide [`agenomic_core::Severity`] used by the
//! contract/diff/replay layers via [`AlertSeverity::from_platform`].

use serde::{Deserialize, Serialize};

use agenomic_core::Severity;

/// Operator-facing severity of a tracking alert.
///
/// Ordered least-to-most severe so `alerts.iter().map(|a| a.severity).max()`
/// yields the worst alert in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Project a platform [`Severity`] onto the tracking severity scale.
    ///
    /// `info`/`low` collapse to `info`, `medium`/`high` to `warning`, and
    /// `critical` stays `critical`.
    ///
    /// ```
    /// # use agenomic_track::{AlertSeverity};
    /// # use agenomic_core::Severity;
    /// assert_eq!(AlertSeverity::from_platform(Severity::High), AlertSeverity::Warning);
    /// assert_eq!(AlertSeverity::from_platform(Severity::Critical), AlertSeverity::Critical);
    /// ```
    pub fn from_platform(s: Severity) -> Self {
        match s {
            Severity::Info | Severity::Low => Self::Info,
            Severity::Medium | Severity::High => Self::Warning,
            Severity::Critical => Self::Critical,
        }
    }

    /// Map back onto a platform [`Severity`] so tracking alerts can feed the
    /// shared `--fail-on` / exit-code machinery.
    pub fn to_platform(self) -> Severity {
        match self {
            Self::Info => Severity::Info,
            Self::Warning => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

/// The category of behaviour an alert reports on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    Drift,
    Loop,
    Intent,
    Harness,
    Policy,
    Security,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Drift => "drift",
            Self::Loop => "loop",
            Self::Intent => "intent",
            Self::Harness => "harness",
            Self::Policy => "policy",
            Self::Security => "security",
        }
    }
}

/// A single alert raised during a tracking session.
///
/// `details` carries kind-specific structured evidence (e.g. `drift_type` +
/// `mode`, or `loop_type` + `pattern` + `count`) so the wire format stays
/// stable even as detectors grow new fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub alert_id: String,
    pub session_id: String,
    pub kind: AlertKind,
    pub severity: AlertSeverity,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub title: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<serde_json::Value>,
    #[serde(default)]
    pub evidence_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
    pub blocks_release: bool,
    pub requires_human_review: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Alert {
    /// Construct a new alert with a freshly minted ULID and `created_at = now`.
    pub fn new(
        session_id: impl Into<String>,
        kind: AlertKind,
        severity: AlertSeverity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            alert_id: ulid::Ulid::new().to_string(),
            session_id: session_id.into(),
            kind,
            severity,
            created_at: chrono::Utc::now(),
            title: title.into(),
            message: message.into(),
            observed: None,
            expected: None,
            evidence_event_ids: Vec::new(),
            recommended_action: None,
            blocks_release: matches!(severity, AlertSeverity::Critical),
            requires_human_review: matches!(severity, AlertSeverity::Critical),
            details: None,
        }
    }

    /// Builder: attach evidence event IDs.
    pub fn with_evidence(mut self, ids: impl IntoIterator<Item = String>) -> Self {
        self.evidence_event_ids.extend(ids);
        self
    }

    /// Builder: attach observed/expected values.
    pub fn with_observed_expected(
        mut self,
        observed: Option<serde_json::Value>,
        expected: Option<serde_json::Value>,
    ) -> Self {
        self.observed = observed;
        self.expected = expected;
        self
    }

    /// Builder: attach a recommended next action.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.recommended_action = Some(action.into());
        self
    }

    /// Builder: override the release-blocking / human-review gating flags.
    pub fn with_gating(mut self, blocks_release: bool, requires_human_review: bool) -> Self {
        self.blocks_release = blocks_release;
        self.requires_human_review = requires_human_review;
        self
    }

    /// Builder: attach structured, kind-specific detail.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_round_trips_through_platform() {
        for s in [
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Critical,
        ] {
            let platform = s.to_platform();
            let back = AlertSeverity::from_platform(platform);
            assert_eq!(s, back);
        }
    }

    #[test]
    fn critical_alert_blocks_and_requires_review_by_default() {
        let a = Alert::new("s1", AlertKind::Drift, AlertSeverity::Critical, "t", "m");
        assert!(a.blocks_release);
        assert!(a.requires_human_review);
    }

    #[test]
    fn info_alert_is_non_blocking() {
        let a = Alert::new("s1", AlertKind::Loop, AlertSeverity::Info, "t", "m");
        assert!(!a.blocks_release);
        assert!(!a.requires_human_review);
    }

    #[test]
    fn severity_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&AlertSeverity::Warning).unwrap(),
            "\"warning\""
        );
    }
}
