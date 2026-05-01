//! Severity, validation level, and output format enums.

use serde::{Deserialize, Serialize};

/// Severity classification for issues, contract violations, and diff changes.
///
/// Ordered from least to most severe; `Ord` follows that ordering so that
/// `report.iter().max()` yields the highest severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns a short human-readable label for the severity.
    ///
    /// ```
    /// # use agentlock_core::severity::Severity;
    /// assert_eq!(Severity::Critical.label(), "critical");
    /// ```
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Validation strictness levels accepted by `agentlock validate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// Required files exist and parse.
    Basic,
    /// Basic plus schema validation and cross-references.
    Strict,
    /// Strict plus security scan and "no warnings ≥ High" rule.
    Ci,
}

/// Output format selector for CLI commands that emit reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    JsonPretty,
    Yaml,
    Sarif,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_serializes_snake_case() {
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(s, "\"critical\"");
    }
}
