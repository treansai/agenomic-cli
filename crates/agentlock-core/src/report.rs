//! Validation report and issue types shared across crates.

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// A single validation issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Stable diagnostic code (e.g. `agentlock::bundle::missing_required_file`).
    pub code: String,
    pub severity: Severity,
    pub message: String,
    /// Path the issue applies to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Short hint for fixing the issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// URL to documentation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// Aggregated validation outcome.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ValidationReport {
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
    #[serde(default)]
    pub info: Vec<ValidationIssue>,
}

impl ValidationReport {
    /// Returns the highest severity present across errors/warnings/info, or
    /// `None` if the report is empty.
    ///
    /// ```
    /// # use agentlock_core::report::{ValidationReport, ValidationIssue};
    /// # use agentlock_core::severity::Severity;
    /// let mut r = ValidationReport::default();
    /// r.warnings.push(ValidationIssue {
    ///     code: "x".into(), severity: Severity::Medium,
    ///     message: "m".into(), path: None, hint: None, doc: None,
    /// });
    /// assert_eq!(r.highest_severity(), Some(Severity::Medium));
    /// ```
    pub fn highest_severity(&self) -> Option<Severity> {
        self.errors
            .iter()
            .chain(self.warnings.iter())
            .chain(self.info.iter())
            .map(|i| i.severity)
            .max()
    }

    /// Returns `true` if the report contains an issue at or above `threshold`.
    ///
    /// ```
    /// # use agentlock_core::report::ValidationReport;
    /// # use agentlock_core::severity::Severity;
    /// let r = ValidationReport::default();
    /// assert!(!r.fail_at_or_above(Severity::High));
    /// ```
    pub fn fail_at_or_above(&self, threshold: Severity) -> bool {
        self.highest_severity().is_some_and(|s| s >= threshold)
    }

    /// Push an error, set `valid = false`.
    pub fn push_error(&mut self, issue: ValidationIssue) {
        self.valid = false;
        self.errors.push(issue);
    }

    /// Push a warning. Does not change `valid`.
    pub fn push_warning(&mut self, issue: ValidationIssue) {
        self.warnings.push(issue);
    }

    /// Push an info-level note. Does not change `valid`.
    pub fn push_info(&mut self, issue: ValidationIssue) {
        self.info.push(issue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(sev: Severity) -> ValidationIssue {
        ValidationIssue {
            code: "test::issue".into(),
            severity: sev,
            message: "msg".into(),
            path: None,
            hint: None,
            doc: None,
        }
    }

    #[test]
    fn highest_severity_picks_max() {
        let mut r = ValidationReport::default();
        r.push_warning(issue(Severity::Low));
        r.push_error(issue(Severity::High));
        r.push_info(issue(Severity::Medium));
        assert_eq!(r.highest_severity(), Some(Severity::High));
    }

    #[test]
    fn empty_report_has_no_severity() {
        let r = ValidationReport::default();
        assert_eq!(r.highest_severity(), None);
        assert!(!r.fail_at_or_above(Severity::Info));
    }

    #[test]
    fn push_error_invalidates() {
        let mut r = ValidationReport {
            valid: true,
            ..Default::default()
        };
        r.push_error(issue(Severity::Critical));
        assert!(!r.valid);
    }
}
