//! Canonical exit codes for the `agentlock` binary.
//!
//! These values are part of the CLI's public contract. **Never change them**;
//! adding a new code is allowed, renumbering an existing one is a breaking
//! change.

/// Canonical exit codes.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    ValidationFailed = 1,
    InvalidUsage = 2,
    InternalError = 3,
    SecurityViolation = 4,
    CloudAuthFailed = 5,
    NetworkError = 6,
    ContractFailed = 7,
    DiffRiskExceeded = 8,
    AttestationVerificationFailed = 9,
    AtepIntegrityFailed = 10,
}

impl ExitCode {
    /// Returns the numeric exit code as `i32`.
    ///
    /// ```
    /// # use agentlock_core::exit::ExitCode;
    /// assert_eq!(ExitCode::Success.as_i32(), 0);
    /// assert_eq!(ExitCode::ContractFailed.as_i32(), 7);
    /// ```
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard: these numeric values are part of the public contract
    /// and must NEVER change.
    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::ValidationFailed.as_i32(), 1);
        assert_eq!(ExitCode::InvalidUsage.as_i32(), 2);
        assert_eq!(ExitCode::InternalError.as_i32(), 3);
        assert_eq!(ExitCode::SecurityViolation.as_i32(), 4);
        assert_eq!(ExitCode::CloudAuthFailed.as_i32(), 5);
        assert_eq!(ExitCode::NetworkError.as_i32(), 6);
        assert_eq!(ExitCode::ContractFailed.as_i32(), 7);
        assert_eq!(ExitCode::DiffRiskExceeded.as_i32(), 8);
        assert_eq!(ExitCode::AttestationVerificationFailed.as_i32(), 9);
        assert_eq!(ExitCode::AtepIntegrityFailed.as_i32(), 10);
    }
}
