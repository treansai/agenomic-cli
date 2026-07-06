//! Canonical exit codes for the `agenomic` binary.
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
    // agenomic-os taxonomy. See docs/agent-uri.md and crates/agenomic-os.
    OsUriInvalid = 11,
    OsResolverFailed = 12,
    OsBundleUnsigned = 13,
    OsContractInvalid = 14,
    OsLauncherFailed = 15,
    OsPolicyViolation = 16,
    OsPortFailed = 17,
    /// The Tool Boundary Gate held a tool call for human review
    /// (`RequireHumanApproval`). Distinct from a hard block (16): the effect is
    /// not denied, only paused pending a signed human decision.
    ToolBoundaryReviewRequired = 18,
    /// The cryptographic event ledger failed an integrity check (broken hash
    /// chain, invalid entry signature, tampering, or corrupted store). See
    /// `docs/plans/atep-ledger-plan.md`. Distinct from ATEP integrity (10):
    /// the ledger is the cross-producer event chain, not the ATEP stream.
    LedgerIntegrityFailed = 19,
}

impl ExitCode {
    /// Returns the numeric exit code as `i32`.
    ///
    /// ```
    /// # use agenomic_core::exit::ExitCode;
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
        assert_eq!(ExitCode::OsUriInvalid.as_i32(), 11);
        assert_eq!(ExitCode::OsResolverFailed.as_i32(), 12);
        assert_eq!(ExitCode::OsBundleUnsigned.as_i32(), 13);
        assert_eq!(ExitCode::OsContractInvalid.as_i32(), 14);
        assert_eq!(ExitCode::OsLauncherFailed.as_i32(), 15);
        assert_eq!(ExitCode::OsPolicyViolation.as_i32(), 16);
        assert_eq!(ExitCode::OsPortFailed.as_i32(), 17);
        assert_eq!(ExitCode::ToolBoundaryReviewRequired.as_i32(), 18);
        assert_eq!(ExitCode::LedgerIntegrityFailed.as_i32(), 19);
    }
}
