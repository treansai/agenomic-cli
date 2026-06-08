//! `port`: propose an `execution:` block for an existing codebase.
//!
//! Reuses [`agenomic_detect::run`] for the language/manifest layer, then
//! maps the detected runtime onto the portable execution contract introduced
//! in spec 0.2. The proposal is informational — `port` never writes files,
//! never modifies the source tree, and never claims behavioural equivalence
//! with the original agent. The caller is expected to review gaps and
//! integrate the proposed block by hand.

mod proposal;

pub use proposal::{propose, Gap, GapSeverity, PortProposal};
