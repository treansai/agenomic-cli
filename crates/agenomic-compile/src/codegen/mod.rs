//! Per-target code generators.
//!
//! Each generator turns a [`Genome`] into a [`CompiledArtifact`] — a
//! deterministic, self-contained source tree. The generators are intentionally
//! dependency-light: they build strings directly (no template engine) so the
//! output is byte-stable for a given genome and easy to diff in review.
//!
//! Generated adapters wire up the model, the system prompt, and the declared
//! skills. MCP **tool bindings are emitted as typed stubs** with the declared
//! server/version recorded — turning them into live calls is the integration
//! step the operator owns. This is faithful to a v0.1 "compile": the control
//! flow and contracts are generated; the side-effecting tool transport is not
//! invented.

mod common;
mod crewai;
mod docker;
mod langgraph;
mod plain;
mod wasm;

use crate::artifact::CompiledArtifact;
use crate::genome::Genome;
use crate::target::CompileTarget;

pub(crate) use common::embed_prompts;

/// Generate the source tree for `target` from `genome` (without the manifest;
/// the caller attaches that after embedding prompts).
pub(crate) fn generate(genome: &Genome, target: CompileTarget) -> CompiledArtifact {
    match target {
        CompileTarget::Plain => plain::generate(genome),
        CompileTarget::LangGraph => langgraph::generate(genome),
        CompileTarget::CrewAi => crewai::generate(genome),
        CompileTarget::Docker => docker::generate(genome),
        CompileTarget::Wasm => wasm::generate(genome),
    }
}
