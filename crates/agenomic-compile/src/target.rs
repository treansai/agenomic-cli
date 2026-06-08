//! Compile targets: the runtime frameworks a genome can be lowered to.

use std::fmt;
use std::str::FromStr;

use crate::error::CompileError;

/// A runtime framework the genome can be compiled to.
///
/// The on-disk directory name is `<label>.compiled` (e.g. `langgraph.compiled`),
/// matching the `agent-bundle` `runtime/` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompileTarget {
    /// FastAPI service calling the model provider SDK directly. No framework.
    Plain,
    /// A LangGraph `StateGraph` with one node per skill.
    LangGraph,
    /// A CrewAI crew with one task per skill.
    CrewAi,
}

impl CompileTarget {
    /// All targets, in deterministic order. Used by `--all`.
    pub const ALL: [CompileTarget; 3] = [
        CompileTarget::Plain,
        CompileTarget::LangGraph,
        CompileTarget::CrewAi,
    ];

    /// Stable label used in CLI args and on disk.
    pub fn label(self) -> &'static str {
        match self {
            CompileTarget::Plain => "plain",
            CompileTarget::LangGraph => "langgraph",
            CompileTarget::CrewAi => "crewai",
        }
    }

    /// Directory name emitted under `runtime/` (`<label>.compiled`).
    pub fn dir_name(self) -> String {
        format!("{}.compiled", self.label())
    }
}

impl fmt::Display for CompileTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for CompileTarget {
    type Err = CompileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "plain" | "fastapi" => Ok(CompileTarget::Plain),
            "langgraph" => Ok(CompileTarget::LangGraph),
            "crewai" | "crew" => Ok(CompileTarget::CrewAi),
            other => Err(CompileError::UnknownTarget(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_labels() {
        for t in CompileTarget::ALL {
            assert_eq!(CompileTarget::from_str(t.label()).unwrap(), t);
        }
    }

    #[test]
    fn aliases_and_case() {
        assert_eq!(
            CompileTarget::from_str("FastAPI").unwrap(),
            CompileTarget::Plain
        );
        assert_eq!(
            CompileTarget::from_str("crew").unwrap(),
            CompileTarget::CrewAi
        );
    }

    #[test]
    fn dir_name_matches_bundle_layout() {
        assert_eq!(CompileTarget::LangGraph.dir_name(), "langgraph.compiled");
    }

    #[test]
    fn unknown_rejected() {
        assert!(CompileTarget::from_str("autogen").is_err());
    }
}
