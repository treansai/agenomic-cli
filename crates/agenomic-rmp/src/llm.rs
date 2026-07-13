//! Optional LLM assistance, strictly behind a provider interface.
//!
//! RMP is deterministic by default: **no provider is wired in and no model
//! is ever called unless the host explicitly injects one.** Suggestions are
//! advisory — they never overwrite deterministic findings or evidence, and
//! high-impact changes still require human approval regardless of origin.
//!
//! Inputs passed to a provider must already be redacted
//! ([`crate::redact::redact_json`]); providers receive summaries and hashes,
//! never raw production payloads or secrets.

use serde::{Deserialize, Serialize};

/// What kind of assistance is being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    IntentClassification,
    RecommendationExplanation,
    ScenarioGeneration,
    RiskSummary,
    AuditNarrative,
    RootCauseExplanation,
}

/// An advisory suggestion returned by a provider. Always carries the
/// deterministic evidence references it was derived from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub kind: SuggestionKind,
    pub text: String,
    /// Confidence as reported by the provider, 0.0 ..= 1.0. Advisory only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// Deterministic references the suggestion is grounded in.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Provider identifier (never a key).
    pub provider: String,
}

/// Provider interface for optional LLM assistance. Implementations live in
/// host layers (CLI enrich provider, cloud); this crate ships only the
/// no-op default.
pub trait SuggestionProvider: Send + Sync {
    /// Provider identifier for audit trails, e.g. `anthropic:claude-x`.
    fn id(&self) -> &str;

    /// Produce a suggestion for the given kind and redacted JSON context.
    /// Returning `Ok(None)` means "no suggestion" and is always safe.
    fn suggest(
        &self,
        kind: SuggestionKind,
        redacted_context: &serde_json::Value,
    ) -> agenomic_core::CliResult<Option<Suggestion>>;
}

/// The default provider: offline, never suggests anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSuggestionProvider;

impl SuggestionProvider for NoopSuggestionProvider {
    fn id(&self) -> &str {
        "noop"
    }

    fn suggest(
        &self,
        _kind: SuggestionKind,
        _redacted_context: &serde_json::Value,
    ) -> agenomic_core::CliResult<Option<Suggestion>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_never_suggests() {
        let p = NoopSuggestionProvider;
        let out = p
            .suggest(SuggestionKind::RiskSummary, &serde_json::json!({}))
            .unwrap();
        assert!(out.is_none());
    }
}
