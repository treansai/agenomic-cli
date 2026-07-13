//! Risk matrix: typed risk items, impact drivers, agent-type assessment,
//! and deterministic release-risk scoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agenomic_core::Severity;

/// Version stamped on risk matrices.
pub const RISK_MATRIX_VERSION: &str = "agenomic.rmp.risk-matrix/v0.1";

/// A driver that scales the impact of a risk (business, regulatory,
/// safety, …). `weight` is 0.0 ..= 1.0.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImpactDriver {
    /// e.g. `financial`, `regulatory`, `safety`, `reputation`, `privacy`.
    pub driver: String,
    /// 0.0 (negligible) ..= 1.0 (maximal).
    pub weight: f64,
    #[serde(default)]
    pub rationale: String,
}

/// Classification of the agent's autonomy/coupling profile, which scales
/// the overall risk posture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentTypeAssessment {
    /// `assistant` | `workflow` | `autonomous` | `tool` | `orchestrator`.
    pub agent_type: String,
    /// 0.0 ..= 1.0 — how independently the agent acts.
    pub autonomy_level: f64,
    /// Whether the agent can cause external side effects (payments, emails…).
    pub external_side_effects: bool,
    /// Whether a human approves consequential actions.
    pub human_in_the_loop: bool,
    #[serde(default)]
    pub rationale: String,
}

impl AgentTypeAssessment {
    /// Deterministically classify from an agent id card.
    ///
    /// ```
    /// use agenomic_rmp::cards::AgentIdCard;
    /// use agenomic_rmp::risk::AgentTypeAssessment;
    /// let mut card = AgentIdCard::new("agent://acme/claims", "Claims");
    /// card.autonomous = true;
    /// card.allowed_tools.push("payments.refund".into());
    /// let a = AgentTypeAssessment::from_id_card(&card);
    /// assert!(a.autonomy_level > 0.5);
    /// ```
    pub fn from_id_card(card: &crate::cards::AgentIdCard) -> Self {
        let external_side_effects = card.allowed_tools.iter().any(|t| {
            let t = t.to_ascii_lowercase();
            [
                "payment", "email", "send", "write", "delete", "refund", "post", "exec",
            ]
            .iter()
            .any(|k| t.contains(k))
        });
        let human_in_the_loop = !card.human_approval_required_for.is_empty();
        let autonomy_level = match (card.autonomous, human_in_the_loop) {
            (true, false) => 0.9,
            (true, true) => 0.6,
            (false, false) => 0.4,
            (false, true) => 0.2,
        };
        let agent_type = if !card.agent_type.is_empty() {
            card.agent_type.clone()
        } else if card.autonomous {
            "autonomous".to_string()
        } else {
            "assistant".to_string()
        };
        Self {
            agent_type,
            autonomy_level,
            external_side_effects,
            human_in_the_loop,
            rationale: "deterministic classification from agent id card".into(),
        }
    }

    /// Risk multiplier in 1.0 ..= 2.0 derived from autonomy and side effects.
    pub fn risk_multiplier(&self) -> f64 {
        let mut m = 1.0 + self.autonomy_level * 0.5;
        if self.external_side_effects {
            m += 0.3;
        }
        if !self.human_in_the_loop {
            m += 0.2;
        }
        m.min(2.0)
    }
}

/// A secondary risk associated with a primary risk item (e.g. a privacy
/// risk associated with a tool-misuse risk).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssociatedRisk {
    /// Id of the related risk item (may be in another matrix).
    pub risk_id: String,
    /// `amplifies` | `enables` | `correlates`.
    pub relation: String,
    #[serde(default)]
    pub note: String,
}

/// One risk in the matrix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskItem {
    pub risk_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// `behavior` | `security` | `privacy` | `compliance` | `operational`.
    #[serde(default)]
    pub category: String,
    /// Probability of occurrence, 0.0 ..= 1.0.
    pub likelihood: f64,
    /// Impact if it occurs, 0.0 ..= 1.0.
    pub impact: f64,
    #[serde(default)]
    pub impact_drivers: Vec<ImpactDriver>,
    #[serde(default)]
    pub associated_risks: Vec<AssociatedRisk>,
    /// Scenario ids covering this risk.
    #[serde(default)]
    pub covered_by_scenarios: Vec<String>,
    /// Finding ids observed for this risk (production evidence).
    #[serde(default)]
    pub observed_findings: Vec<String>,
    /// `open` | `mitigated` | `accepted`.
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

fn default_status() -> String {
    "open".into()
}

impl RiskItem {
    /// Create a risk item with a fresh ULID id.
    pub fn new(title: impl Into<String>, likelihood: f64, impact: f64) -> Self {
        Self {
            risk_id: format!("risk_{}", ulid::Ulid::new()),
            title: title.into(),
            description: String::new(),
            category: String::new(),
            likelihood: likelihood.clamp(0.0, 1.0),
            impact: impact.clamp(0.0, 1.0),
            impact_drivers: Vec::new(),
            associated_risks: Vec::new(),
            covered_by_scenarios: Vec::new(),
            observed_findings: Vec::new(),
            status: default_status(),
            created_at: Some(Utc::now()),
            updated_at: None,
        }
    }

    /// Raw score: likelihood × impact, weighted by impact drivers.
    ///
    /// ```
    /// # use agenomic_rmp::risk::RiskItem;
    /// let r = RiskItem::new("loop", 0.5, 0.8);
    /// assert!((r.score() - 0.4).abs() < 1e-9);
    /// ```
    pub fn score(&self) -> f64 {
        let driver_boost = if self.impact_drivers.is_empty() {
            1.0
        } else {
            let avg: f64 = self
                .impact_drivers
                .iter()
                .map(|d| d.weight.clamp(0.0, 1.0))
                .sum::<f64>()
                / self.impact_drivers.len() as f64;
            1.0 + avg * 0.5
        };
        (self.likelihood * self.impact * driver_boost).clamp(0.0, 1.0)
    }

    /// Map the score onto the platform severity scale.
    pub fn severity(&self) -> Severity {
        let s = self.score();
        if s >= 0.7 {
            Severity::Critical
        } else if s >= 0.5 {
            Severity::High
        } else if s >= 0.3 {
            Severity::Medium
        } else if s >= 0.1 {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    /// Whether at least one scenario covers this risk.
    pub fn is_covered(&self) -> bool {
        !self.covered_by_scenarios.is_empty()
    }
}

/// The full risk matrix for one agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskMatrix {
    pub spec_version: String,
    pub matrix_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<AgentTypeAssessment>,
    #[serde(default)]
    pub items: Vec<RiskItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl RiskMatrix {
    /// Create an empty matrix for an agent.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            spec_version: RISK_MATRIX_VERSION.into(),
            matrix_id: format!("rm_{}", ulid::Ulid::new()),
            agent_id: agent_id.into(),
            genome_hash: None,
            assessment: None,
            items: Vec::new(),
            created_at: Some(Utc::now()),
            updated_at: None,
        }
    }

    /// Aggregate release-risk score in 0.0 ..= 1.0: the max item score,
    /// blended with the mean and scaled by the agent-type multiplier.
    ///
    /// ```
    /// # use agenomic_rmp::risk::{RiskItem, RiskMatrix};
    /// let mut m = RiskMatrix::new("agent://acme/claims");
    /// assert_eq!(m.release_risk_score(), 0.0);
    /// m.items.push(RiskItem::new("loop", 0.9, 0.9));
    /// assert!(m.release_risk_score() > 0.7);
    /// ```
    pub fn release_risk_score(&self) -> f64 {
        let open: Vec<&RiskItem> = self
            .items
            .iter()
            .filter(|i| i.status != "mitigated")
            .collect();
        if open.is_empty() {
            return 0.0;
        }
        let max = open.iter().map(|i| i.score()).fold(0.0_f64, f64::max);
        let mean: f64 = open.iter().map(|i| i.score()).sum::<f64>() / open.len() as f64;
        let base = max * 0.7 + mean * 0.3;
        let mult = self
            .assessment
            .as_ref()
            .map(AgentTypeAssessment::risk_multiplier)
            .unwrap_or(1.0);
        (base * mult).clamp(0.0, 1.0)
    }

    /// Fraction of open risks covered by at least one scenario.
    pub fn coverage_ratio(&self) -> f64 {
        let open: Vec<&RiskItem> = self.items.iter().filter(|i| i.status == "open").collect();
        if open.is_empty() {
            return 1.0;
        }
        open.iter().filter(|i| i.is_covered()).count() as f64 / open.len() as f64
    }

    /// Find a risk item by id.
    pub fn item(&self, risk_id: &str) -> Option<&RiskItem> {
        self.items.iter().find(|i| i.risk_id == risk_id)
    }

    /// Insert or replace a risk item by id; stamps `updated_at`.
    pub fn upsert(&mut self, item: RiskItem) {
        self.updated_at = Some(Utc::now());
        if let Some(existing) = self.items.iter_mut().find(|i| i.risk_id == item.risk_id) {
            *existing = item;
        } else {
            self.items.push(item);
        }
    }

    /// Record that a scenario covers a risk.
    pub fn mark_covered(&mut self, risk_id: &str, scenario_id: &str) {
        if let Some(item) = self.items.iter_mut().find(|i| i.risk_id == risk_id) {
            if !item.covered_by_scenarios.iter().any(|s| s == scenario_id) {
                item.covered_by_scenarios.push(scenario_id.to_string());
                self.updated_at = Some(Utc::now());
            }
        }
    }

    /// Record production evidence (a finding) against a risk.
    pub fn record_observation(&mut self, risk_id: &str, finding_id: &str) {
        if let Some(item) = self.items.iter_mut().find(|i| i.risk_id == risk_id) {
            if !item.observed_findings.iter().any(|f| f == finding_id) {
                item.observed_findings.push(finding_id.to_string());
                item.updated_at = Some(Utc::now());
                self.updated_at = Some(Utc::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bands() {
        let mut r = RiskItem::new("x", 1.0, 0.8);
        assert_eq!(r.severity(), Severity::Critical);
        r.likelihood = 0.2;
        r.impact = 0.2;
        assert_eq!(r.severity(), Severity::Info);
    }

    #[test]
    fn matrix_score_scales_with_assessment() {
        let mut m = RiskMatrix::new("agent://a/b");
        m.items.push(RiskItem::new("x", 0.5, 0.5));
        let base = m.release_risk_score();
        m.assessment = Some(AgentTypeAssessment {
            agent_type: "autonomous".into(),
            autonomy_level: 1.0,
            external_side_effects: true,
            human_in_the_loop: false,
            rationale: String::new(),
        });
        assert!(m.release_risk_score() > base);
    }

    #[test]
    fn coverage_ratio_counts_open_only() {
        let mut m = RiskMatrix::new("agent://a/b");
        let mut covered = RiskItem::new("a", 0.5, 0.5);
        covered.covered_by_scenarios.push("sc_1".into());
        m.items.push(covered);
        m.items.push(RiskItem::new("b", 0.5, 0.5));
        assert!((m.coverage_ratio() - 0.5).abs() < 1e-9);
    }
}
