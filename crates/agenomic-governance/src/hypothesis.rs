//! `HypothesisAgent` — Mode 2 of Point 4.
//!
//! Turns one [`Cluster`] into one textual [`Proposal`]. It **never mutates**
//! anything: the proposal is JSON that a human (or the adversarial reviewer)
//! reads before any change is approved.

use crate::types::{Cluster, FailureSignal, Proposal, ProposalAction};

/// Stateless engine. Generates one proposal per cluster.
#[derive(Debug, Default, Clone)]
pub struct HypothesisAgent;

impl HypothesisAgent {
    pub fn new() -> Self {
        Self
    }

    /// Build a proposal for `cluster`. Deterministic for a given cluster.
    pub fn hypothesize(&self, cluster: &Cluster) -> Proposal {
        let action = suggest_action(cluster);
        let hypothesis = render_hypothesis(cluster, &action);
        let id = proposal_id(cluster, &action);
        Proposal {
            id,
            cluster_id: cluster.id.clone(),
            target_skill: cluster.skill.clone(),
            target_version: None,
            hypothesis,
            suggested_action: action,
            evidence_count: cluster.size,
        }
    }

    /// Convenience: hypothesize over many clusters in deterministic order.
    pub fn hypothesize_many(&self, clusters: &[Cluster]) -> Vec<Proposal> {
        clusters.iter().map(|c| self.hypothesize(c)).collect()
    }
}

fn suggest_action(cluster: &Cluster) -> ProposalAction {
    match &cluster.signal {
        FailureSignal::Escalation | FailureSignal::Complaint => {
            // Cap the example count at 12 — keeps prompt growth conservative
            // and matches the spec note in the original Point 4 wording.
            let count = cluster.size.clamp(3, 12);
            ProposalAction::ExtendSkillExamples { count }
        }
        FailureSignal::ContractViolation => {
            // First keyword is the strongest signal-bearing anchor.
            match cluster.keywords.first() {
                Some(kw) => ProposalAction::AddPolicyRule {
                    rule_hint: format!("forbid when input contains {kw:?}"),
                },
                None => ProposalAction::AddPolicyRule {
                    rule_hint: "(no anchoring keyword surfaced — refine cluster first)".into(),
                },
            }
        }
        FailureSignal::RefundGranted => {
            if cluster.skill.starts_with("compensation") || cluster.skill.starts_with("refund") {
                ProposalAction::EscalationOverhaul
            } else {
                ProposalAction::ExtendSkillExamples {
                    count: cluster.size.clamp(3, 8),
                }
            }
        }
        FailureSignal::HumanOverride => ProposalAction::NarrowSkillScope {
            excluded_keywords: cluster.keywords.iter().take(3).cloned().collect(),
        },
        FailureSignal::Other(_) => ProposalAction::None,
    }
}

fn render_hypothesis(cluster: &Cluster, action: &ProposalAction) -> String {
    let kw_summary = if cluster.keywords.is_empty() {
        "no dominant keywords".to_string()
    } else {
        format!(
            "around keywords [{}]",
            cluster
                .keywords
                .iter()
                .take(5)
                .map(|k| format!("\"{k}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let signal = cluster.signal.label();
    match action {
        ProposalAction::ExtendSkillExamples { count } => format!(
            "Skill `{skill}` shows {n} {signal} traces {kw}. \
             Hypothesis: the skill does not cover this case. \
             Candidate remediation: extend the skill prompt with {count} additional examples drawn from the cluster.",
            skill = cluster.skill,
            n = cluster.size,
            signal = signal,
            kw = kw_summary,
            count = count,
        ),
        ProposalAction::AddPolicyRule { rule_hint } => format!(
            "Skill `{skill}` produced {n} contract-violating outputs {kw}. \
             Hypothesis: the policy layer is missing a hard guard. \
             Candidate remediation: add a policy rule — {rule_hint}.",
            skill = cluster.skill,
            n = cluster.size,
            kw = kw_summary,
        ),
        ProposalAction::EscalationOverhaul => format!(
            "Skill `{skill}` saw {n} refund-granted overrides {kw}. \
             Hypothesis: the current escalation path under-routes high-value disputes. \
             Candidate remediation: re-design the escalation gate before further deployment.",
            skill = cluster.skill,
            n = cluster.size,
            kw = kw_summary,
        ),
        ProposalAction::NarrowSkillScope { excluded_keywords } => format!(
            "Skill `{skill}` was manually overridden {n} times {kw}. \
             Hypothesis: the skill is over-triggering. \
             Candidate remediation: narrow scope by excluding inputs containing [{ex}].",
            skill = cluster.skill,
            n = cluster.size,
            kw = kw_summary,
            ex = excluded_keywords
                .iter()
                .map(|k| format!("\"{k}\""))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ProposalAction::None => format!(
            "Skill `{skill}` shows {n} traces with signal `{signal}` {kw}, \
             but the diagnostic has no canonical remediation for this signal. \
             Recommend triage by a human before proposing a change.",
            skill = cluster.skill,
            n = cluster.size,
            signal = signal,
            kw = kw_summary,
        ),
    }
}

/// Hash the cluster id and the action label/payload so two runs over the
/// same diagnosis produce identical proposal ids — needed when chaining into
/// an attestation downstream.
fn proposal_id(cluster: &Cluster, action: &ProposalAction) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"proposal\0");
    hasher.update(cluster.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(action.label().as_bytes());
    // Include the action's payload so two same-label proposals with
    // different counts/keywords still hash distinctly.
    if let Ok(bytes) = serde_json::to_vec(action) {
        hasher.update(b"\0");
        hasher.update(&bytes);
    }
    hex::encode(&hasher.finalize().as_bytes()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster(signal: FailureSignal, skill: &str, size: usize, keywords: &[&str]) -> Cluster {
        Cluster {
            id: "c0".into(),
            signal,
            skill: skill.into(),
            size,
            members: (0..size).map(|i| format!("t{i}")).collect(),
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            exemplars: vec![],
        }
    }

    #[test]
    fn escalation_proposes_extending_examples_with_clamp() {
        let c = cluster(
            FailureSignal::Escalation,
            "classify",
            50,
            &["refund", "partial"],
        );
        let p = HypothesisAgent::new().hypothesize(&c);
        match p.suggested_action {
            ProposalAction::ExtendSkillExamples { count } => assert_eq!(count, 12),
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(p.hypothesis.contains("classify"));
        assert!(p.hypothesis.contains("\"refund\""));
        assert_eq!(p.evidence_count, 50);
    }

    #[test]
    fn contract_violation_anchors_rule_on_top_keyword() {
        let c = cluster(
            FailureSignal::ContractViolation,
            "compensation",
            5,
            &["pii", "leak"],
        );
        let p = HypothesisAgent::new().hypothesize(&c);
        match p.suggested_action {
            ProposalAction::AddPolicyRule { rule_hint } => assert!(rule_hint.contains("\"pii\"")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refund_granted_on_compensation_skill_proposes_escalation_overhaul() {
        let c = cluster(FailureSignal::RefundGranted, "compensation_lookup", 4, &[]);
        assert!(matches!(
            HypothesisAgent::new().hypothesize(&c).suggested_action,
            ProposalAction::EscalationOverhaul
        ));
    }

    #[test]
    fn human_override_proposes_scope_narrowing() {
        let c = cluster(
            FailureSignal::HumanOverride,
            "triage",
            3,
            &["urgent", "vip"],
        );
        match HypothesisAgent::new().hypothesize(&c).suggested_action {
            ProposalAction::NarrowSkillScope { excluded_keywords } => {
                assert_eq!(excluded_keywords, vec!["urgent", "vip"])
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn other_signal_yields_no_action() {
        let c = cluster(FailureSignal::Other("weird".into()), "s", 1, &[]);
        assert!(matches!(
            HypothesisAgent::new().hypothesize(&c).suggested_action,
            ProposalAction::None
        ));
    }

    #[test]
    fn proposal_id_is_stable_across_runs() {
        let c = cluster(FailureSignal::Escalation, "classify", 5, &["refund"]);
        let a = HypothesisAgent::new().hypothesize(&c).id;
        let b = HypothesisAgent::new().hypothesize(&c).id;
        assert_eq!(a, b);
    }
}
