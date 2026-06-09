//! `AdversarialReviewer` — Mode 3 of Point 4.
//!
//! Tries to break a [`Proposal`] by running a battery of pessimistic heuristics
//! against it. Each rule that fires emits a [`Finding`]; the verdict is the
//! max severity across findings (see [`Verdict::from_findings`]).
//!
//! Configuring this reviewer with an objective opposite to the hypothesis
//! agent — as the original Point 4 wording requires to avoid collusion — is
//! reflected here in the **default-deny shape**: any proposal that lands at
//! High/Critical is `Block`ed, and the rule list is curated so common
//! mistakes (no evidence, no anchor, broad expansion) trip a Finding.

use crate::types::{Critique, Finding, Proposal, ProposalAction, Severity, Verdict};

/// Stateless engine. Per-proposal verdicts are pure functions of the proposal
/// itself.
#[derive(Debug, Default, Clone)]
pub struct AdversarialReviewer;

impl AdversarialReviewer {
    pub fn new() -> Self {
        Self
    }

    /// Critique one proposal.
    pub fn critique(&self, proposal: &Proposal) -> Critique {
        let mut findings = Vec::new();
        for rule in RULES {
            if let Some(f) = rule(proposal) {
                findings.push(f);
            }
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.area.cmp(&b.area)));
        let verdict = Verdict::from_findings(&findings);
        Critique {
            proposal_id: proposal.id.clone(),
            findings,
            verdict,
        }
    }

    /// Critique many proposals; the result preserves input order.
    pub fn critique_many(&self, proposals: &[Proposal]) -> Vec<Critique> {
        proposals.iter().map(|p| self.critique(p)).collect()
    }
}

type Rule = fn(&Proposal) -> Option<Finding>;

const RULES: &[Rule] = &[
    rule_sample_size,
    rule_no_action,
    rule_extension_too_large,
    rule_scope_narrowing_without_exclusions,
    rule_policy_rule_unanchored,
    rule_escalation_overhaul_needs_human_gate,
    rule_no_target_version,
];

fn rule_sample_size(p: &Proposal) -> Option<Finding> {
    if p.evidence_count < 3 {
        Some(Finding {
            severity: Severity::High,
            area: "evidence".into(),
            title: "evidence base too small".into(),
            body: format!(
                "Proposal is backed by only {n} flagged trace(s). \
                 Fewer than 3 traces risks overfitting to a single incident — \
                 wait for the pattern to recur before approving a change.",
                n = p.evidence_count
            ),
            citations: vec!["proposal.evidence_count".into()],
        })
    } else {
        None
    }
}

fn rule_no_action(p: &Proposal) -> Option<Finding> {
    matches!(p.suggested_action, ProposalAction::None).then(|| Finding {
        severity: Severity::Medium,
        area: "remediation".into(),
        title: "no concrete remediation".into(),
        body:
            "The proposal carries no `suggested_action`; either close the cluster as triage-only \
               or refine the diagnostic so a typed action is produced."
                .into(),
        citations: vec!["proposal.suggested_action".into()],
    })
}

fn rule_extension_too_large(p: &Proposal) -> Option<Finding> {
    if let ProposalAction::ExtendSkillExamples { count } = p.suggested_action {
        if count > 20 {
            return Some(Finding {
                severity: Severity::Medium,
                area: "regression-risk".into(),
                title: "large prompt expansion".into(),
                body: format!(
                    "Adding {count} examples in a single change increases over-triggering risk. \
                     Split into multiple proposals or canary the change at 5/25/100%."
                ),
                citations: vec!["proposal.suggested_action.count".into()],
            });
        }
    }
    None
}

fn rule_scope_narrowing_without_exclusions(p: &Proposal) -> Option<Finding> {
    if let ProposalAction::NarrowSkillScope { excluded_keywords } = &p.suggested_action {
        if excluded_keywords.is_empty() {
            return Some(Finding {
                severity: Severity::High,
                area: "regression-risk".into(),
                title: "scope narrowing without exclusions".into(),
                body: "Narrowing the skill's scope without explicit excluded keywords masks the \
                       failure rather than fixing it; the next override will simply move sideways."
                    .into(),
                citations: vec!["proposal.suggested_action.excluded_keywords".into()],
            });
        }
    }
    None
}

fn rule_policy_rule_unanchored(p: &Proposal) -> Option<Finding> {
    if let ProposalAction::AddPolicyRule { rule_hint } = &p.suggested_action {
        let unanchored = rule_hint.trim().is_empty()
            || rule_hint
                .to_ascii_lowercase()
                .contains("no anchoring keyword");
        if unanchored {
            return Some(Finding {
                severity: Severity::High,
                area: "policy".into(),
                title: "policy rule lacks an anchor".into(),
                body: "Proposing a policy rule without an anchoring keyword phrase produces a \
                       guard that either never fires or fires everywhere. Re-cluster or hand-pick \
                       the anchor before approval."
                    .into(),
                citations: vec!["proposal.suggested_action.rule_hint".into()],
            });
        }
    }
    None
}

fn rule_escalation_overhaul_needs_human_gate(p: &Proposal) -> Option<Finding> {
    if matches!(p.suggested_action, ProposalAction::EscalationOverhaul)
        && (p.target_skill.starts_with("compensation") || p.target_skill.starts_with("refund"))
    {
        Some(Finding {
            severity: Severity::Medium,
            area: "compliance".into(),
            title: "escalation overhaul on a money-touching skill".into(),
            body: "Re-routing escalations on a compensation/refund skill is a high-impact change; \
                   it must traverse the AI Act human-approval gate explicitly before any shadow \
                   deployment."
                .into(),
            citations: vec!["proposal.target_skill".into()],
        })
    } else {
        None
    }
}

fn rule_no_target_version(p: &Proposal) -> Option<Finding> {
    if p.target_version.is_none() {
        Some(Finding {
            severity: Severity::Low,
            area: "lineage".into(),
            title: "target_version not pinned".into(),
            body:
                "`target_version` is unset; pin the proposal against a specific skill version to \
                   prevent retroactive drift once the skill is updated."
                    .into(),
            citations: vec!["proposal.target_version".into()],
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(action: ProposalAction, evidence: usize, version: Option<&str>) -> Proposal {
        Proposal {
            id: "p0".into(),
            cluster_id: "c0".into(),
            target_skill: "classify".into(),
            target_version: version.map(str::to_string),
            hypothesis: "...".into(),
            suggested_action: action,
            evidence_count: evidence,
        }
    }

    #[test]
    fn small_evidence_blocks() {
        let p = proposal(
            ProposalAction::ExtendSkillExamples { count: 4 },
            1,
            Some("@7"),
        );
        let c = AdversarialReviewer::new().critique(&p);
        assert_eq!(c.verdict, Verdict::Block);
        assert!(c.findings.iter().any(|f| f.area == "evidence"));
    }

    #[test]
    fn good_extension_proposal_passes_or_warns() {
        let p = proposal(
            ProposalAction::ExtendSkillExamples { count: 6 },
            10,
            Some("@7"),
        );
        let c = AdversarialReviewer::new().critique(&p);
        assert!(matches!(c.verdict, Verdict::Pass | Verdict::Warn));
    }

    #[test]
    fn huge_extension_warns_about_regression() {
        let p = proposal(
            ProposalAction::ExtendSkillExamples { count: 50 },
            50,
            Some("@7"),
        );
        let c = AdversarialReviewer::new().critique(&p);
        assert!(c.findings.iter().any(|f| f.area == "regression-risk"));
        assert_eq!(c.verdict, Verdict::Warn);
    }

    #[test]
    fn scope_narrowing_with_no_exclusions_blocks() {
        let p = proposal(
            ProposalAction::NarrowSkillScope {
                excluded_keywords: vec![],
            },
            10,
            Some("@7"),
        );
        assert_eq!(
            AdversarialReviewer::new().critique(&p).verdict,
            Verdict::Block
        );
    }

    #[test]
    fn policy_rule_without_keyword_blocks() {
        let p = proposal(
            ProposalAction::AddPolicyRule {
                rule_hint: "   ".into(),
            },
            10,
            Some("@7"),
        );
        let c = AdversarialReviewer::new().critique(&p);
        assert_eq!(c.verdict, Verdict::Block);
        assert!(c.findings.iter().any(|f| f.area == "policy"));
    }

    #[test]
    fn escalation_overhaul_on_compensation_warns_about_human_gate() {
        let mut p = proposal(ProposalAction::EscalationOverhaul, 8, Some("@1"));
        p.target_skill = "compensation_lookup".into();
        let c = AdversarialReviewer::new().critique(&p);
        assert!(c.findings.iter().any(|f| f.area == "compliance"));
    }

    #[test]
    fn no_target_version_yields_lineage_finding() {
        let p = proposal(ProposalAction::ExtendSkillExamples { count: 5 }, 10, None);
        let c = AdversarialReviewer::new().critique(&p);
        assert!(c.findings.iter().any(|f| f.area == "lineage"));
    }

    #[test]
    fn findings_are_sorted_by_severity_desc() {
        let p = proposal(ProposalAction::ExtendSkillExamples { count: 5 }, 1, None);
        let c = AdversarialReviewer::new().critique(&p);
        for w in c.findings.windows(2) {
            assert!(w[0].severity >= w[1].severity);
        }
    }

    #[test]
    fn no_action_warns() {
        let p = proposal(ProposalAction::None, 5, Some("@1"));
        let c = AdversarialReviewer::new().critique(&p);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.findings.iter().any(|f| f.area == "remediation"));
    }
}
