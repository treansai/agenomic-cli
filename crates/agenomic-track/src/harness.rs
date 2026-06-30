//! The runtime harness.
//!
//! The harness evaluates a session's live events against the bundle's
//! behavior contract and policies, folds in the drift/loop/intent alerts the
//! detectors produced, and emits a pass/fail [`HarnessResult`] with per-check
//! evidence. It reuses [`agenomic_contract::evaluate_contract`] and
//! [`agenomic_policy::PolicyBundle`] rather than reimplementing rule
//! evaluation.

use serde::{Deserialize, Serialize};

use agenomic_contract::{evaluate_contract, BehaviorContract, ToolCall, TraceEnvelope};
use agenomic_policy::PolicyBundle;

use crate::alert::{Alert, AlertKind, AlertSeverity};
use crate::event::{TrackingEvent, TrackingEventType};

/// Optional baseline artifacts the harness evaluates against.
pub struct HarnessInputs {
    pub contract: Option<BehaviorContract>,
    pub policy: Option<PolicyBundle>,
    /// Severity at or above which any alert fails the harness. Defaults to
    /// `critical`; set from the session's `tracking_config.fail_on`.
    pub fail_on: AlertSeverity,
}

impl Default for HarnessInputs {
    fn default() -> Self {
        Self {
            contract: None,
            policy: None,
            fail_on: AlertSeverity::Critical,
        }
    }
}

/// One harness check outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HarnessCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub severity: AlertSeverity,
    pub message: String,
    #[serde(default)]
    pub evidence_event_ids: Vec<String>,
}

/// The aggregate result of a harness evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HarnessResult {
    pub passed: bool,
    pub checks: Vec<HarnessCheck>,
    /// Alerts the harness itself raised (contract/policy/approval violations).
    pub alerts: Vec<Alert>,
}

/// The runtime harness evaluator.
pub struct RuntimeHarness {
    session_id: String,
}

impl RuntimeHarness {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
        }
    }

    /// Project a session's events into a single [`TraceEnvelope`] for contract
    /// evaluation. Input/output come from the redacted previews on the
    /// `agent.started`/`agent.completed` events; tool calls come from
    /// `tool.call.completed`.
    fn project_trace(&self, agent_id: &str, events: &[TrackingEvent]) -> TraceEnvelope {
        let input = events
            .iter()
            .find(|e| matches!(e.event_type, TrackingEventType::AgentStarted))
            .and_then(|e| e.redacted_preview.clone())
            .unwrap_or(serde_json::Value::Null);
        let output = events
            .iter()
            .rev()
            .find(|e| matches!(e.event_type, TrackingEventType::AgentCompleted))
            .and_then(|e| e.redacted_preview.clone());
        let tool_calls = events
            .iter()
            .filter(|e| matches!(e.event_type, TrackingEventType::ToolCallCompleted))
            .filter_map(|e| {
                e.tool.as_ref().map(|t| ToolCall {
                    name: t.name.clone(),
                    arguments: None,
                    result: None,
                    human_approval_present: e
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("approval_present"))
                        .and_then(|v| v.as_bool()),
                })
            })
            .collect();
        TraceEnvelope {
            trace_id: self.session_id.clone(),
            agent_id: agent_id.to_string(),
            input,
            output,
            tool_calls,
            metadata: None,
        }
    }

    /// Evaluate the harness over a session.
    ///
    /// `detector_alerts` are the drift/loop/intent alerts already accumulated
    /// by the engine; they are folded into summary checks. `inputs` carry the
    /// optional behavior contract and policy bundle.
    pub fn evaluate(
        &self,
        agent_id: &str,
        events: &[TrackingEvent],
        detector_alerts: &[Alert],
        inputs: &HarnessInputs,
    ) -> HarnessResult {
        let mut checks = Vec::new();
        let mut alerts = Vec::new();

        // --- behavior contract --------------------------------------------
        if let Some(contract) = &inputs.contract {
            let trace = self.project_trace(agent_id, events);
            match evaluate_contract(contract, std::slice::from_ref(&trace)) {
                Ok(eval) => {
                    let failed: Vec<_> = eval
                        .violations_by_check
                        .values()
                        .flatten()
                        .cloned()
                        .collect();
                    let passed = eval.critical_count == 0 && eval.high_count == 0;
                    checks.push(HarnessCheck {
                        id: "behavior_contract".into(),
                        name: format!("Behavior contract '{}'", eval.contract_id),
                        passed,
                        severity: if passed {
                            AlertSeverity::Info
                        } else {
                            AlertSeverity::Critical
                        },
                        message: if passed {
                            "All deterministic contract checks held.".into()
                        } else {
                            format!("{} contract violation(s).", failed.len())
                        },
                        evidence_event_ids: vec![],
                    });
                    for v in failed {
                        alerts.push(
                            Alert::new(
                                self.session_id.clone(),
                                AlertKind::Harness,
                                AlertSeverity::from_platform(v.severity),
                                format!("Contract violation: {}", v.check_id),
                                v.message.clone(),
                            )
                            .with_action(
                                "Review the behavior contract rule and the offending output.",
                            ),
                        );
                    }
                }
                Err(e) => {
                    checks.push(HarnessCheck {
                        id: "behavior_contract".into(),
                        name: "Behavior contract".into(),
                        passed: false,
                        severity: AlertSeverity::Warning,
                        message: format!("Contract evaluation error: {e}"),
                        evidence_event_ids: vec![],
                    });
                }
            }
        }

        // --- policy --------------------------------------------------------
        // Primary signal: the runtime's own `policy.evaluated` decisions. We
        // trust the decision the agent actually made rather than guessing a
        // Rego input shape. A supplied policy bundle is only re-evaluated
        // against an *explicit* context a producer attached as
        // `metadata.policy_input`, so we never produce default-deny false
        // positives for events that were never meant to be gated.
        let mut denied: Vec<(String, String, Vec<String>)> = Vec::new();
        for e in events
            .iter()
            .filter(|e| matches!(e.event_type, TrackingEventType::PolicyEvaluated))
        {
            if let Some(pr) = &e.policy_result {
                if pr.outcome.eq_ignore_ascii_case("deny") {
                    let label = pr.policy_id.clone().unwrap_or_else(|| "policy".into());
                    denied.push((e.event_id.clone(), label, pr.denies.clone()));
                }
            }
        }
        if let Some(policy) = &inputs.policy {
            if !policy.is_empty() {
                for e in events {
                    if let Some(ctx) = e.metadata.as_ref().and_then(|m| m.get("policy_input")) {
                        if let Ok(decision) = policy.evaluate(ctx) {
                            if !decision.allowed {
                                denied.push((
                                    e.event_id.clone(),
                                    "policy_bundle".into(),
                                    decision.denies,
                                ));
                            }
                        }
                    }
                }
            }
        }
        // Only emit a policy check if there was a policy decision to evaluate.
        let saw_policy = events
            .iter()
            .any(|e| matches!(e.event_type, TrackingEventType::PolicyEvaluated))
            || inputs.policy.as_ref().is_some_and(|p| !p.is_empty());
        if saw_policy {
            let passed = denied.is_empty();
            checks.push(HarnessCheck {
                id: "policy".into(),
                name: "Policy evaluation".into(),
                passed,
                severity: if passed {
                    AlertSeverity::Info
                } else {
                    AlertSeverity::Critical
                },
                message: if passed {
                    "No policy denials observed.".into()
                } else {
                    format!("{} policy denial(s).", denied.len())
                },
                evidence_event_ids: denied.iter().map(|(id, _, _)| id.clone()).collect(),
            });
            for (eid, label, denies) in denied {
                alerts.push(
                    Alert::new(
                        self.session_id.clone(),
                        AlertKind::Policy,
                        AlertSeverity::Critical,
                        format!("Policy '{label}' denied"),
                        if denies.is_empty() {
                            format!("Policy '{label}' returned deny.")
                        } else {
                            format!("Policy '{label}' denied: {}.", denies.join("; "))
                        },
                    )
                    .with_evidence([eid])
                    .with_gating(true, true)
                    .with_action("Block the effect and review the policy/permission grant."),
                );
            }
        }

        // --- missing human-approval gates ---------------------------------
        let approval_gaps: Vec<String> = events
            .iter()
            .filter(|e| matches!(e.event_type, TrackingEventType::ToolCallCompleted))
            .filter(|e| {
                let meta = e.metadata.as_ref();
                let requires = meta
                    .and_then(|m| m.get("requires_human_approval"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let present = meta
                    .and_then(|m| m.get("approval_present"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                requires && !present
            })
            .map(|e| e.event_id.clone())
            .collect();
        if !approval_gaps.is_empty() {
            checks.push(HarnessCheck {
                id: "human_approval_gates".into(),
                name: "Human approval gates".into(),
                passed: false,
                severity: AlertSeverity::Critical,
                message: format!(
                    "{} tool call(s) executed without required human approval.",
                    approval_gaps.len()
                ),
                evidence_event_ids: approval_gaps.clone(),
            });
            alerts.push(
                Alert::new(
                    self.session_id.clone(),
                    AlertKind::Security,
                    AlertSeverity::Critical,
                    "Missing human approval",
                    "A tool requiring human approval executed without one.",
                )
                .with_evidence(approval_gaps)
                .with_gating(true, true)
                .with_action("Require a signed human approval before this tool can execute."),
            );
        }

        // --- fold detector alerts into summary checks ---------------------
        for (kind, id, name) in [
            (AlertKind::Drift, "drift_violations", "Drift checks"),
            (AlertKind::Loop, "loop_violations", "Loop checks"),
            (AlertKind::Intent, "intent_violations", "Intent checks"),
        ] {
            let matched: Vec<&Alert> = detector_alerts.iter().filter(|a| a.kind == kind).collect();
            let worst = matched.iter().map(|a| a.severity).max();
            let passed = matched.is_empty();
            checks.push(HarnessCheck {
                id: id.into(),
                name: name.into(),
                passed,
                severity: worst.unwrap_or(AlertSeverity::Info),
                message: if passed {
                    format!("No {} alerts.", kind.label())
                } else {
                    format!("{} {} alert(s).", matched.len(), kind.label())
                },
                evidence_event_ids: matched
                    .iter()
                    .flat_map(|a| a.evidence_event_ids.clone())
                    .collect(),
            });
        }

        // The harness fails only on a *hard* check (contract / policy / human
        // approval) or any critical-severity alert. The folded drift/loop/intent
        // checks are informational severity rollups: a warning-level finding is
        // surfaced but does not by itself fail the session.
        let all_alerts: Vec<&Alert> = detector_alerts.iter().chain(alerts.iter()).collect();
        let hard_checks_pass = checks
            .iter()
            .filter(|c| {
                matches!(
                    c.id.as_str(),
                    "behavior_contract" | "policy" | "human_approval_gates"
                )
            })
            .all(|c| c.passed);
        let passed = hard_checks_pass && !all_alerts.iter().any(|a| a.severity >= inputs.fail_on);

        HarnessResult {
            passed,
            checks,
            alerts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ToolMeta;

    fn agent_started(seq: u64, preview: serde_json::Value) -> TrackingEvent {
        let mut e = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentStarted, seq);
        e.redacted_preview = Some(preview);
        e
    }
    fn agent_completed(seq: u64, preview: serde_json::Value) -> TrackingEvent {
        let mut e = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::AgentCompleted, seq);
        e.redacted_preview = Some(preview);
        e
    }

    #[test]
    fn clean_session_passes() {
        let h = RuntimeHarness::new("s1");
        let events = vec![
            agent_started(0, serde_json::json!({"q": "x"})),
            agent_completed(1, serde_json::json!({"language": "en"})),
        ];
        let r = h.evaluate("agent://a/b", &events, &[], &HarnessInputs::default());
        assert!(r.passed);
    }

    #[test]
    fn contract_violation_fails_and_alerts() {
        let contract = agenomic_contract::parse_contract_yaml(
            "spec_version: '0.1'\ncontract:\n  id: c1\n  rules:\n    - id: r1\n      type: required_output_field\n      severity: critical\n      required_fields: [language]\n",
        )
        .unwrap();
        let h = RuntimeHarness::new("s1");
        let events = vec![
            agent_started(0, serde_json::json!({"q": "x"})),
            agent_completed(1, serde_json::json!({})), // missing `language`
        ];
        let inputs = HarnessInputs {
            contract: Some(contract),
            policy: None,
            ..Default::default()
        };
        let r = h.evaluate("agent://a/b", &events, &[], &inputs);
        assert!(!r.passed);
        assert!(r.alerts.iter().any(|a| a.kind == AlertKind::Harness));
    }

    #[test]
    fn missing_human_approval_is_flagged() {
        let h = RuntimeHarness::new("s1");
        let mut tool =
            TrackingEvent::new("s1", "agent://a/b", TrackingEventType::ToolCallCompleted, 1);
        tool.tool = Some(ToolMeta {
            name: "wire_transfer".into(),
            ..Default::default()
        });
        tool.metadata =
            Some(serde_json::json!({ "requires_human_approval": true, "approval_present": false }));
        let events = vec![agent_started(0, serde_json::json!({})), tool];
        let r = h.evaluate("agent://a/b", &events, &[], &HarnessInputs::default());
        assert!(!r.passed);
        assert!(r
            .checks
            .iter()
            .any(|c| c.id == "human_approval_gates" && !c.passed));
    }

    #[test]
    fn policy_evaluated_deny_fails() {
        let h = RuntimeHarness::new("s1");
        let mut pe = TrackingEvent::new("s1", "agent://a/b", TrackingEventType::PolicyEvaluated, 1);
        pe.policy_result = Some(crate::event::PolicyResult {
            policy_id: Some("pii_guard".into()),
            outcome: "deny".into(),
            denies: vec!["writes PII to logs".into()],
        });
        let events = vec![agent_started(0, serde_json::json!({})), pe];
        let r = h.evaluate("agent://a/b", &events, &[], &HarnessInputs::default());
        assert!(!r.passed);
        assert!(r.checks.iter().any(|c| c.id == "policy" && !c.passed));
        assert!(r.alerts.iter().any(|a| a.kind == AlertKind::Policy));
    }

    #[test]
    fn no_policy_signal_no_policy_check() {
        let h = RuntimeHarness::new("s1");
        let events = vec![agent_started(0, serde_json::json!({}))];
        let r = h.evaluate("agent://a/b", &events, &[], &HarnessInputs::default());
        assert!(!r.checks.iter().any(|c| c.id == "policy"));
    }

    #[test]
    fn fail_on_warning_fails_the_harness_on_a_warning() {
        let h = RuntimeHarness::new("s1");
        let warn = Alert::new("s1", AlertKind::Loop, AlertSeverity::Warning, "t", "m");
        let inputs = HarnessInputs {
            fail_on: AlertSeverity::Warning,
            ..Default::default()
        };
        let r = h.evaluate(
            "agent://a/b",
            &[agent_started(0, serde_json::json!({}))],
            std::slice::from_ref(&warn),
            &inputs,
        );
        assert!(!r.passed, "fail_on=warning must fail on a warning alert");
    }

    #[test]
    fn detector_alerts_fold_into_checks() {
        let h = RuntimeHarness::new("s1");
        let drift = Alert::new("s1", AlertKind::Drift, AlertSeverity::Warning, "t", "m");
        let r = h.evaluate(
            "agent://a/b",
            &[agent_started(0, serde_json::json!({}))],
            std::slice::from_ref(&drift),
            &HarnessInputs::default(),
        );
        let c = r
            .checks
            .iter()
            .find(|c| c.id == "drift_violations")
            .unwrap();
        assert!(!c.passed);
        // a single warning does not fail the whole harness
        assert!(r.passed);
    }
}
