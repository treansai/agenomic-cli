//! Built-in deterministic checks.

use agentlock_core::Severity;

use crate::types::{BehaviorContract, CheckResult, ContractRule, TraceEnvelope};

/// Trait every deterministic check implements.
pub trait DeterministicCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult;
}

/// Build the default registry of seven deterministic checks.
///
/// ```
/// let checks = agentlock_contract::default_checks();
/// assert_eq!(checks.len(), 7);
/// ```
pub fn default_checks() -> Vec<Box<dyn DeterministicCheck>> {
    vec![
        Box::new(RequiredOutputField),
        Box::new(ForbiddenToolUsed),
        Box::new(ToolRequiresHumanApproval),
        Box::new(PolicySourceRequired),
        Box::new(LanguageMatchFieldPresent),
        Box::new(JsonOutputValid),
        Box::new(NoFinalDecisionWithoutApproval),
    ]
}

fn passing(rule: &ContractRule, id: &'static str) -> CheckResult {
    CheckResult {
        check_id: id.to_string(),
        passed: true,
        severity: rule.severity,
        violation_message: None,
    }
}

fn failing(rule: &ContractRule, id: &'static str, msg: String) -> CheckResult {
    CheckResult {
        check_id: id.to_string(),
        passed: false,
        severity: rule.severity,
        violation_message: Some(msg),
    }
}

/// Output JSON has all `required_fields`.
pub struct RequiredOutputField;
impl DeterministicCheck for RequiredOutputField {
    fn id(&self) -> &'static str {
        "required_output_field"
    }
    fn description(&self) -> &'static str {
        "Output JSON must contain every required_fields entry"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        let output = match &trace.output {
            Some(serde_json::Value::Object(m)) => m,
            _ => return failing(rule, self.id(), "output is not a JSON object".into()),
        };
        for field in &rule.required_fields {
            if !output.contains_key(field) {
                return failing(rule, self.id(), format!("missing required field '{field}'"));
            }
        }
        passing(rule, self.id())
    }
}

/// No use of any tool listed in `forbidden_tools`.
pub struct ForbiddenToolUsed;
impl DeterministicCheck for ForbiddenToolUsed {
    fn id(&self) -> &'static str {
        "forbidden_tool_used"
    }
    fn description(&self) -> &'static str {
        "No call to any tool in forbidden_tools"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        for c in &trace.tool_calls {
            if rule.forbidden_tools.contains(&c.name) {
                return failing(rule, self.id(), format!("forbidden tool '{}' used", c.name));
            }
        }
        passing(rule, self.id())
    }
}

/// Sensitive tools never called without `human_approval_present = true`.
pub struct ToolRequiresHumanApproval;
impl DeterministicCheck for ToolRequiresHumanApproval {
    fn id(&self) -> &'static str {
        "tool_requires_human_approval"
    }
    fn description(&self) -> &'static str {
        "Sensitive tool calls require explicit human approval"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        for c in &trace.tool_calls {
            if rule.sensitive_tools.contains(&c.name)
                && !c.human_approval_present.unwrap_or(false)
            {
                return failing(
                    rule,
                    self.id(),
                    format!("sensitive tool '{}' called without human_approval", c.name),
                );
            }
        }
        passing(rule, self.id())
    }
}

/// When output mentions compensation/policy, must reference a policy source.
pub struct PolicySourceRequired;
impl DeterministicCheck for PolicySourceRequired {
    fn id(&self) -> &'static str {
        "policy_source_required"
    }
    fn description(&self) -> &'static str {
        "If output references a policy decision, a `policy_source` field must be present"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        let output = match &trace.output {
            Some(serde_json::Value::Object(m)) => m,
            _ => return passing(rule, self.id()),
        };
        let mentions_policy = output
            .iter()
            .any(|(_, v)| match v {
                serde_json::Value::String(s) => {
                    let lc = s.to_lowercase();
                    lc.contains("compensation") || lc.contains("policy")
                }
                _ => false,
            });
        if mentions_policy && !output.contains_key("policy_source") {
            return failing(
                rule,
                self.id(),
                "output references a policy/compensation decision but `policy_source` is missing"
                    .into(),
            );
        }
        passing(rule, self.id())
    }
}

/// Output has a `language` field for multilingual auditability.
pub struct LanguageMatchFieldPresent;
impl DeterministicCheck for LanguageMatchFieldPresent {
    fn id(&self) -> &'static str {
        "language_match_field_present"
    }
    fn description(&self) -> &'static str {
        "Output must declare its `language` field"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        let output = match &trace.output {
            Some(serde_json::Value::Object(m)) => m,
            _ => return failing(rule, self.id(), "output is not a JSON object".into()),
        };
        if !output.contains_key("language") {
            return failing(rule, self.id(), "missing `language` field".into());
        }
        passing(rule, self.id())
    }
}

/// If `output_format = json`, the final output parses as JSON. (When the
/// trace's output is already a JSON value we always pass; this check exists
/// for traces where the final answer is a string.)
pub struct JsonOutputValid;
impl DeterministicCheck for JsonOutputValid {
    fn id(&self) -> &'static str {
        "json_output_valid"
    }
    fn description(&self) -> &'static str {
        "If output_format=json, the final output parses as JSON"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        let want_json = rule.output_format.as_deref() == Some("json");
        if !want_json {
            return passing(rule, self.id());
        }
        match &trace.output {
            Some(serde_json::Value::Object(_) | serde_json::Value::Array(_)) => {
                passing(rule, self.id())
            }
            Some(serde_json::Value::String(s)) => {
                if serde_json::from_str::<serde_json::Value>(s).is_ok() {
                    passing(rule, self.id())
                } else {
                    failing(
                        rule,
                        self.id(),
                        "output_format=json but output string is not valid JSON".into(),
                    )
                }
            }
            _ => failing(rule, self.id(), "output is not JSON".into()),
        }
    }
}

/// Final decision requires a `human_approval` flag in metadata.
pub struct NoFinalDecisionWithoutApproval;
impl DeterministicCheck for NoFinalDecisionWithoutApproval {
    fn id(&self) -> &'static str {
        "no_final_decision_without_approval"
    }
    fn description(&self) -> &'static str {
        "Output containing `final_decision` requires `human_approval = true` in metadata"
    }
    fn evaluate(&self, trace: &TraceEnvelope, rule: &ContractRule) -> CheckResult {
        if rule.rule_type != self.id() {
            return passing(rule, self.id());
        }
        let has_decision = match &trace.output {
            Some(serde_json::Value::Object(m)) => m.contains_key("final_decision"),
            _ => false,
        };
        if !has_decision {
            return passing(rule, self.id());
        }
        let approved = trace
            .metadata
            .as_ref()
            .and_then(|m| m.get("human_approval"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !approved {
            return failing(
                rule,
                self.id(),
                "final_decision present but human_approval is not true".into(),
            );
        }
        passing(rule, self.id())
    }
}

/// Severity counter helper used by the evaluator.
pub fn bump_count(
    sev: Severity,
    crit: &mut u32,
    high: &mut u32,
    med: &mut u32,
    low: &mut u32,
) {
    match sev {
        Severity::Critical => *crit += 1,
        Severity::High => *high += 1,
        Severity::Medium => *med += 1,
        Severity::Low | Severity::Info => *low += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCall;

    fn rule(id: &str, rule_type: &str, sev: Severity) -> ContractRule {
        ContractRule {
            id: id.into(),
            rule_type: rule_type.into(),
            severity: sev,
            description: None,
            required_fields: vec![],
            forbidden_tools: vec![],
            sensitive_tools: vec![],
            output_format: None,
            extra: Default::default(),
        }
    }

    fn trace_with_output(out: serde_json::Value) -> TraceEnvelope {
        TraceEnvelope {
            trace_id: "t1".into(),
            agent_id: "a".into(),
            input: serde_json::json!({}),
            output: Some(out),
            tool_calls: vec![],
            metadata: None,
        }
    }

    #[test]
    fn required_field_pass_and_fail() {
        let mut r = rule("r", "required_output_field", Severity::High);
        r.required_fields = vec!["foo".into()];
        let pass = trace_with_output(serde_json::json!({"foo": 1}));
        let fail = trace_with_output(serde_json::json!({"bar": 1}));
        assert!(RequiredOutputField.evaluate(&pass, &r).passed);
        assert!(!RequiredOutputField.evaluate(&fail, &r).passed);
    }

    #[test]
    fn forbidden_tool_detected() {
        let mut r = rule("r", "forbidden_tool_used", Severity::High);
        r.forbidden_tools = vec!["delete_db".into()];
        let mut t = trace_with_output(serde_json::json!({}));
        t.tool_calls.push(ToolCall {
            name: "delete_db".into(),
            arguments: None,
            result: None,
            human_approval_present: None,
        });
        assert!(!ForbiddenToolUsed.evaluate(&t, &r).passed);
    }

    #[test]
    fn sensitive_tool_requires_approval() {
        let mut r = rule("r", "tool_requires_human_approval", Severity::Critical);
        r.sensitive_tools = vec!["wire_transfer".into()];
        let mut t = trace_with_output(serde_json::json!({}));
        t.tool_calls.push(ToolCall {
            name: "wire_transfer".into(),
            arguments: None,
            result: None,
            human_approval_present: Some(false),
        });
        assert!(!ToolRequiresHumanApproval.evaluate(&t, &r).passed);
        t.tool_calls[0].human_approval_present = Some(true);
        assert!(ToolRequiresHumanApproval.evaluate(&t, &r).passed);
    }
}
