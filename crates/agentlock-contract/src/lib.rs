//! Deterministic behavior-contract checks for stored traces.
//!
//! See [`evaluate_contract`].

pub mod checks;
pub mod types;

use std::collections::BTreeMap;

use agentlock_core::CliResult;

pub use checks::{
    bump_count, default_checks, DeterministicCheck, ForbiddenToolUsed, JsonOutputValid,
    LanguageMatchFieldPresent, NoFinalDecisionWithoutApproval, PolicySourceRequired,
    RequiredOutputField, ToolRequiresHumanApproval,
};
pub use types::{
    BehaviorContract, CheckResult, ContractEvaluation, ContractRule, ToolCall, TraceEnvelope,
    TraceViolation,
};

/// Evaluate a contract against a list of traces using the default check set.
///
/// ```no_run
/// use agentlock_contract::{evaluate_contract, BehaviorContract, TraceEnvelope};
/// let contract = BehaviorContract { id: "c".into(), description: None, rules: vec![] };
/// let traces: Vec<TraceEnvelope> = vec![];
/// let r = evaluate_contract(&contract, &traces).unwrap();
/// assert!(r.passed);
/// ```
pub fn evaluate_contract(
    contract: &BehaviorContract,
    traces: &[TraceEnvelope],
) -> CliResult<ContractEvaluation> {
    evaluate_contract_with(contract, traces, &default_checks())
}

/// Evaluate using a custom check set.
pub fn evaluate_contract_with(
    contract: &BehaviorContract,
    traces: &[TraceEnvelope],
    checks: &[Box<dyn DeterministicCheck>],
) -> CliResult<ContractEvaluation> {
    let mut violations: BTreeMap<String, Vec<TraceViolation>> = BTreeMap::new();
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;

    for trace in traces {
        for rule in &contract.rules {
            for check in checks {
                if check.id() != rule.rule_type {
                    continue;
                }
                let r = check.evaluate(trace, rule);
                if !r.passed {
                    let v = TraceViolation {
                        trace_id: trace.trace_id.clone(),
                        check_id: r.check_id.clone(),
                        severity: r.severity,
                        message: r
                            .violation_message
                            .clone()
                            .unwrap_or_else(|| "violation".into()),
                    };
                    bump_count(r.severity, &mut critical, &mut high, &mut medium, &mut low);
                    violations.entry(r.check_id).or_default().push(v);
                }
            }
        }
    }

    let passed = critical == 0 && high == 0;
    Ok(ContractEvaluation {
        contract_id: contract.id.clone(),
        total_traces: traces.len(),
        passed,
        violations_by_check: violations,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
    })
}

/// Parse a behavior contract from YAML text.
///
/// ```
/// let yaml = r#"
/// spec_version: '0.1'
/// contract:
///   id: 'c1'
///   rules:
///     - id: r1
///       type: required_output_field
///       severity: high
///       required_fields: [foo]
/// "#;
/// let c = agentlock_contract::parse_contract_yaml(yaml).unwrap();
/// assert_eq!(c.id, "c1");
/// ```
pub fn parse_contract_yaml(yaml_text: &str) -> CliResult<BehaviorContract> {
    let v: serde_yaml::Value = serde_yaml::from_str(yaml_text)
        .map_err(|e| agentlock_core::CliError::Schema(format!("yaml: {e}")))?;
    let c = v
        .get("contract")
        .cloned()
        .ok_or_else(|| agentlock_core::CliError::Schema("missing 'contract' key".into()))?;
    let parsed: BehaviorContract = serde_yaml::from_value(c)
        .map_err(|e| agentlock_core::CliError::Schema(format!("contract parse: {e}")))?;
    Ok(parsed)
}

/// Parse a JSONL file of traces.
pub fn parse_traces_jsonl(text: &str) -> CliResult<Vec<TraceEnvelope>> {
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let t: TraceEnvelope = serde_json::from_str(line).map_err(|e| {
            agentlock_core::CliError::Schema(format!("trace line {}: {e}", lineno + 1))
        })?;
        out.push(t);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlock_core::Severity;
    use serde_json::json;

    fn make_contract() -> BehaviorContract {
        BehaviorContract {
            id: "c1".into(),
            description: None,
            rules: vec![ContractRule {
                id: "r1".into(),
                rule_type: "required_output_field".into(),
                severity: Severity::High,
                description: None,
                required_fields: vec!["language".into()],
                forbidden_tools: vec![],
                sensitive_tools: vec![],
                output_format: None,
                extra: Default::default(),
            }],
        }
    }

    #[test]
    fn passing_evaluation() {
        let c = make_contract();
        let traces = vec![TraceEnvelope {
            trace_id: "t1".into(),
            agent_id: "a".into(),
            input: json!({}),
            output: Some(json!({"language": "en"})),
            tool_calls: vec![],
            metadata: None,
        }];
        let r = evaluate_contract(&c, &traces).unwrap();
        assert!(r.passed);
        assert_eq!(r.high_count, 0);
    }

    #[test]
    fn failing_high_blocks() {
        let c = make_contract();
        let traces = vec![TraceEnvelope {
            trace_id: "t1".into(),
            agent_id: "a".into(),
            input: json!({}),
            output: Some(json!({})),
            tool_calls: vec![],
            metadata: None,
        }];
        let r = evaluate_contract(&c, &traces).unwrap();
        assert!(!r.passed);
        assert_eq!(r.high_count, 1);
    }

    #[test]
    fn parse_contract_yaml_basic() {
        let yaml = "spec_version: '0.1'\ncontract:\n  id: c1\n  rules:\n    - id: r1\n      type: required_output_field\n      severity: high\n      required_fields: [foo]\n";
        let c = parse_contract_yaml(yaml).unwrap();
        assert_eq!(c.id, "c1");
        assert_eq!(c.rules.len(), 1);
    }
}
