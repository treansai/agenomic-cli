//! Property tests: the gate is a deterministic, total function. The same
//! `(rule set, tool call)` must always yield the same decision — that is the
//! whole point of enforcing at the effect rather than at the prompt.

use agenomic_gate::{GateDecision, GateRuleSet, ToolBoundaryGate, ToolCall};
use agenomic_policy::PolicyBundle;
use proptest::prelude::*;

/// A pool mixing dangerous tools, benign tools, and arbitrary names so the
/// strategy exercises every rule branch.
fn tool_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("send_email".to_string()),
        Just("http_post".to_string()),
        Just("delete_record".to_string()),
        Just("transfer_funds".to_string()),
        Just("set_system_prompt".to_string()),
        Just("fs.write".to_string()),
        Just("read_file".to_string()),
        Just("get_weather".to_string()),
        "[a-z_]{1,12}",
    ]
}

fn arg_key_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("path".to_string()),
        Just("to".to_string()),
        Just("url".to_string()),
        Just("body".to_string()),
        Just("content".to_string()),
        Just("id".to_string()),
        "[a-z]{1,6}",
    ]
}

fn arg_val_strategy() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        "[ -~]{0,24}".prop_map(serde_json::Value::String),
        any::<i32>().prop_map(|n| serde_json::json!(n)),
        Just(serde_json::Value::Bool(true)),
    ]
}

prop_compose! {
    fn tool_call_strategy()(
        tool in tool_strategy(),
        untrusted in any::<bool>(),
        args in prop::collection::hash_map(arg_key_strategy(), arg_val_strategy(), 0..4),
        scopes in prop::collection::vec("[a-z.]{1,10}", 0..3),
    ) -> ToolCall {
        let arguments = serde_json::Value::Object(args.into_iter().collect());
        serde_json::from_value(serde_json::json!({
            "tool": tool,
            "provenance": if untrusted { "untrusted" } else { "trusted" },
            "arguments": arguments,
            "scopes": scopes,
        })).expect("constructed tool call")
    }
}

proptest! {
    /// Same input ⇒ same decision, every time.
    #[test]
    fn evaluate_is_deterministic(call in tool_call_strategy()) {
        let gate = ToolBoundaryGate::new(GateRuleSet::default());
        let a = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
        let b = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
        prop_assert_eq!(a, b);
    }

    /// The decision is total: always exactly one of the three verdicts, and the
    /// reasons are sorted with blocks first.
    #[test]
    fn decision_is_total_and_sorted(call in tool_call_strategy()) {
        let gate = ToolBoundaryGate::new(GateRuleSet::default());
        let out = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
        prop_assert!(matches!(
            out.decision,
            GateDecision::Allow | GateDecision::Block | GateDecision::RequireHumanApproval
        ));
        let mut sorted = out.reasons.clone();
        sorted.sort();
        prop_assert_eq!(out.reasons, sorted);
    }

    /// The invariant layer is independently deterministic (no Rego involved).
    #[test]
    fn invariants_are_deterministic(call in tool_call_strategy()) {
        let gate = ToolBoundaryGate::new(GateRuleSet::default());
        prop_assert_eq!(gate.evaluate_invariants(&call), gate.evaluate_invariants(&call));
    }
}
