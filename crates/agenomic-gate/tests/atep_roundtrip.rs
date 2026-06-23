//! Round-trip: the gate's event descriptors seal into signed, hash-linked ATEP
//! events that an `AtepStore` verifies — the same chain `agenomic atep verify`
//! checks. This proves the audit trail the gate produces is tamper-evident.

use agenomic_atep::{AtepEvent, AtepStore, EventHeader, EventPayload, Hlc, StreamId};
use agenomic_gate::events::{gate_descriptors, GateEventDescriptor, GateStream};
use agenomic_gate::{GateRuleSet, ToolBoundaryGate, ToolCall};
use agenomic_policy::PolicyBundle;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;

const AGENT: &str = "agent://acme/gateway";

fn fixed_key() -> SigningKey {
    // Deterministic key keeps the test reproducible (no OsRng).
    SigningKey::from_bytes(&[7u8; 32])
}

fn stream_id(s: GateStream) -> StreamId {
    match s {
        GateStream::Policy => StreamId::Policy,
        GateStream::Governance => StreamId::Governance,
    }
}

/// Seal a descriptor batch onto a store, chaining each event onto its stream's
/// head — the same logic the CLI's `emit_gate_events` performs.
fn seal_and_append(store: &mut AtepStore, sk: &SigningKey, descriptors: &[GateEventDescriptor]) {
    let key_id = "ed25519:testkey".to_string();
    let mut counter: u64 = 0;
    for kind in [GateStream::Policy, GateStream::Governance] {
        let stream = stream_id(kind);
        let descs: Vec<&GateEventDescriptor> =
            descriptors.iter().filter(|d| d.stream == kind).collect();
        if descs.is_empty() {
            continue;
        }
        let head = store.stream_head(stream).unwrap();
        let seq_start = head.as_ref().map(|(s, _)| s + 1).unwrap_or(0);
        let mut parent = head.map(|(_, h)| h);
        let mut events = Vec::with_capacity(descs.len());
        for (seq, (i, d)) in (seq_start..).zip(descs.iter().enumerate()) {
            let mut event_id = [0u8; 16];
            event_id[..8].copy_from_slice(&counter.to_le_bytes());
            counter += 1;
            let header = EventHeader {
                schema_version: 1,
                event_id,
                agent_id: AGENT.to_string(),
                stream,
                stream_seq: seq,
                clock: Hlc::new(1000, i as u32, 1),
                parents: parent.into_iter().collect(),
                event_type: d.event_type.clone(),
                payload_schema_uri: d.payload_schema_uri(),
            };
            let cbor = ciborium::value::Value::serialized(&d.payload).unwrap();
            let event = AtepEvent::seal(header, EventPayload(cbor), sk, key_id.clone()).unwrap();
            parent = Some(event.causal_hash);
            events.push(event);
        }
        store.append_batch(stream, &events).unwrap();
    }
}

fn tool_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("send_email".to_string()),
        Just("http_post".to_string()),
        Just("delete_record".to_string()),
        Just("set_system_prompt".to_string()),
        Just("read_file".to_string()),
        Just("get_weather".to_string()),
    ]
}

prop_compose! {
    fn call_strategy()(
        tool in tool_strategy(),
        untrusted in any::<bool>(),
        body in "[ -~]{0,16}",
    ) -> ToolCall {
        serde_json::from_value(serde_json::json!({
            "tool": tool,
            "provenance": if untrusted { "untrusted" } else { "trusted" },
            "arguments": { "url": "https://x.example/p", "to": "z@gmail.com", "body": body, "path": "a/b.txt" },
        })).unwrap()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any gate passage produces a chain that verifies under the signer's key.
    #[test]
    fn gate_events_seal_and_verify(call in call_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        let sk = fixed_key();
        let gate = ToolBoundaryGate::new(GateRuleSet::default());
        let out = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
        let descriptors = gate_descriptors(&call, &out);

        let mut store = AtepStore::open_or_init(dir.path(), AGENT).unwrap();
        seal_and_append(&mut store, &sk, &descriptors);

        // Reopen and verify every signature + segment merkle root.
        let store2 = AtepStore::open_or_init(dir.path(), AGENT).unwrap();
        let report = store2.verify_all(&sk.verifying_key()).unwrap();
        prop_assert!(report.valid);
        prop_assert_eq!(report.total_events, descriptors.len() as u64);
        prop_assert_eq!(report.verified_signatures, descriptors.len() as u64);
    }
}

/// A tampered payload breaks verification — the chain is genuinely
/// integrity-protected, not merely well-formed.
#[test]
fn tampering_breaks_verification() {
    let dir = tempfile::tempdir().unwrap();
    let sk = fixed_key();
    let call: ToolCall = serde_json::from_value(serde_json::json!({
        "tool": "delete_record", "provenance": "trusted", "arguments": { "id": 1 }
    }))
    .unwrap();
    let gate = ToolBoundaryGate::new(GateRuleSet::default());
    let out = gate.evaluate(&call, &PolicyBundle::default()).unwrap();
    let descriptors = gate_descriptors(&call, &out);

    let mut store = AtepStore::open_or_init(dir.path(), AGENT).unwrap();
    seal_and_append(&mut store, &sk, &descriptors);

    // A *different* key must not verify the chain.
    let wrong = SigningKey::from_bytes(&[9u8; 32]);
    let store2 = AtepStore::open_or_init(dir.path(), AGENT).unwrap();
    assert!(store2.verify_all(&wrong.verifying_key()).is_err());
}
