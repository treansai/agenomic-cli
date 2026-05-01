//! Property test: arbitrary events seal+verify roundtrip and tampering breaks
//! verification.

use agentlock_atep::{AtepEvent, EventHeader, EventPayload, Hlc, StreamId};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand_core::OsRng;

fn arb_stream() -> impl Strategy<Value = StreamId> {
    prop_oneof![
        Just(StreamId::Identity),
        Just(StreamId::Capability),
        Just(StreamId::Knowledge),
        Just(StreamId::Policy),
        Just(StreamId::Runtime),
        Just(StreamId::Interaction),
        Just(StreamId::Governance),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn seal_verify_roundtrip(
        seq in 0u64..1_000_000u64,
        ms in 0u64..1_000_000u64,
        text in "[a-z0-9]{0,32}",
        stream in arb_stream(),
    ) {
        let sk = SigningKey::generate(&mut OsRng);
        let h = EventHeader {
            schema_version: 1,
            event_id: ulid::Ulid::new().to_bytes(),
            agent_id: "agent://acme/foo".into(),
            stream,
            stream_seq: seq,
            clock: Hlc::new(ms, 0, 1),
            parents: vec![],
            event_type: format!("{}.evt", stream.label()),
            payload_schema_uri: "atep://schemas/v1/test".into(),
        };
        let p = EventPayload(ciborium::value::Value::Text(text));
        let e = AtepEvent::seal(h, p, &sk, "k1".into()).unwrap();
        e.verify(&sk.verifying_key()).unwrap();
    }
}
