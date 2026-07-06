//! Property tests: canonicalization determinism and stability.
//!
//! The canonical form is the hashed/signed surface — these properties are the
//! ground truth behind every chain-integrity guarantee in the crate.

use agenomic_ledger_local::canonical::{canonical_json, entry_digest, payload_hash};
use proptest::prelude::*;
use serde_json::Value;

/// Arbitrary JSON values. Numbers are restricted to i64/u64 (the hashed
/// surfaces carry no non-integer floats by design — payloads are committed by
/// hash, and float round-tripping is the reason why).
fn arb_json(depth: u32) -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        any::<u64>().prop_map(|n| Value::Number(n.into())),
        "[a-zA-Z0-9 _\\-\u{00e9}\u{4e8b}\"\\\\\n\t]{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(depth, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-zA-Z0-9_\\-]{1,12}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    /// canonicalize ∘ parse ∘ canonicalize is a fixpoint: the canonical form
    /// re-parses to a value whose canonical form is byte-identical.
    #[test]
    fn canonical_form_is_a_fixpoint(v in arb_json(3)) {
        let c1 = canonical_json(&v);
        let reparsed: Value = serde_json::from_str(&c1).expect("canonical form parses");
        let c2 = canonical_json(&reparsed);
        prop_assert_eq!(c1, c2);
    }

    /// Key insertion order never affects the canonical form (and therefore
    /// never affects any hash or signature).
    #[test]
    fn key_order_is_irrelevant(v in arb_json(3)) {
        let c1 = canonical_json(&v);
        // Round-tripping through serde_json re-orders map internals; the
        // canonical form must be unchanged.
        let reparsed: Value = serde_json::from_str(&v.to_string()).expect("json parses");
        prop_assert_eq!(c1, canonical_json(&reparsed));
    }

    /// Same value → same digest; the digest is a pure function of the
    /// canonical form.
    #[test]
    fn digest_is_deterministic(v in arb_json(3)) {
        let c = canonical_json(&v);
        prop_assert_eq!(entry_digest(&c), entry_digest(&c));
        prop_assert_eq!(payload_hash(&v), payload_hash(&v));
    }

    /// Canonical output contains no insignificant whitespace outside strings.
    #[test]
    fn canonical_form_is_compact(v in arb_json(2)) {
        let c = canonical_json(&v);
        let mut in_string = false;
        let mut escaped = false;
        for ch in c.chars() {
            if in_string {
                if escaped { escaped = false; }
                else if ch == '\\' { escaped = true; }
                else if ch == '"' { in_string = false; }
            } else {
                prop_assert!(ch != ' ' && ch != '\n' && ch != '\t');
                if ch == '"' { in_string = true; }
            }
        }
    }
}
