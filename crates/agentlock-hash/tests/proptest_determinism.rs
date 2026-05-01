//! Property test: hashing twice yields the same root for any random
//! (path, content) corpus.

use agentlock_hash::compute_manifest_from_pairs;
use proptest::prelude::*;

fn arb_segment() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,5}".prop_map(|s| s.to_string())
}

fn arb_path() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_segment(), 1..4).prop_map(|segs| segs.join("/"))
}

fn arb_content() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..64)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn hashing_is_deterministic(
        files in proptest::collection::vec((arb_path(), arb_content()), 1..20)
    ) {
        // Deduplicate paths (last write wins) and sort
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        for (p, c) in files {
            map.insert(p, c);
        }
        let pairs: Vec<(String, Vec<u8>)> = map.into_iter().collect();

        let m1 = compute_manifest_from_pairs(pairs.clone()).unwrap();
        let m2 = compute_manifest_from_pairs(pairs).unwrap();
        prop_assert_eq!(m1.root_hash, m2.root_hash);
    }
}
