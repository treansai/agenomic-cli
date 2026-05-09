//! Property test: `Hlc::tick_after` produces a strictly monotonic sequence.

use agenomic_atep::Hlc;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn tick_after_is_monotonic(
        ticks in proptest::collection::vec(0u64..1_000_000_000u64, 1..50)
    ) {
        let mut local = Hlc::new(0, 0, 1);
        let mut prev = local;
        for t in ticks {
            let recv = Hlc::new(t, 0, 2);
            local = local.tick_after(recv, t);
            prop_assert!(local > prev, "expected {:?} > {:?}", local, prev);
            prev = local;
        }
    }
}
