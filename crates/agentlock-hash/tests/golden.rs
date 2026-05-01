//! Golden test for the canonical Merkle algorithm.
//!
//! If this test ever fails, you have made a BREAKING change to the bundle
//! hashing spec. Bump `MANIFEST_VERSION` and update the golden value with the
//! new known-good hash.

use agentlock_hash::compute_manifest_from_pairs;

const GOLDEN_PAIRS: &[(&str, &[u8])] = &[
    ("a/leaf.txt", b"alpha"),
    ("a/sibling.txt", b"beta"),
    ("b/c/deep.txt", b"deep"),
    ("z.txt", b"zulu"),
];

/// Golden hex root computed deterministically from `GOLDEN_PAIRS` with
/// the v0.1 algorithm. Captured from a passing run on commit-of-record.
const GOLDEN_ROOT: &str = "14d3f4988a0ed626e299426f6ac410796ca91199e2cd0ed50d4034de27f5c738";

#[test]
fn golden_root_is_stable() {
    let pairs: Vec<(String, Vec<u8>)> = GOLDEN_PAIRS
        .iter()
        .map(|(p, c)| (p.to_string(), c.to_vec()))
        .collect();
    let m = compute_manifest_from_pairs(pairs).unwrap();
    if GOLDEN_ROOT == "GOLDEN_ROOT_PLACEHOLDER" {
        // First run: print so we can capture.
        eprintln!("captured golden root: {}", m.root_hash);
        return;
    }
    assert_eq!(
        m.root_hash, GOLDEN_ROOT,
        "BREAKING CHANGE to bundle hashing detected. Bump MANIFEST_VERSION."
    );
}
