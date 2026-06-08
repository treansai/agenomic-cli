//! Property-based tests for `agent://` URI parsing.
//!
//! Two invariants are checked:
//! 1. Round-trip: every reference generated from valid components parses to
//!    the same value its [`canonical`](agenomic_os::AgentReference::canonical)
//!    form emits.
//! 2. Total parsing: arbitrary bytes never panic the parser.

use agenomic_os::{AgentReference, Qualifier};
use proptest::prelude::*;

fn segment_strategy() -> impl Strategy<Value = String> {
    // [a-z0-9-] with no leading/trailing dash and no '.'/'..'
    "[a-z0-9][a-z0-9-]{0,30}[a-z0-9]|[a-z0-9]".prop_filter(
        "no leading/trailing dash",
        |s: &String| {
            !s.starts_with('-') && !s.ends_with('-') && s != "." && s != ".."
        },
    )
}

fn version_strategy() -> impl Strategy<Value = String> {
    // Conservative semver-ish: digit-led, then alnum/./-
    "[0-9][0-9a-zA-Z._-]{0,15}"
}

fn channel_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,10}"
}

fn hex_strategy() -> impl Strategy<Value = String> {
    "[0-9a-f]{4,32}"
}

fn qualifier_strategy() -> impl Strategy<Value = Option<Qualifier>> {
    prop_oneof![
        Just(None),
        version_strategy().prop_map(|v| Some(Qualifier::Version(v))),
        channel_strategy().prop_map(|c| Some(Qualifier::Channel(c))),
        hex_strategy().prop_map(|h| Some(Qualifier::Digest {
            algorithm: "sha256".into(),
            hex: h
        })),
    ]
}

proptest! {
    #[test]
    fn canonical_roundtrip(
        org in segment_strategy(),
        slug in segment_strategy(),
        qualifier in qualifier_strategy(),
    ) {
        let mut s = format!("agent://{org}/{slug}");
        if let Some(q) = &qualifier {
            s.push('@');
            s.push_str(&q.as_suffix());
        }
        let parsed: AgentReference = s.parse().expect("generated input must parse");
        let again: AgentReference = parsed.canonical().parse().expect("canonical must round-trip");
        prop_assert_eq!(parsed, again);
    }

    #[test]
    fn arbitrary_strings_never_panic(input in "\\PC{0,80}") {
        // Parser must be total: either Ok or OsError, never panic.
        let _ = input.parse::<AgentReference>();
    }

    #[test]
    fn parser_accepts_only_valid_segments(
        bad_char in "[A-Z!@#$%^&*()/?\\\\]",
        good in segment_strategy(),
    ) {
        let candidate = format!("agent://{}{}/{}", good, bad_char, good);
        prop_assert!(candidate.parse::<AgentReference>().is_err());
    }
}
