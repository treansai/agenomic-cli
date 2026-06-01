//! Property tests for the merge algorithm (§3.4 / spec §6): merge is idempotent
//! and hand-edits are never silently overwritten.

use agenomic_detect::{merge, DetectedGenome, Provenance, SourceRecord};
use proptest::prelude::*;

/// A genome varying only the two required scalars the properties exercise.
fn genome(name: &str, provider: &str) -> DetectedGenome {
    let mut g = DetectedGenome::defaults();
    g.evidence.clear();
    g.agent_name = name.to_string();
    g.model_provider = provider.to_string();
    g
}

/// A provenance recording the given `(field, value)` prior-detection outputs.
fn prov(pairs: &[(&str, &str)]) -> Provenance {
    Provenance {
        detector_version: "0.1.0".into(),
        detected_at: "2026-05-31T00:00:00Z".into(),
        sources: pairs
            .iter()
            .map(|(f, v)| SourceRecord {
                field: (*f).into(),
                value: (*v).into(),
                from: "pyproject".into(),
                evidence: String::new(),
            })
            .collect(),
        frozen: vec![],
        last_update: None,
    }
}

proptest! {
    /// merge(merge(a, b), b) == merge(a, b): re-running update with the same
    /// detection (and the provenance it wrote) is a fixed point.
    #[test]
    fn merge_is_idempotent(
        cn in "[a-c]", cp in "[a-c]",
        dn in "[a-c]", dp in "[a-c]",
        pn in "[a-c]", pp in "[a-c]",
    ) {
        let current = genome(&cn, &cp);
        let detected = genome(&dn, &dp);
        let prior = prov(&[("agent.name", &pn), ("runtime.model_provider", &pp)]);

        let m1 = merge(&current, &detected, Some(&prior), false);

        // After m1, the sidecar records THIS detection's outputs + frozen set.
        let mut prior2 = prov(&[("agent.name", &dn), ("runtime.model_provider", &dp)]);
        prior2.frozen = m1.frozen.clone();
        let m2 = merge(&m1.merged, &detected, Some(&prior2), false);

        prop_assert_eq!(&m1.merged, &m2.merged);
    }

    /// A field whose current value differs from the prior detection output is a
    /// hand-edit and must survive the merge unchanged.
    #[test]
    fn hand_edits_never_overwritten(cn in "[a-c]", dn in "[a-c]", pn in "[a-c]") {
        let current = genome(&cn, "p");
        let detected = genome(&dn, "p");
        let prior = prov(&[("agent.name", &pn)]);

        let m = merge(&current, &detected, Some(&prior), false);

        if cn != pn {
            // current was edited away from what detection last produced → kept.
            prop_assert_eq!(m.merged.agent_name, cn);
        }
    }
}
