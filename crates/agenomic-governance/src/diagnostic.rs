//! `DiagnosticAgent` — Mode 1 of Point 4.
//!
//! Groups flagged traces by `(signal, skill)`, mines keywords from their
//! snippets, and emits a deterministic [`Cluster`] list. **No mutation, no
//! LLM call** — clustering is keyword-frequency + grouping so the output is
//! byte-stable for a fixed input.

use std::collections::BTreeMap;

use crate::types::{Cluster, FlaggedTrace};

/// Stateless engine; instantiated for ergonomics with builder-shaped configs
/// later.
#[derive(Debug, Default, Clone)]
pub struct DiagnosticAgent;

impl DiagnosticAgent {
    pub fn new() -> Self {
        Self
    }

    /// Cluster `traces` and return the clusters sorted by size (descending),
    /// then by id (ascending) for determinism. Each call is pure: the same
    /// input always yields the same output.
    pub fn cluster(&self, traces: &[FlaggedTrace]) -> Vec<Cluster> {
        // Group by (signal_label, skill). Using BTreeMap keeps iteration
        // deterministic; the cluster id is derived from the actual member
        // trace ids, so insertion order can't leak into output.
        let mut groups: BTreeMap<(String, String), Vec<&FlaggedTrace>> = BTreeMap::new();
        for t in traces {
            let key = (t.signal.label().to_string(), t.skill.clone());
            groups.entry(key).or_default().push(t);
        }

        let mut clusters: Vec<Cluster> = groups
            .into_iter()
            .map(|((_, skill), members)| build_cluster(skill, members))
            .collect();

        // Largest first, then by id for ties — deterministic and most-useful-first.
        clusters.sort_by(|a, b| b.size.cmp(&a.size).then(a.id.cmp(&b.id)));
        clusters
    }
}

fn build_cluster(skill: String, members: Vec<&FlaggedTrace>) -> Cluster {
    let signal = members[0].signal.clone();
    let mut trace_ids: Vec<String> = members.iter().map(|m| m.trace_id.clone()).collect();
    trace_ids.sort();
    trace_ids.dedup();

    let keywords = mine_keywords(&members);
    let exemplars = pick_exemplars(&members, &keywords);

    // Cluster id pins the (signal, skill, sorted_members) tuple so two runs
    // over the same flagged corpus produce identical ids — required for
    // downstream attestation chaining.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"cluster\0");
    hasher.update(signal.label().as_bytes());
    hasher.update(b"\0");
    hasher.update(skill.as_bytes());
    for id in &trace_ids {
        hasher.update(b"\0");
        hasher.update(id.as_bytes());
    }
    let id = hex::encode(&hasher.finalize().as_bytes()[..16]);

    Cluster {
        id,
        signal,
        skill,
        size: trace_ids.len(),
        members: trace_ids,
        keywords,
        exemplars,
    }
}

/// Tokenise + stopword-filter the input + output snippets, then rank words by
/// frequency. Ties broken alphabetically; truncated to the top 8.
fn mine_keywords(members: &[&FlaggedTrace]) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for m in members {
        for source in [&m.input_snippet, &m.output_snippet] {
            for token in tokenise(source) {
                *counts.entry(token).or_default() += 1;
            }
        }
    }
    let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    pairs.into_iter().take(8).map(|(w, _)| w).collect()
}

/// Pick up to 3 exemplar snippets: the first member-snippet containing each
/// of the cluster's three most-frequent keywords. Falls back to the first
/// few snippets when no keyword matches.
fn pick_exemplars(members: &[&FlaggedTrace], keywords: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

    for kw in keywords.iter().take(3) {
        for m in members {
            for snippet in [&m.input_snippet, &m.output_snippet] {
                if !snippet.is_empty()
                    && snippet
                        .to_ascii_lowercase()
                        .contains(&kw.to_ascii_lowercase())
                    && !seen.contains(snippet.as_str())
                {
                    seen.insert(snippet.as_str());
                    out.push(snippet.clone());
                    break;
                }
            }
            if out.len() >= 3 {
                break;
            }
        }
        if out.len() >= 3 {
            break;
        }
    }
    if out.is_empty() {
        for m in members.iter().take(3) {
            if !m.input_snippet.is_empty() {
                out.push(m.input_snippet.clone());
            } else if !m.output_snippet.is_empty() {
                out.push(m.output_snippet.clone());
            }
        }
    }
    out
}

/// Very small English stopword list — enough to surface signal-bearing words
/// (refund, escalation, partial, …) without dragging in NLP dependencies.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "had", "has", "have",
    "he", "her", "his", "i", "in", "is", "it", "its", "me", "my", "no", "not", "of", "on", "or",
    "our", "she", "so", "some", "than", "that", "the", "their", "them", "they", "this", "to",
    "was", "we", "were", "what", "when", "which", "who", "will", "with", "would", "you", "your",
];

fn tokenise(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(|tok| {
            let lower = tok.to_ascii_lowercase();
            if lower.len() < 3 || STOPWORDS.contains(&lower.as_str()) {
                None
            } else {
                Some(lower)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FailureSignal;

    fn trace(id: &str, signal: FailureSignal, skill: &str, input: &str) -> FlaggedTrace {
        FlaggedTrace {
            trace_id: id.into(),
            agent_id: "agent://x/y".into(),
            skill: skill.into(),
            skill_version: Some("@7".into()),
            signal,
            input_snippet: input.into(),
            output_snippet: String::new(),
        }
    }

    #[test]
    fn groups_by_signal_and_skill() {
        let traces = vec![
            trace(
                "t1",
                FailureSignal::Escalation,
                "classify",
                "refund partial",
            ),
            trace(
                "t2",
                FailureSignal::Escalation,
                "classify",
                "refund partial advance",
            ),
            trace("t3", FailureSignal::Complaint, "classify", "complaint case"),
            trace(
                "t4",
                FailureSignal::Escalation,
                "compensation",
                "credit only",
            ),
        ];
        let clusters = DiagnosticAgent::new().cluster(&traces);
        assert_eq!(clusters.len(), 3);
        // Largest first (escalation/classify has 2 members).
        assert_eq!(clusters[0].size, 2);
        assert_eq!(clusters[0].skill, "classify");
        assert!(matches!(clusters[0].signal, FailureSignal::Escalation));
    }

    #[test]
    fn is_deterministic_across_runs() {
        let traces = vec![
            trace(
                "t2",
                FailureSignal::Escalation,
                "classify",
                "refund partial",
            ),
            trace(
                "t1",
                FailureSignal::Escalation,
                "classify",
                "refund partial",
            ),
        ];
        let a = DiagnosticAgent::new().cluster(&traces);
        // Reverse order in input must not change output.
        let mut reversed = traces.clone();
        reversed.reverse();
        let b = DiagnosticAgent::new().cluster(&reversed);
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_trace_ids_are_deduplicated() {
        let traces = vec![
            trace("t1", FailureSignal::Escalation, "classify", "refund"),
            trace("t1", FailureSignal::Escalation, "classify", "refund again"),
        ];
        let clusters = DiagnosticAgent::new().cluster(&traces);
        assert_eq!(clusters[0].size, 1, "duplicate trace_id collapsed");
    }

    #[test]
    fn keywords_are_stopword_filtered_and_ranked() {
        let traces = vec![
            trace(
                "t1",
                FailureSignal::Escalation,
                "classify",
                "the client wants a refund and a partial credit",
            ),
            trace(
                "t2",
                FailureSignal::Escalation,
                "classify",
                "client refund partial",
            ),
        ];
        let c = &DiagnosticAgent::new().cluster(&traces)[0];
        assert!(c.keywords.contains(&"refund".to_string()));
        assert!(c.keywords.contains(&"partial".to_string()));
        assert!(!c.keywords.contains(&"the".to_string()));
        assert!(!c.keywords.contains(&"and".to_string()));
    }

    #[test]
    fn other_signal_keeps_distinct_label() {
        let t1 = trace("t1", FailureSignal::Other("foo".into()), "s", "x");
        let t2 = trace("t2", FailureSignal::Other("bar".into()), "s", "x");
        let clusters = DiagnosticAgent::new().cluster(&[t1, t2]);
        assert_eq!(clusters.len(), 2);
    }
}
