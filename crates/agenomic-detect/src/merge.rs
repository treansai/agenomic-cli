//! Merge a fresh detection into an existing bundle, preserving hand edits (§3.4).
//!
//! The decision for each field uses three inputs: `current` (the value in the
//! existing `genome.yaml`), `detected` (what detection produces now), and the
//! prior detection output recorded in the provenance sidecar's `sources`. A
//! field is a hand-edit — and is kept — when `current` differs from both
//! `detected` and the prior detection output; otherwise detection wins.
//!
//! The merge is idempotent: `merge(merge(a, b), b) == merge(a, b)`.

use std::collections::{HashMap, HashSet};

use crate::model::{DetectedGenome, ToolEntry};
use crate::provenance::Provenance;

/// One change the merge applied, rendered for the commit body (§3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Scalar {
        field: String,
        before: String,
        after: String,
    },
    ToolAdded {
        name: String,
        kind: String,
        version: Option<String>,
    },
    ToolRemoved {
        name: String,
    },
}

impl Change {
    /// Render as a commit-body line, e.g. `runtime.model_provider: anthropic → openai`.
    pub fn render(&self) -> String {
        match self {
            Change::Scalar {
                field,
                before,
                after,
            } => format!("{field}: {before} → {after}"),
            Change::ToolAdded {
                name,
                kind,
                version,
            } => match version {
                Some(v) => format!("tools[+]: {name} ({kind}, {v})"),
                None => format!("tools[+]: {name} ({kind})"),
            },
            Change::ToolRemoved { name } => format!("tools[-]: {name}"),
        }
    }
}

/// Outcome of a merge.
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// The merged genome to write. Its `evidence` carries the *current* detection
    /// output (so the rewritten provenance lets the next merge spot hand-edits).
    pub merged: DetectedGenome,
    /// Changes detection applied (drives the commit body and the "no changes" exit).
    pub changes: Vec<Change>,
    /// Fields kept because they were hand-edited.
    pub frozen: Vec<String>,
}

impl MergeResult {
    /// True when detection produced no changes (drives `agm update` exit 1, §3.7).
    pub fn is_noop(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Merge `detected` into `current`, using `prior` (the provenance sidecar) to
/// distinguish hand-edits. `prune` drops list items that detection produced
/// before but no longer does; without it they are kept.
pub fn merge(
    current: &DetectedGenome,
    detected: &DetectedGenome,
    prior: Option<&Provenance>,
    prune: bool,
) -> MergeResult {
    let prior_scalar = prior_scalar_map(prior);
    let prior_tools = prior_tool_names(prior);

    let mut changes: Vec<Change> = Vec::new();
    let mut frozen: Vec<String> = Vec::new();

    // Start from current; overlay merged scalar decisions.
    let mut merged = current.clone();

    macro_rules! merge_req {
        ($field:literal, $accessor:ident) => {
            merged.$accessor = pick(
                $field,
                Some(&current.$accessor),
                Some(&detected.$accessor),
                &prior_scalar,
                &mut changes,
                &mut frozen,
            )
            .unwrap_or_else(|| current.$accessor.clone());
        };
    }
    macro_rules! merge_opt {
        ($field:literal, $accessor:ident) => {
            merged.$accessor = pick(
                $field,
                current.$accessor.as_deref(),
                detected.$accessor.as_deref(),
                &prior_scalar,
                &mut changes,
                &mut frozen,
            );
        };
    }

    merge_req!("agent.id", agent_id);
    merge_req!("agent.name", agent_name);
    merge_req!("agent.domain", domain);
    merge_req!("agent.criticality", criticality);
    merge_opt!("description", description);
    merge_opt!("runtime.framework", framework);
    merge_opt!("runtime.runtime_kind", runtime_kind);
    merge_req!("runtime.model_provider", model_provider);
    merge_req!("runtime.model_id", model_id);
    merge_opt!("runtime.entrypoint", entrypoint);

    merged.tools = merge_tools(
        &current.tools,
        &detected.tools,
        &prior_tools,
        prune,
        &mut changes,
    );
    // authors / skills / knowledge / policies: detection rarely produces these;
    // set-merge by value, keeping current entries (union).
    merged.authors = union_keep(&current.authors, &detected.authors);
    merged.skills = union_keep(&current.skills, &detected.skills);
    merged.knowledge = union_keep(&current.knowledge, &detected.knowledge);
    merged.policies = union_keep(&current.policies, &detected.policies);

    // The rewritten provenance should record THIS detection run.
    merged.evidence = detected.evidence.clone();

    frozen.sort();
    frozen.dedup();
    MergeResult {
        merged,
        changes,
        frozen,
    }
}

/// Decide one scalar/optional field. Returns the value to keep.
fn pick(
    field: &str,
    current: Option<&str>,
    detected: Option<&str>,
    prior: &HashMap<String, String>,
    changes: &mut Vec<Change>,
    frozen: &mut Vec<String>,
) -> Option<String> {
    if current == detected {
        return current.map(str::to_string);
    }
    let prior_val = prior.get(field).map(String::as_str);
    if prior_val == current {
        // Current is unchanged since the last detection → detection is authoritative.
        changes.push(Change::Scalar {
            field: field.to_string(),
            before: current.unwrap_or("(none)").to_string(),
            after: detected.unwrap_or("(none)").to_string(),
        });
        detected.map(str::to_string)
    } else {
        // Current differs from both detection and the prior detection → hand-edited.
        frozen.push(field.to_string());
        current.map(str::to_string)
    }
}

fn merge_tools(
    current: &[ToolEntry],
    detected: &[ToolEntry],
    prior_tools: &HashSet<String>,
    prune: bool,
    changes: &mut Vec<Change>,
) -> Vec<ToolEntry> {
    let current_names: HashSet<&str> = current.iter().map(|t| t.name.as_str()).collect();
    let detected_names: HashSet<&str> = detected.iter().map(|t| t.name.as_str()).collect();

    let mut result: Vec<ToolEntry> = Vec::new();
    // Detected tools are authoritative for kind/version.
    for t in detected {
        if !current_names.contains(t.name.as_str()) {
            changes.push(Change::ToolAdded {
                name: t.name.clone(),
                kind: t.kind.label().to_string(),
                version: t.version.clone(),
            });
        }
        result.push(t.clone());
    }
    // Current-only tools: keep, unless they were detected before and --prune is set.
    for t in current {
        if detected_names.contains(t.name.as_str()) {
            continue;
        }
        if prune && prior_tools.contains(&t.name) {
            changes.push(Change::ToolRemoved {
                name: t.name.clone(),
            });
        } else {
            result.push(t.clone());
        }
    }
    result.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    result
}

/// Union by value, preserving current's items and appending new detected ones.
fn union_keep(current: &[String], detected: &[String]) -> Vec<String> {
    let mut out = current.to_vec();
    for d in detected {
        if !out.contains(d) {
            out.push(d.clone());
        }
    }
    out
}

fn prior_scalar_map(prior: Option<&Provenance>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(p) = prior {
        for s in &p.sources {
            if !s.field.starts_with("tools[") {
                map.insert(s.field.clone(), s.value.clone());
            }
        }
    }
    map
}

fn prior_tool_names(prior: Option<&Provenance>) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(p) = prior {
        for s in &p.sources {
            if s.field.starts_with("tools[") {
                set.insert(s.value.clone());
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Source, ToolKind};
    use crate::provenance::SourceRecord;

    fn prov(pairs: &[(&str, &str)]) -> Provenance {
        Provenance {
            detector_version: "0.1.0".into(),
            detected_at: "2026-05-31T00:00:00Z".into(),
            sources: pairs
                .iter()
                .map(|(f, v)| SourceRecord {
                    field: f.to_string(),
                    value: v.to_string(),
                    from: "pyproject".into(),
                    evidence: String::new(),
                })
                .collect(),
            frozen: vec![],
            last_update: None,
        }
    }

    fn tool(name: &str, kind: ToolKind, v: &str) -> ToolEntry {
        ToolEntry {
            name: name.into(),
            kind,
            version: Some(v.into()),
        }
    }

    #[test]
    fn provider_swap_updates_when_unchanged_since_detection() {
        let mut current = DetectedGenome::defaults();
        current.model_provider = "anthropic".into();
        current.model_id = "claude-sonnet-4-6".into();
        let mut detected = DetectedGenome::defaults();
        detected.model_provider = "openai".into();
        detected.model_id = "gpt-4o".into();
        let prior = prov(&[
            ("runtime.model_provider", "anthropic"),
            ("runtime.model_id", "claude-sonnet-4-6"),
        ]);

        let r = merge(&current, &detected, Some(&prior), false);
        assert_eq!(r.merged.model_provider, "openai");
        assert_eq!(r.merged.model_id, "gpt-4o");
        assert!(r.frozen.is_empty());
        assert_eq!(r.changes.len(), 2);
    }

    #[test]
    fn hand_edit_is_preserved() {
        let mut current = DetectedGenome::defaults();
        current.agent_name = "hand-named".into(); // user edited
        let mut detected = DetectedGenome::defaults();
        detected.agent_name = "detected-name".into();
        // Prior detection produced "old-detected", i.e. user changed it away.
        let prior = prov(&[("agent.name", "old-detected")]);

        let r = merge(&current, &detected, Some(&prior), false);
        assert_eq!(r.merged.agent_name, "hand-named"); // kept
        assert!(r.frozen.contains(&"agent.name".to_string()));
    }

    #[test]
    fn tool_added_and_pruned() {
        let mut current = DetectedGenome::defaults();
        current.tools = vec![
            tool("ruff", ToolKind::Linter, ">=0.6.0"),
            tool("pylint", ToolKind::Linter, ">=3"),
        ];
        let mut detected = DetectedGenome::defaults();
        detected.tools = vec![
            tool("ruff", ToolKind::Linter, ">=0.6.0"),
            tool("bandit", ToolKind::Security, ">=1.7.9"),
        ];
        let prior = prov(&[("tools[0]", "ruff"), ("tools[1]", "pylint")]);

        // Without prune: pylint kept (removed-upstream), bandit added.
        let r = merge(&current, &detected, Some(&prior), false);
        let names: Vec<&str> = r.merged.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"pylint") && names.contains(&"bandit") && names.contains(&"ruff"));
        assert!(r
            .changes
            .iter()
            .any(|c| matches!(c, Change::ToolAdded { name, .. } if name == "bandit")));

        // With prune: pylint (detected-before, now gone) dropped.
        let r = merge(&current, &detected, Some(&prior), true);
        let names: Vec<&str> = r.merged.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"pylint"));
        assert!(r
            .changes
            .iter()
            .any(|c| matches!(c, Change::ToolRemoved { name } if name == "pylint")));
    }

    #[test]
    fn no_change_is_noop() {
        let mut g = DetectedGenome::defaults();
        g.evidence.clear();
        let r = merge(&g, &g, None, false);
        assert!(r.is_noop());
    }

    #[test]
    fn merge_is_idempotent() {
        let mut current = DetectedGenome::defaults();
        current.agent_name = "hand".into();
        current.model_provider = "anthropic".into();
        let mut detected = DetectedGenome::defaults();
        detected.agent_name = "auto".into();
        detected.model_provider = "openai".into();
        detected.record(Source::Pyproject, "runtime.model_provider", "openai", "dep");
        let prior = prov(&[
            ("agent.name", "old"),
            ("runtime.model_provider", "anthropic"),
        ]);

        let m1 = merge(&current, &detected, Some(&prior), false);
        // Provenance after m1 = this detection's sources + frozen.
        let mut p2 = Provenance::from_detection(&m1.merged, "t".into());
        p2.frozen = m1.frozen.clone();
        let m2 = merge(&m1.merged, &detected, Some(&p2), false);
        assert_eq!(m1.merged, m2.merged);
    }
}
