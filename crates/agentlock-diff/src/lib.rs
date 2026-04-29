use std::collections::{BTreeMap, BTreeSet};

use agentlock_core::LoadedBundle;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleDiff {
    pub changed_prompts: Vec<String>,
    pub tool_changes: ChangeSet,
    pub policy_changes: ChangeSet,
    pub knowledge_changes: ChangeSet,
    pub model_changes: Vec<String>,
}

impl BundleDiff {
    pub fn is_empty(&self) -> bool {
        self.changed_prompts.is_empty()
            && self.tool_changes == ChangeSet::default()
            && self.policy_changes == ChangeSet::default()
            && self.knowledge_changes == ChangeSet::default()
            && self.model_changes.is_empty()
    }
}

pub fn diff_bundles(old: &LoadedBundle, new: &LoadedBundle) -> BundleDiff {
    BundleDiff {
        changed_prompts: diff_prompt_paths(&old.prompts, &new.prompts),
        tool_changes: diff_named_items(
            old.genome
                .tools
                .iter()
                .map(|tool| (tool.id.clone(), tool))
                .collect(),
            new.genome
                .tools
                .iter()
                .map(|tool| (tool.id.clone(), tool))
                .collect(),
        ),
        policy_changes: diff_named_items(
            old.behavior_contract
                .contract
                .policies
                .iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            new.behavior_contract
                .contract
                .policies
                .iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
        ),
        knowledge_changes: diff_named_items(
            old.genome
                .knowledge_snapshots
                .iter()
                .map(|snapshot| (snapshot.id.clone(), snapshot))
                .collect(),
            new.genome
                .knowledge_snapshots
                .iter()
                .map(|snapshot| (snapshot.id.clone(), snapshot))
                .collect(),
        ),
        model_changes: diff_model(old, new),
    }
}

pub fn render_diff(diff: &BundleDiff) -> String {
    if diff.is_empty() {
        return "No bundle changes detected.".to_owned();
    }

    let mut lines = Vec::new();

    if !diff.changed_prompts.is_empty() {
        lines.push("Changed prompts:".to_owned());
        for path in &diff.changed_prompts {
            lines.push(format!("  - {path}"));
        }
    }

    append_change_set(&mut lines, "Changed tools", &diff.tool_changes);
    append_change_set(&mut lines, "Changed policies", &diff.policy_changes);
    append_change_set(
        &mut lines,
        "Changed knowledge snapshots",
        &diff.knowledge_changes,
    );

    if !diff.model_changes.is_empty() {
        lines.push("Changed model config:".to_owned());
        for change in &diff.model_changes {
            lines.push(format!("  - {change}"));
        }
    }

    lines.join("\n")
}

fn diff_prompt_paths(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
) -> Vec<String> {
    let keys = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    keys.into_iter()
        .filter(|key| old.get(key) != new.get(key))
        .collect()
}

fn diff_model(old: &LoadedBundle, new: &LoadedBundle) -> Vec<String> {
    let mut changes = Vec::new();

    if old.genome.model.provider != new.genome.model.provider {
        changes.push(format!(
            "provider: {} -> {}",
            old.genome.model.provider, new.genome.model.provider
        ));
    }
    if old.genome.model.model != new.genome.model.model {
        changes.push(format!(
            "model: {} -> {}",
            old.genome.model.model, new.genome.model.model
        ));
    }
    if old.genome.model.temperature != new.genome.model.temperature {
        changes.push(format!(
            "temperature: {:?} -> {:?}",
            old.genome.model.temperature, new.genome.model.temperature
        ));
    }
    if old.genome.model.max_input_tokens != new.genome.model.max_input_tokens {
        changes.push(format!(
            "max_input_tokens: {:?} -> {:?}",
            old.genome.model.max_input_tokens, new.genome.model.max_input_tokens
        ));
    }
    if old.genome.model.max_output_tokens != new.genome.model.max_output_tokens {
        changes.push(format!(
            "max_output_tokens: {:?} -> {:?}",
            old.genome.model.max_output_tokens, new.genome.model.max_output_tokens
        ));
    }

    changes
}

fn diff_named_items<T>(old: BTreeMap<String, &T>, new: BTreeMap<String, &T>) -> ChangeSet
where
    T: PartialEq,
{
    let keys = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = ChangeSet::default();

    for key in keys {
        match (old.get(&key), new.get(&key)) {
            (None, Some(_)) => changes.added.push(key),
            (Some(_), None) => changes.removed.push(key),
            (Some(old_item), Some(new_item)) if old_item != new_item => changes.modified.push(key),
            _ => {}
        }
    }

    changes
}

fn append_change_set(lines: &mut Vec<String>, title: &str, changes: &ChangeSet) {
    if changes == &ChangeSet::default() {
        return;
    }

    lines.push(format!("{title}:"));
    for added in &changes.added {
        lines.push(format!("  - added: {added}"));
    }
    for removed in &changes.removed {
        lines.push(format!("  - removed: {removed}"));
    }
    for modified in &changes.modified {
        lines.push(format!("  - modified: {modified}"));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentlock_core::{
        AgentLock, AgentMetadata, BehaviorContract, ContractDefinition, Genome, KnowledgeSnapshot,
        LoadedBundle, ModelConfig, Policy, ToolSpec,
    };

    use super::{diff_bundles, render_diff};

    #[test]
    fn reports_static_changes() {
        let old = fixture_bundle("old-model", "claims.lookup");
        let mut new = fixture_bundle("new-model", "policy.lookup");
        new.prompts
            .insert("prompts/system.md".to_owned(), "updated prompt".to_owned());

        let diff = diff_bundles(&old, &new);
        assert!(!diff.is_empty());
        let rendered = render_diff(&diff);
        assert!(rendered.contains("Changed prompts"));
        assert!(rendered.contains("Changed tools"));
        assert!(rendered.contains("Changed model config"));
    }

    fn fixture_bundle(model_name: &str, tool_id: &str) -> LoadedBundle {
        LoadedBundle {
            root: std::path::PathBuf::from("."),
            genome: Genome {
                schema_version: 1,
                agent: AgentMetadata {
                    id: "agent".to_owned(),
                    name: "Agent".to_owned(),
                    version: "0.1.0".to_owned(),
                    description: None,
                },
                model: ModelConfig {
                    provider: "local".to_owned(),
                    model: model_name.to_owned(),
                    temperature: Some(0.0),
                    max_input_tokens: None,
                    max_output_tokens: Some(32),
                },
                tools: vec![ToolSpec {
                    id: tool_id.to_owned(),
                    description: None,
                    kind: None,
                }],
                knowledge_snapshots: vec![KnowledgeSnapshot {
                    id: "knowledge".to_owned(),
                    digest: "sha256:knowledge".to_owned(),
                    description: None,
                    uri: None,
                }],
            },
            agent_lock: AgentLock {
                schema_version: 1,
                agent_id: "agent".to_owned(),
                behavior_contract_id: "contract".to_owned(),
                tracked_files: Vec::new(),
            },
            behavior_contract: BehaviorContract {
                schema_version: 1,
                contract: ContractDefinition {
                    id: "contract".to_owned(),
                    description: None,
                    policies: vec![Policy {
                        id: "p1".to_owned(),
                        description: "policy".to_owned(),
                    }],
                    checks: Vec::new(),
                },
            },
            prompts: BTreeMap::from([(
                "prompts/system.md".to_owned(),
                "original prompt".to_owned(),
            )]),
        }
    }
}
