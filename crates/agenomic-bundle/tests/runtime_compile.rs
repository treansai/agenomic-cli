use std::fs;

use agenomic_bundle::{compile_runtime_artifacts, CompileRuntimeOptions, RuntimeAdapter};
use serde_json::Value as JsonValue;
use tempfile::tempdir;

#[test]
fn cli_v01_bundle_compiles_plain_and_langgraph_artifacts() {
    let td = tempdir().unwrap();
    let bundle = td.path().join("bundle");
    fs::create_dir_all(bundle.join("prompts/skills")).unwrap();
    fs::write(
        bundle.join("genome.yaml"),
        r#"spec_version: '0.1'
agent:
  id: 'agent://treansai/agenomic-codedrift'
  name: 'agenomic-codedrift'
  domain: 'general'
  criticality: 'low'
runtime:
  framework: 'langgraph'
  runtime_kind: 'python'
  model_provider: 'anthropic'
  model_id: 'claude-sonnet-4-6'
  entrypoint: 'agenomic_codedrift.__main__:main'
tools: []
skills:
  - name: 'classify'
    prompt: 'prompts/skills/classify.md'
knowledge: []
policies: []
"#,
    )
    .unwrap();
    fs::write(bundle.join("agent.lock.yaml"), "spec_version: '0.1'\n").unwrap();
    fs::write(
        bundle.join("behavior.contract.yaml"),
        "spec_version: '0.1'\n",
    )
    .unwrap();
    fs::write(bundle.join("prompts/system.md"), "system").unwrap();
    fs::write(bundle.join("prompts/skills/classify.md"), "skill").unwrap();

    let result = compile_runtime_artifacts(CompileRuntimeOptions {
        input_dir: bundle.clone(),
        output_dir: None,
        adapters: Vec::new(),
    })
    .unwrap();

    assert_eq!(result.artifacts.len(), 2);
    assert_eq!(result.artifacts[0].adapter, RuntimeAdapter::Plain);
    assert_eq!(result.artifacts[1].adapter, RuntimeAdapter::Langgraph);
    assert!(result.artifacts.iter().all(|artifact| artifact.ready));

    let plain: JsonValue =
        serde_json::from_slice(&fs::read(bundle.join("runtime/plain.compiled")).unwrap()).unwrap();
    assert_eq!(plain["schema_version"], "agenomic.runtime/v1");
    assert_eq!(plain["adapter"], "plain");
    assert_eq!(plain["agent"]["id"], "agent://treansai/agenomic-codedrift");
    assert_eq!(plain["execution"]["entrypoint"]["command"], "python");
    assert_eq!(plain["execution"]["entrypoint"]["args"][0], "-m");
    assert_eq!(
        plain["execution"]["entrypoint"]["args"][1],
        "agenomic_codedrift"
    );
    assert_eq!(plain["source"]["framework_hint"], "langgraph");
    assert_eq!(plain["prompts"]["system"], "prompts/system.md");
    assert_eq!(
        plain["prompts"]["skills"][0]["path"],
        "prompts/skills/classify.md"
    );
    assert_eq!(
        plain["bindings"]["behavior_contract"],
        "behavior.contract.yaml"
    );

    let langgraph: JsonValue =
        serde_json::from_slice(&fs::read(bundle.join("runtime/langgraph.compiled")).unwrap())
            .unwrap();
    assert_eq!(langgraph["adapter"], "langgraph");
    assert_eq!(langgraph["adapter_config"]["framework"], "langgraph");
    assert_eq!(langgraph["ready"], true);
}

#[test]
fn v1alpha1_bundle_compiles_metadata_only_plain_artifact() {
    let td = tempdir().unwrap();
    let bundle = td.path().join("bundle");
    fs::create_dir_all(bundle.join("prompts/skills")).unwrap();
    fs::write(
        bundle.join("genome.yaml"),
        r#"apiVersion: agenomic/v1alpha1
kind: AgentGenome
metadata:
  name: claims-agent-demo
summary:
  objective: Classify complaint messages.
artifacts:
  system_prompt: prompts/system.md
  skills:
    - prompts/skills/classify_claim.md
  behavior_contract: behavior.contract.yaml
  tool_lock: tools/mcp.lock.yaml
  memory_schema: memory/memory.schema.yaml
  policies:
    - policies/compensation_policy.rego
  evals:
    - evals/replay_manifest.yaml
"#,
    )
    .unwrap();
    fs::write(
        bundle.join("behavior.contract.yaml"),
        "spec_version: '0.1'\n",
    )
    .unwrap();
    fs::write(bundle.join("prompts/system.md"), "system").unwrap();
    fs::write(bundle.join("prompts/skills/classify_claim.md"), "skill").unwrap();

    let result = compile_runtime_artifacts(CompileRuntimeOptions {
        input_dir: bundle.clone(),
        output_dir: None,
        adapters: Vec::new(),
    })
    .unwrap();

    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.artifacts[0].adapter, RuntimeAdapter::Plain);
    assert!(!result.artifacts[0].ready);

    let plain: JsonValue =
        serde_json::from_slice(&fs::read(bundle.join("runtime/plain.compiled")).unwrap()).unwrap();
    assert_eq!(plain["source"]["genome_shape"], "agenomic_v1alpha1");
    assert_eq!(plain["agent"]["name"], "claims-agent-demo");
    assert!(plain["agent"].get("id").is_none());
    assert!(plain.get("execution").is_none());
    let warnings = plain["warnings"].as_array().unwrap();
    assert!(warnings
        .iter()
        .any(|w| { w.as_str().unwrap_or_default().contains("metadata-only") }));
}
