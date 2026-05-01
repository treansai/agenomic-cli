//! Integration tests for build/extract/inspect.

use std::fs;
use std::path::Path;

use agentlock_bundle::{
    build_bundle, extract_bundle, inspect_bundle, BuildBundleOptions, ExtractOptions,
};
use tempfile::tempdir;

fn fixture(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("genome.yaml"),
        r#"spec_version: '0.1'
agent:
  id: 'agent://acme/foo'
  name: 'Foo Agent'
  domain: 'general'
  criticality: 'medium'
runtime:
  model_provider: 'openai'
  model_id: 'gpt-4o'
tools:
  - name: 'web_search'
    protocol: 'mcp'
skills:
  - name: 'classify'
knowledge: []
policies: []
"#,
    )
    .unwrap();
    fs::write(
        dir.join("behavior.contract.yaml"),
        r#"spec_version: '0.1'
contract:
  id: 'contract://acme/foo/v1'
  rules:
    - id: 'r1'
      type: 'required_output_field'
      severity: 'high'
"#,
    )
    .unwrap();
    fs::write(dir.join("agent.lock"), "spec_version: '0.1'\nagent_id: 'agent://acme/foo'\nmodel:\n  provider: 'openai'\n  model_id: 'gpt-4o'\ntools: []\nknowledge: []\n").unwrap();
    fs::create_dir_all(dir.join("prompts")).unwrap();
    fs::write(dir.join("prompts/system.md"), "You are a helpful agent.").unwrap();
}

#[test]
fn build_is_deterministic_logical_hash() {
    let src = tempdir().unwrap();
    fixture(src.path());

    let out1 = tempdir().unwrap();
    let r1 = build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: out1.path().join("a.bundle.tar.zst"),
        compression_level: 3,
        ..Default::default()
    })
    .unwrap();

    let out2 = tempdir().unwrap();
    let r2 = build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: out2.path().join("a.bundle.tar.zst"),
        compression_level: 3,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(r1.logical_bundle_hash, r2.logical_bundle_hash);
}

#[test]
fn compression_level_changes_archive_not_logical() {
    let src = tempdir().unwrap();
    fixture(src.path());

    let out1 = tempdir().unwrap();
    let r1 = build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: out1.path().join("a.bundle.tar.zst"),
        compression_level: 1,
        ..Default::default()
    })
    .unwrap();

    let out2 = tempdir().unwrap();
    let r2 = build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: out2.path().join("a.bundle.tar.zst"),
        compression_level: 19,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(r1.logical_bundle_hash, r2.logical_bundle_hash);
    assert_ne!(r1.archive_hash, r2.archive_hash);
}

#[test]
fn build_extract_rebuild_same_logical_hash() {
    let src = tempdir().unwrap();
    fixture(src.path());

    let out = tempdir().unwrap();
    let archive = out.path().join("a.bundle.tar.zst");
    let r1 = build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: archive.clone(),
        ..Default::default()
    })
    .unwrap();

    let extract_dir = tempdir().unwrap();
    extract_bundle(ExtractOptions {
        archive: archive.clone(),
        destination: extract_dir.path().to_path_buf(),
    })
    .unwrap();

    let out2 = tempdir().unwrap();
    let r2 = build_bundle(BuildBundleOptions {
        input_dir: extract_dir.path().to_path_buf(),
        output_file: out2.path().join("b.bundle.tar.zst"),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(r1.logical_bundle_hash, r2.logical_bundle_hash);
}

#[test]
fn dotenv_excluded_from_bundle() {
    let src = tempdir().unwrap();
    fixture(src.path());
    fs::write(src.path().join(".env"), "SECRET=42").unwrap();

    let out = tempdir().unwrap();
    let archive = out.path().join("a.bundle.tar.zst");
    build_bundle(BuildBundleOptions {
        input_dir: src.path().to_path_buf(),
        output_file: archive.clone(),
        ..Default::default()
    })
    .unwrap();

    let extract = tempdir().unwrap();
    extract_bundle(ExtractOptions {
        archive,
        destination: extract.path().to_path_buf(),
    })
    .unwrap();
    assert!(!extract.path().join(".env").exists());
}

#[test]
fn inspect_directory_summary() {
    let src = tempdir().unwrap();
    fixture(src.path());
    let s = inspect_bundle(src.path()).unwrap();
    assert_eq!(s.agent_id, "agent://acme/foo");
    assert_eq!(s.agent_name, "Foo Agent");
    assert_eq!(s.tool_count, 1);
    assert_eq!(s.skill_count, 1);
    assert_eq!(s.contract_id.as_deref(), Some("contract://acme/foo/v1"));
}
