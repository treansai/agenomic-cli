//! Snapshot + integration tests for `agm init` / `agm update`.
//!
//! Drives the built binary. Snapshots target deterministic output (the
//! generated `genome.yaml` and the human change list); the volatile bundle
//! hash / commit id are exercised by the manual/e2e path, not snapshotted.

use std::fs;
use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

fn agm() -> Command {
    Command::cargo_bin("agenomic").expect("binary built")
}

fn write(dir: &Path, name: &str, content: &str) {
    fs::write(dir.join(name), content).unwrap();
}

/// A pyproject mirroring `agenomic-codedrift` (langgraph + anthropic + linters).
const CODEDRIFT_PYPROJECT: &str = "[project]\n\
name = \"codedrift-agent\"\n\
description = \"E2E test agent — measures Claude code-quality drift over a fixed benchmark\"\n\
authors = [{name = \"Traidano\", email = \"dev@traidano.com\"}]\n\
dependencies = [\"langgraph>=0.2.0\", \"anthropic>=0.45.0\", \"ruff>=0.6.0\", \"radon>=6.0.1\", \"bandit>=1.7.9\"]\n\
\n\
[project.scripts]\n\
agenomic-codedrift = \"agenomic_codedrift.__main__:main\"\n";

const CODEDRIFT_ID: &str = "agent://traidano/agenomic-codedrift";

#[test]
fn init_empty_is_legacy_scaffold() {
    let d = TempDir::new().unwrap();
    let bundle = d.path().join("agent");
    let out = agm()
        .args([
            "init",
            bundle.to_str().unwrap(),
            "--agent-id",
            "agent://example/new",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let genome = fs::read_to_string(bundle.join("genome.yaml")).unwrap();
    insta::assert_snapshot!("init_empty", genome);
}

/// §7 reproduction: `agm init . --dry-run --format yaml` against the codedrift
/// fixture must produce the §2.5 genome.
#[test]
fn init_codedrift_matches_spec() {
    let d = TempDir::new().unwrap();
    write(d.path(), "pyproject.toml", CODEDRIFT_PYPROJECT);
    let out = agm()
        .args([
            "init",
            d.path().to_str().unwrap(),
            "--dry-run",
            "--format",
            "yaml",
            "--agent-id",
            CODEDRIFT_ID,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!("init_codedrift", String::from_utf8_lossy(&out.stdout));
}

fn init_codedrift_bundle(dir: &Path) {
    write(dir, "pyproject.toml", CODEDRIFT_PYPROJECT);
    let out = agm()
        .args(["init", dir.to_str().unwrap(), "--agent-id", CODEDRIFT_ID])
        .output()
        .unwrap();
    assert!(out.status.success(), "init failed");
}

#[test]
fn update_no_change_exits_1() {
    let d = TempDir::new().unwrap();
    init_codedrift_bundle(d.path());
    let out = agm()
        .args(["update", d.path().to_str().unwrap(), "--no-commit"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "no-change must exit 1");
    insta::assert_snapshot!("update_no_change", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn update_provider_swap() {
    let d = TempDir::new().unwrap();
    init_codedrift_bundle(d.path());
    // Swap anthropic → openai in the manifest.
    write(
        d.path(),
        "pyproject.toml",
        &CODEDRIFT_PYPROJECT.replace("anthropic>=0.45.0", "openai>=1.0.0"),
    );
    let out = agm()
        .args([
            "update",
            d.path().to_str().unwrap(),
            "--no-commit",
            "--step",
            "swap",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!(
        "update_provider_swap_stdout",
        String::from_utf8_lossy(&out.stdout)
    );
    let genome = fs::read_to_string(d.path().join("genome.yaml")).unwrap();
    insta::assert_snapshot!("update_provider_swap_genome", genome);
}

#[test]
fn update_user_edit_preserved() {
    let d = TempDir::new().unwrap();
    init_codedrift_bundle(d.path());
    // Hand-edit the generated name.
    let genome_path = d.path().join("genome.yaml");
    let edited = fs::read_to_string(&genome_path)
        .unwrap()
        .replace("name: 'codedrift-agent'", "name: 'hand-named'");
    fs::write(&genome_path, edited).unwrap();
    // Add a new linter to the manifest so there is also a detected change.
    write(
        d.path(),
        "pyproject.toml",
        &CODEDRIFT_PYPROJECT.replace("\"ruff>=0.6.0\"", "\"ruff>=0.6.0\", \"mypy>=1.0.0\""),
    );
    let out = agm()
        .args(["update", d.path().to_str().unwrap(), "--no-commit"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let genome = fs::read_to_string(&genome_path).unwrap();
    // Hand-edited name kept; mypy added.
    assert!(
        genome.contains("name: 'hand-named'"),
        "hand-edit lost:\n{genome}"
    );
    assert!(
        genome.contains("'mypy'"),
        "detected change missing:\n{genome}"
    );
    insta::assert_snapshot!("update_user_edit_preserved_genome", genome);
}
