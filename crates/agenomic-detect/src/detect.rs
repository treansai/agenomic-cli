//! Detection entry point — runs the §2.3 precedence chain.
//!
//! Sources are applied lowest priority first (`defaults → git → readme →
//! go-mod/cargo/package-json → pyproject → dockerfile → agenomic-yaml`), so a
//! higher-precedence source overwrites a lower one and empty values never
//! overwrite a set value. Inference over collected dependencies (§2.4) runs
//! after the chain. All file and git access is local and offline.

use std::path::Path;

use agenomic_core::CliResult;

use crate::model::{Dependency, DetectedGenome, Source};

/// Options controlling a detection run.
#[derive(Debug, Clone, Default)]
pub struct DetectOptions {
    /// If set, only these sources are consulted (the `--from` flag). Defaults
    /// are always included as the base.
    pub only: Option<Vec<Source>>,
    /// Skip all detection; behave like the legacy scaffolder.
    pub no_detect: bool,
    /// Override the detected agent name (`--name`).
    pub name_override: Option<String>,
    /// Override the detected agent id (`--agent-id`).
    pub agent_id_override: Option<String>,
}

/// Run repo detection against `path`, returning a [`DetectedGenome`].
///
/// Fallible because manifest parsing is untrusted: a malformed `pyproject.toml`
/// / `Cargo.toml` / `package.json` surfaces as [`agenomic_core::CliError::Schema`]
/// (exit 3), and a symlinked manifest as `SymlinkRejected` (exit 4) — never a
/// panic. Returns the legacy defaults when `no_detect` is set.
///
/// ```no_run
/// use agenomic_detect::{run, DetectOptions};
/// use std::path::Path;
/// let genome = run(Path::new("."), &DetectOptions::default()).unwrap();
/// assert!(!genome.agent_id.is_empty());
/// ```
pub fn run(path: &Path, opts: &DetectOptions) -> CliResult<DetectedGenome> {
    let mut genome = DetectedGenome::defaults();

    if !opts.no_detect {
        let mut deps: Vec<Dependency> = Vec::new();
        for source in Source::PRECEDENCE {
            if source == Source::Defaults {
                continue;
            }
            if let Some(only) = &opts.only {
                if !only.contains(&source) {
                    continue;
                }
            }
            match source {
                Source::Defaults => {}
                Source::Git => crate::sources::git::apply(path, &mut genome)?,
                Source::Readme => crate::sources::readme::apply(path, &mut genome)?,
                Source::GoMod => crate::sources::manifest::apply_go_mod(path, &mut genome)?,
                Source::Cargo => {
                    crate::sources::manifest::apply_cargo(path, &mut genome, &mut deps)?
                }
                Source::PackageJson => {
                    crate::sources::manifest::apply_package_json(path, &mut genome, &mut deps)?
                }
                Source::Pyproject => {
                    crate::sources::pyproject::apply(path, &mut genome, &mut deps)?
                }
                Source::Dockerfile => crate::sources::dockerfile::apply(path, &mut genome)?,
                Source::AgenomicYaml => crate::sources::agenomic_yaml::apply(path, &mut genome)?,
            }
        }
        crate::infer::apply(&deps, &mut genome);
    }

    apply_overrides(&mut genome, opts);
    Ok(genome)
}

/// Apply `--name` / `--agent-id` overrides. These take precedence over every
/// detected source; the corresponding detection evidence is dropped because
/// the value no longer came from detection.
fn apply_overrides(genome: &mut DetectedGenome, opts: &DetectOptions) {
    if let Some(name) = opts.name_override.as_deref().filter(|s| !s.is_empty()) {
        genome.agent_name = name.to_string();
        genome.evidence.retain(|e| e.field != "agent.name");
    }
    if let Some(id) = opts.agent_id_override.as_deref().filter(|s| !s.is_empty()) {
        genome.agent_id = id.to_string();
        genome.evidence.retain(|e| e.field != "agent.id");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn no_detect_returns_defaults() {
        let d = tempdir().unwrap();
        let g = run(
            d.path(),
            &DetectOptions {
                no_detect: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(g.agent_id, "agent://example/new");
        assert_eq!(g.model_provider, "openai");
        assert!(g.runtime_kind.is_none());
    }

    #[test]
    fn detects_pyproject_and_readme() {
        let d = tempdir().unwrap();
        fs::write(
            d.path().join("pyproject.toml"),
            "[project]\nname = \"codedrift-agent\"\ndescription = \"E2E drift agent\"\n\
             authors = [{name = \"Traidano\", email = \"dev@traidano.com\"}]\n\
             dependencies = [\"anthropic>=0.45.0\", \"ruff>=0.6.0\"]\n\
             [project.scripts]\nagenomic-codedrift = \"agenomic_codedrift.__main__:main\"\n",
        )
        .unwrap();
        fs::write(
            d.path().join("README.md"),
            "# Readme Title\n\nA paragraph.\n",
        )
        .unwrap();

        let g = run(d.path(), &DetectOptions::default()).unwrap();
        // pyproject (tier 5) wins over readme (tier 3) for the name.
        assert_eq!(g.agent_name, "codedrift-agent");
        assert_eq!(g.description.as_deref(), Some("E2E drift agent"));
        assert_eq!(g.runtime_kind.as_deref(), Some("python"));
        assert_eq!(
            g.entrypoint.as_deref(),
            Some("agenomic_codedrift.__main__:main")
        );
        assert_eq!(g.authors, vec!["Traidano <dev@traidano.com>".to_string()]);
    }

    #[test]
    fn agenomic_yaml_wins_and_overrides_apply() {
        let d = tempdir().unwrap();
        fs::write(
            d.path().join("pyproject.toml"),
            "[project]\nname = \"from-pyproject\"\n",
        )
        .unwrap();
        fs::write(
            d.path().join("agenomic.yaml"),
            "agent:\n  name: from-yaml\nruntime:\n  model_id: claude-opus-4-7\n",
        )
        .unwrap();

        let g = run(d.path(), &DetectOptions::default()).unwrap();
        // agenomic.yaml (tier 7) beats pyproject (tier 5).
        assert_eq!(g.agent_name, "from-yaml");
        assert_eq!(g.model_id, "claude-opus-4-7");

        // --name override beats everything and drops the detection evidence.
        let g2 = run(
            d.path(),
            &DetectOptions {
                name_override: Some("forced".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(g2.agent_name, "forced");
        assert!(g2.evidence.iter().all(|e| e.field != "agent.name"));
    }

    #[test]
    fn only_restricts_sources() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("README.md"), "# Readme Name\n\nDesc.\n").unwrap();
        fs::write(
            d.path().join("pyproject.toml"),
            "[project]\nname = \"py-name\"\n",
        )
        .unwrap();

        // Restrict to readme only → pyproject is ignored.
        let g = run(
            d.path(),
            &DetectOptions {
                only: Some(vec![Source::Readme]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(g.agent_name, "Readme Name");
        assert!(g.runtime_kind.is_none());
    }

    #[test]
    fn malformed_pyproject_is_error_not_panic() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("pyproject.toml"), "[project\nname = oops").unwrap();
        let err = run(d.path(), &DetectOptions::default()).unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 3);
    }
}
