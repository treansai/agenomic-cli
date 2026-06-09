//! Port proposal generation.
//!
//! See [`propose`] for the entry point. The output is deliberately
//! conservative: when in doubt, raise a [`Gap`] rather than guess. The
//! emitted YAML is hand-formatted (block style, two-space indent) to match
//! the rest of the workspace's canonical emitter conventions.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use agenomic_detect::{run as detect_run, DetectOptions, DetectedGenome};

use crate::contract::RuntimeKind;
use crate::error::{OsError, OsResult};

/// A proposed execution block plus the gaps a human must close before the
/// agent can actually run under `agenomic-os`.
#[derive(Debug, Clone)]
pub struct PortProposal {
    pub source_path: PathBuf,
    /// YAML for the `execution:` block, ready to paste into a genome.yaml.
    /// Includes only fields with non-trivial proposed values; everything
    /// else is reported as a [`Gap`].
    pub proposed_execution_yaml: String,
    pub runtime_kind: Option<RuntimeKind>,
    pub framework: Option<String>,
    pub gaps: Vec<Gap>,
}

/// A field the proposal could not confidently fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub field: String,
    pub reason: String,
    pub severity: GapSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapSeverity {
    /// The user must fill this before launch is safe.
    Required,
    /// Strongly suggested but not blocking.
    Recommended,
    /// Heads-up only.
    Informational,
}

/// Run port detection against `path` and produce a [`PortProposal`].
///
/// Errors only when the underlying detection itself fails (malformed
/// manifest, I/O). A codebase whose runtime cannot be mapped to spec 0.2
/// still returns a proposal, with the unmapped runtime recorded as a
/// `Required` gap.
pub fn propose(path: &Path) -> OsResult<PortProposal> {
    let detected =
        detect_run(path, &DetectOptions::default()).map_err(|e| OsError::PortFailed {
            reason: e.to_string(),
        })?;

    let (runtime_kind, runtime_gap) = map_runtime_kind(&detected);
    let (command, args, entrypoint_gaps) = derive_entrypoint(&detected, runtime_kind);

    let mut gaps: Vec<Gap> = Vec::new();
    gaps.extend(runtime_gap);
    gaps.extend(entrypoint_gaps);
    // Permissions and env always start closed; the user must opt-in.
    gaps.push(Gap {
        field: "execution.env.required".into(),
        reason: "no environment variables inferred; review the source for secrets/configuration that must be declared"
            .into(),
        severity: GapSeverity::Recommended,
    });
    gaps.push(Gap {
        field: "execution.permissions".into(),
        reason: "permissions default to closed; declare filesystem/network access explicitly before running under agenomic-os"
            .into(),
        severity: GapSeverity::Required,
    });
    if let Some(framework) = &detected.framework {
        gaps.push(Gap {
            field: "execution.entrypoint".into(),
            reason: format!(
                "detected framework `{framework}` is not natively supported at MVP; the proposed entrypoint runs the underlying interpreter only"
            ),
            severity: GapSeverity::Informational,
        });
    }

    let yaml = render_execution_yaml(runtime_kind, &command, &args);

    Ok(PortProposal {
        source_path: path.to_path_buf(),
        proposed_execution_yaml: yaml,
        runtime_kind,
        framework: detected.framework.clone(),
        gaps,
    })
}

fn map_runtime_kind(detected: &DetectedGenome) -> (Option<RuntimeKind>, Vec<Gap>) {
    match detected.runtime_kind.as_deref() {
        Some("python") => (Some(RuntimeKind::Python), Vec::new()),
        Some("node") => (Some(RuntimeKind::Node), Vec::new()),
        Some("rust") => (Some(RuntimeKind::Rust), Vec::new()),
        Some(other) => (
            None,
            vec![Gap {
                field: "execution.runtime.kind".into(),
                reason: format!(
                    "detected runtime `{other}` has no direct mapping in spec 0.2 (supported: python, node, rust, binary); choose `binary` and provide an explicit command, or wait for spec extension"
                ),
                severity: GapSeverity::Required,
            }],
        ),
        None => (
            None,
            vec![Gap {
                field: "execution.runtime.kind".into(),
                reason: "no runtime detected from manifests; declare it manually".into(),
                severity: GapSeverity::Required,
            }],
        ),
    }
}

fn derive_entrypoint(
    detected: &DetectedGenome,
    runtime: Option<RuntimeKind>,
) -> (String, Vec<String>, Vec<Gap>) {
    let raw = detected.entrypoint.as_deref();
    let mut gaps = Vec::new();
    let (command, args) = match (runtime, raw) {
        (Some(RuntimeKind::Python), Some(ep)) => python_entrypoint(ep),
        (Some(RuntimeKind::Node), Some(ep)) => ("node".into(), vec![ep.to_string()]),
        (Some(RuntimeKind::Rust), _) => {
            // Cargo is the most portable runner inside a Rust workspace.
            ("cargo".into(), vec!["run".into(), "--release".into()])
        }
        (Some(RuntimeKind::Python), None) => {
            gaps.push(Gap {
                field: "execution.entrypoint.args".into(),
                reason:
                    "no Python entrypoint detected; defaulting to `python -m <package>` placeholder"
                        .into(),
                severity: GapSeverity::Required,
            });
            ("python".into(), vec!["-m".into(), "<package>".into()])
        }
        (Some(RuntimeKind::Node), None) => {
            gaps.push(Gap {
                field: "execution.entrypoint.args".into(),
                reason: "no Node entrypoint detected; declare it manually".into(),
                severity: GapSeverity::Required,
            });
            ("node".into(), vec!["<script>.js".into()])
        }
        _ => {
            gaps.push(Gap {
                field: "execution.entrypoint".into(),
                reason: "no entrypoint could be inferred".into(),
                severity: GapSeverity::Required,
            });
            ("<command>".into(), Vec::new())
        }
    };
    (command, args, gaps)
}

fn python_entrypoint(ep: &str) -> (String, Vec<String>) {
    // pyproject scripts produce `pkg.module:func`; treat the package prefix as
    // a `-m` target. Otherwise treat as a script path.
    if let Some((module, _func)) = ep.split_once(':') {
        let package = module.split('.').next().unwrap_or(module);
        ("python".into(), vec!["-m".into(), package.to_string()])
    } else if ep.ends_with(".py") {
        ("python".into(), vec![ep.to_string()])
    } else {
        ("python".into(), vec!["-m".into(), ep.to_string()])
    }
}

fn render_execution_yaml(runtime: Option<RuntimeKind>, command: &str, args: &[String]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "execution:");
    let _ = writeln!(s, "  entrypoint:");
    let _ = writeln!(s, "    kind: command");
    let _ = writeln!(s, "    command: {}", yaml_scalar(command));
    if args.is_empty() {
        let _ = writeln!(s, "    args: []");
    } else {
        let _ = writeln!(s, "    args:");
        for a in args {
            let _ = writeln!(s, "      - {}", yaml_scalar(a));
        }
    }
    let _ = writeln!(s, "  runtime:");
    match runtime {
        Some(k) => {
            let _ = writeln!(s, "    kind: {}", k.label());
        }
        None => {
            let _ = writeln!(s, "    kind: binary  # REVIEW: no runtime inferred");
        }
    }
    let _ = writeln!(s, "  working_directory: \".\"");
    let _ = writeln!(s, "  env:");
    let _ = writeln!(s, "    required: []");
    let _ = writeln!(s, "    optional: []");
    let _ = writeln!(s, "  permissions:");
    let _ = writeln!(s, "    filesystem:");
    let _ = writeln!(s, "      read: []");
    let _ = writeln!(s, "      write: []");
    let _ = writeln!(s, "    network:");
    let _ = writeln!(s, "      allow: []");
    s
}

fn yaml_scalar(s: &str) -> String {
    // Conservative quoting: if the string contains anything beyond
    // [A-Za-z0-9_./-], wrap it in double quotes with simple escaping.
    let needs_quotes = s.is_empty()
        || s.chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')));
    if !needs_quotes {
        s.to_string()
    } else {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn python_pyproject_yields_python_entrypoint() {
        let td = TempDir::new().unwrap();
        fs::write(
            td.path().join("pyproject.toml"),
            r#"[project]
name = "codedrift"
version = "0.1.0"

[project.scripts]
codedrift = "codedrift.agent:main"
"#,
        )
        .unwrap();

        let p = propose(td.path()).unwrap();
        assert_eq!(p.runtime_kind, Some(RuntimeKind::Python));
        assert!(p.proposed_execution_yaml.contains("kind: command"));
        assert!(p.proposed_execution_yaml.contains("command: python"));
        assert!(p.proposed_execution_yaml.contains("- codedrift"));
        // Permissions gap is always Required.
        assert!(p
            .gaps
            .iter()
            .any(|g| g.field == "execution.permissions" && g.severity == GapSeverity::Required));
    }

    #[test]
    fn rust_project_proposes_cargo_run() {
        let td = TempDir::new().unwrap();
        fs::write(
            td.path().join("Cargo.toml"),
            r#"[package]
name = "demo"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        fs::create_dir(td.path().join("src")).unwrap();
        fs::write(td.path().join("src/main.rs"), "fn main() {}").unwrap();

        let p = propose(td.path()).unwrap();
        assert_eq!(p.runtime_kind, Some(RuntimeKind::Rust));
        assert!(p.proposed_execution_yaml.contains("command: cargo"));
        assert!(p.proposed_execution_yaml.contains("- run"));
    }

    #[test]
    fn unsupported_runtime_records_required_gap() {
        // go.mod is detected as runtime_kind = "go", which is NOT in spec 0.2.
        let td = TempDir::new().unwrap();
        fs::write(td.path().join("go.mod"), "module example.com/foo\n").unwrap();

        let p = propose(td.path()).unwrap();
        assert_eq!(p.runtime_kind, None);
        let required_gap = p
            .gaps
            .iter()
            .find(|g| g.field == "execution.runtime.kind")
            .expect("runtime gap recorded");
        assert_eq!(required_gap.severity, GapSeverity::Required);
        assert!(required_gap.reason.contains("go"));
        assert!(p.proposed_execution_yaml.contains("kind: binary  # REVIEW"));
    }

    #[test]
    fn empty_directory_proposes_placeholder_with_required_gaps() {
        let td = TempDir::new().unwrap();
        let p = propose(td.path()).unwrap();
        assert!(p.runtime_kind.is_none());
        assert!(p
            .gaps
            .iter()
            .any(|g| g.field == "execution.runtime.kind" && g.severity == GapSeverity::Required));
    }

    #[test]
    fn proposed_yaml_round_trips_through_serde_yaml() {
        let td = TempDir::new().unwrap();
        fs::write(
            td.path().join("pyproject.toml"),
            "[project]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let p = propose(td.path()).unwrap();
        // The emitted block must at least be valid YAML.
        let _: serde_yaml::Value = serde_yaml::from_str(&p.proposed_execution_yaml).unwrap();
    }
}
