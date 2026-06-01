//! Source: `Dockerfile` `ENTRYPOINT`/`CMD` → `entrypoint` fallback (§2.3 tier 6).

use std::path::Path;

use agenomic_core::CliResult;

use crate::model::{DetectedGenome, Source};
use crate::sources::read_file_opt;

/// Set `runtime.entrypoint` from `ENTRYPOINT` (preferred) or `CMD`, but only
/// if no earlier source already set it.
pub(crate) fn apply(path: &Path, genome: &mut DetectedGenome) -> CliResult<()> {
    if genome.entrypoint.is_some() {
        return Ok(());
    }
    let Some(text) = read_file_opt(&path.join("Dockerfile"))? else {
        return Ok(());
    };
    if let Some(ep) = parse_entrypoint(&text) {
        genome.entrypoint = Some(ep.clone());
        genome.record(
            Source::Dockerfile,
            "runtime.entrypoint",
            &ep,
            "Dockerfile ENTRYPOINT/CMD",
        );
    }
    Ok(())
}

fn parse_entrypoint(text: &str) -> Option<String> {
    let mut cmd_fallback = None;
    for line in text.lines() {
        let t = line.trim();
        let upper = t.to_uppercase();
        if upper.starts_with("ENTRYPOINT") {
            let arg = t["ENTRYPOINT".len()..].trim();
            if !arg.is_empty() {
                return Some(normalize_exec(arg));
            }
        } else if upper.starts_with("CMD ") && cmd_fallback.is_none() {
            let arg = t["CMD".len()..].trim();
            if !arg.is_empty() {
                cmd_fallback = Some(normalize_exec(arg));
            }
        }
    }
    cmd_fallback
}

/// Normalise exec form (`["python", "-m", "app"]`) to a space-joined string;
/// leave shell form as-is.
fn normalize_exec(arg: &str) -> String {
    let arg = arg.trim();
    if arg.starts_with('[') {
        if let Ok(parts) = serde_json::from_str::<Vec<String>>(arg) {
            return parts.join(" ");
        }
    }
    arg.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_form_entrypoint() {
        let df = "FROM python:3.12\nENTRYPOINT [\"python\", \"-m\", \"app\"]\n";
        assert_eq!(parse_entrypoint(df).as_deref(), Some("python -m app"));
    }

    #[test]
    fn cmd_fallback_when_no_entrypoint() {
        let df = "FROM x\nCMD python main.py\n";
        assert_eq!(parse_entrypoint(df).as_deref(), Some("python main.py"));
    }

    #[test]
    fn entrypoint_preferred_over_cmd() {
        let df = "CMD a\nENTRYPOINT b\n";
        assert_eq!(parse_entrypoint(df).as_deref(), Some("b"));
    }
}
