//! Tiny JSONL loader for [`FlaggedTrace`] streams.
//!
//! Trace pipelines append one JSON object per line; this loader parses that
//! file (or `-` for stdin), surfacing per-line errors with the line number.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{GovernanceError, GovernanceResult};
use crate::types::FlaggedTrace;

/// Read `path` (or stdin when `path == "-"`) and parse each non-blank line as
/// a [`FlaggedTrace`].
pub fn read_traces(path: &Path) -> GovernanceResult<Vec<FlaggedTrace>> {
    let raw = read_all(path)?;
    parse_traces(&raw, path)
}

fn read_all(path: &Path) -> GovernanceResult<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| GovernanceError::Io {
                path: PathBuf::from("<stdin>"),
                source: e,
            })?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| GovernanceError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

fn parse_traces(raw: &str, path: &Path) -> GovernanceResult<Vec<FlaggedTrace>> {
    let mut out = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let trace: FlaggedTrace =
            serde_json::from_str(trimmed).map_err(|e| GovernanceError::TraceParse {
                path: path.to_path_buf(),
                line: Some(idx + 1),
                reason: e.to_string(),
            })?;
        out.push(trace);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn loads_jsonl_with_blank_lines() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"trace_id":"t1","agent_id":"a","skill":"s","signal":"escalation","input_snippet":"x","output_snippet":""}}"#).unwrap();
        writeln!(f).unwrap();
        writeln!(f, r#"{{"trace_id":"t2","agent_id":"a","skill":"s","signal":"complaint","input_snippet":"y","output_snippet":""}}"#).unwrap();
        let traces = read_traces(f.path()).unwrap();
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].trace_id, "t1");
    }

    #[test]
    fn malformed_line_carries_line_number() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"trace_id":"t1","agent_id":"a","skill":"s","signal":"escalation"}}"#
        )
        .unwrap();
        writeln!(f, "not json").unwrap();
        let err = read_traces(f.path()).unwrap_err();
        match err {
            GovernanceError::TraceParse { line: Some(2), .. } => {}
            other => panic!("expected line=2, got {other:?}"),
        }
    }
}
