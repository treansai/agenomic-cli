//! Source: `README.md` → `agent.name` + `description` (§2.3 tier 3).

use std::path::Path;

use agenomic_core::CliResult;

use crate::model::{DetectedGenome, Source};
use crate::sources::read_file_opt;

/// First H1 → candidate name; first paragraph → candidate description.
pub(crate) fn apply(path: &Path, genome: &mut DetectedGenome) -> CliResult<()> {
    let Some(text) = read_file_opt(&path.join("README.md"))? else {
        return Ok(());
    };
    if let Some(h1) = first_h1(&text) {
        genome.agent_name = h1.clone();
        genome.record(Source::Readme, "agent.name", &h1, "README.md first H1");
    }
    if let Some(para) = first_paragraph(&text) {
        genome.description = Some(para.clone());
        genome.record(
            Source::Readme,
            "description",
            &para,
            "README.md first paragraph",
        );
    }
    Ok(())
}

fn first_h1(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("# ")
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
    })
}

fn first_paragraph(text: &str) -> Option<String> {
    let mut para = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            if para.is_empty() {
                continue;
            }
            break;
        }
        if t.is_empty() {
            if para.is_empty() {
                continue;
            }
            break;
        }
        if !para.is_empty() {
            para.push(' ');
        }
        para.push_str(t);
    }
    (!para.is_empty()).then_some(para)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_h1_and_first_paragraph() {
        let md = "# My Agent\n\nDoes a thing.\nAcross two lines.\n\nSecond paragraph.\n";
        assert_eq!(first_h1(md).as_deref(), Some("My Agent"));
        assert_eq!(
            first_paragraph(md).as_deref(),
            Some("Does a thing. Across two lines.")
        );
    }

    #[test]
    fn no_h1_returns_none() {
        assert_eq!(first_h1("## not h1\ntext\n"), None);
    }
}
