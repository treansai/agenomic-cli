//! Source: local git remote → `agent.id` (§2.3 tier 2).

use std::path::Path;

use agenomic_core::CliResult;

use crate::model::{DetectedGenome, Source};

/// Seed `agent.id = agent://<org>/<repo>` from `remote.origin.url`.
pub(crate) fn apply(path: &Path, genome: &mut DetectedGenome) -> CliResult<()> {
    let Some(url) = crate::git::origin_url(path)? else {
        return Ok(());
    };
    if let Some(org_repo) = parse_org_repo(&url) {
        let id = format!("agent://{org_repo}");
        genome.agent_id = id.clone();
        genome.record(Source::Git, "agent.id", &id, &format!("origin={url}"));
    }
    Ok(())
}

/// Extract `<org>/<repo>` from a git remote URL, supporting both `https://`
/// and scp-style `git@host:org/repo(.git)` forms.
fn parse_org_repo(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    // The last two `/`- or `:`-separated segments are `<org>` then `<repo>`.
    let mut tail = without_git.rsplit(['/', ':']);
    let repo = tail.next().filter(|s| !s.is_empty())?;
    let org = tail.next().filter(|s| !s.is_empty())?;
    Some(format!("{org}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_scp_form() {
        assert_eq!(
            parse_org_repo("git@github.com:traidano/agenomic-codedrift.git").as_deref(),
            Some("traidano/agenomic-codedrift")
        );
    }

    #[test]
    fn parses_https_form() {
        assert_eq!(
            parse_org_repo("https://github.com/traidano/agenomic-codedrift").as_deref(),
            Some("traidano/agenomic-codedrift")
        );
        assert_eq!(
            parse_org_repo("https://github.com/acme/widget.git/").as_deref(),
            Some("acme/widget")
        );
    }

    #[test]
    fn rejects_single_segment() {
        assert_eq!(parse_org_repo("justone"), None);
    }
}
