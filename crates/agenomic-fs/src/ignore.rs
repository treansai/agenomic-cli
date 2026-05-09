//! Minimal `.agenomicignore` parser (gitignore-style globs, no negation).

use std::path::Path;

use agenomic_core::{io_at, CliError, CliResult};

/// In-memory representation of a `.agenomicignore` file.
#[derive(Debug, Clone, Default)]
pub struct IgnoreFile {
    patterns: Vec<glob::Pattern>,
    raw: Vec<String>,
}

impl IgnoreFile {
    /// Load an ignore file from disk.
    ///
    /// Empty lines and lines starting with `#` are skipped. Negation (`!`) is
    /// NOT supported in v0.1; such lines are ignored with no error.
    ///
    /// ```no_run
    /// use agenomic_fs::IgnoreFile;
    /// let ig = IgnoreFile::load_from(std::path::Path::new(".agenomicignore")).unwrap();
    /// let _ = ig.matches("target/foo");
    /// ```
    pub fn load_from(path: &Path) -> CliResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
        Self::parse(&text)
    }

    /// Parse from a string.
    pub fn parse(text: &str) -> CliResult<Self> {
        let mut out = Self::default();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('!') {
                continue;
            }
            let pat = trimmed.trim_end_matches('/');
            let p = glob::Pattern::new(pat)
                .map_err(|e| CliError::Internal(format!("bad ignore pattern '{pat}': {e}")))?;
            out.patterns.push(p);
            out.raw.push(trimmed.to_string());
        }
        Ok(out)
    }

    /// Returns `true` if `relative_path` (POSIX-style) matches any pattern.
    ///
    /// Matching rules:
    /// - exact glob match against the full relative path
    /// - basename match for patterns without `/`
    /// - prefix-segment match (so `target/` matches `target/foo`)
    pub fn matches(&self, relative_path: &str) -> bool {
        for (pat, raw) in self.patterns.iter().zip(self.raw.iter()) {
            if pat.matches(relative_path) {
                return true;
            }
            let plain = raw.trim_end_matches('/');
            if !plain.contains('/') {
                if let Some(last) = relative_path.rsplit('/').next() {
                    if pat.matches(last) {
                        return true;
                    }
                }
            }
            if raw.ends_with('/') || !plain.contains('/') {
                for (i, ch) in relative_path.char_indices() {
                    if ch == '/' && pat.matches(&relative_path[..i]) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_basic() {
        let ig = IgnoreFile::parse(
            "# comment\n\
             *.tmp\n\
             secret/\n\
             docs/draft.md\n",
        )
        .unwrap();

        assert!(ig.matches("foo.tmp"));
        assert!(ig.matches("nested/foo.tmp"));
        assert!(ig.matches("secret/x"));
        assert!(ig.matches("docs/draft.md"));
        assert!(!ig.matches("docs/final.md"));
    }

    #[test]
    fn ignores_negation_silently() {
        let ig = IgnoreFile::parse("*.tmp\n!keep.tmp\n").unwrap();
        assert!(ig.matches("keep.tmp")); // negation NOT supported
    }
}
