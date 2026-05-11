//! Security scan for bundle directories.

use std::path::Path;

use agenomic_core::{io_at, CliResult, Severity, ValidationIssue};
use walkdir::WalkDir;

/// Heuristic max file size for bundles (50 MiB).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// File-name patterns that signal a credential or key.
const SECRET_NAMES: &[&str] = &[".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

const SECRET_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx"];

const SECRET_FIELD_PREFIXES: &[&str] =
    &["api_key:", "secret:", "password:", "token:", "private_key:"];

/// Run a security scan over `dir` and return issues found.
pub fn security_scan(dir: &Path) -> CliResult<Vec<ValidationIssue>> {
    let mut out: Vec<ValidationIssue> = Vec::new();

    for dirent in WalkDir::new(dir).follow_links(false) {
        let dirent = match dirent {
            Ok(d) => d,
            Err(_) => continue,
        };
        let path = dirent.path();
        if path == dir {
            continue;
        }
        let rel = path
            .strip_prefix(dir)
            .map(|p| p.to_string_lossy().replace('\\', "/").to_string())
            .unwrap_or_default();

        // Path traversal
        if rel.split('/').any(|seg| seg == "..") {
            out.push(ValidationIssue {
                code: "agenomic::security::path_traversal".into(),
                severity: Severity::Critical,
                message: format!("path contains '..' segment: {rel}"),
                path: Some(rel.clone()),
                hint: None,
                doc: None,
            });
            continue;
        }

        let file_type = dirent.file_type();

        if file_type.is_symlink() {
            out.push(ValidationIssue {
                code: "agenomic::security::symlink".into(),
                severity: Severity::High,
                message: format!("symlink found: {rel}"),
                path: Some(rel),
                hint: Some(
                    "symlinks are excluded by default; remove or use --allow-symlinks".into(),
                ),
                doc: None,
            });
            continue;
        }

        if file_type.is_file() {
            // Secret name match
            if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                if SECRET_NAMES.contains(&fname) || fname.starts_with(".env.") {
                    out.push(ValidationIssue {
                        code: "agenomic::security::secret_file".into(),
                        severity: Severity::Critical,
                        message: format!("credential file present: {rel}"),
                        path: Some(rel.clone()),
                        hint: Some("delete or .agenomicignore".into()),
                        doc: None,
                    });
                }
            }
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if SECRET_EXTENSIONS.contains(&ext) {
                    out.push(ValidationIssue {
                        code: "agenomic::security::secret_file".into(),
                        severity: Severity::Critical,
                        message: format!("key file present: {rel}"),
                        path: Some(rel.clone()),
                        hint: Some("delete or move outside the bundle".into()),
                        doc: None,
                    });
                }
            }

            // Size cap
            if let Ok(meta) = dirent.metadata() {
                if meta.len() > DEFAULT_MAX_FILE_BYTES {
                    out.push(ValidationIssue {
                        code: "agenomic::security::oversize_file".into(),
                        severity: Severity::Medium,
                        message: format!(
                            "file exceeds {} bytes: {rel} ({} bytes)",
                            DEFAULT_MAX_FILE_BYTES,
                            meta.len()
                        ),
                        path: Some(rel.clone()),
                        hint: None,
                        doc: None,
                    });
                }
            }

            // Inline secret heuristic for YAML
            if path.extension().and_then(|s| s.to_str()) == Some("yaml")
                || path.extension().and_then(|s| s.to_str()) == Some("yml")
            {
                if let Ok(text) = std::fs::read_to_string(path).map_err(|e| io_at(path, e)) {
                    for (lineno, line) in text.lines().enumerate() {
                        let l = line.trim_start();
                        for prefix in SECRET_FIELD_PREFIXES {
                            if let Some(rest) = l.strip_prefix(prefix) {
                                let val = rest.trim();
                                if !val.is_empty()
                                    && !val
                                        .starts_with('"')
                                        .then(|| val.trim_matches('"'))
                                        .map(|s| s.is_empty())
                                        .unwrap_or(false)
                                    && val != "''"
                                    && val != "\"\""
                                {
                                    out.push(ValidationIssue {
                                        code: "agenomic::security::inline_secret".into(),
                                        severity: Severity::High,
                                        message: format!(
                                            "potential inline secret in {rel}:{}: '{prefix}'",
                                            lineno + 1
                                        ),
                                        path: Some(rel.clone()),
                                        hint: Some(
                                            "use a vault reference or env-var indirection".into(),
                                        ),
                                        doc: None,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}
