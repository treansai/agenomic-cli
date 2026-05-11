//! Renderers for agenomic-cli reports.
//!
//! Implements [`Renderable`] for the major report types.

use std::io::Write;

use agenomic_attestation::{ReleaseAttestation, VerificationResult};
use agenomic_bundle::BundleSummary;
use agenomic_core::{CliError, CliResult, Severity, ValidationReport};
use agenomic_diff::DiffReport;
use agenomic_replay_local::ReplayReport;

#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    pub no_color: bool,
    pub no_unicode: bool,
    pub width: Option<usize>,
}

pub trait Renderable {
    fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()>;
    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()>;
    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()>;
    fn render_html(&self, w: &mut dyn Write) -> CliResult<()> {
        let mut md = Vec::new();
        self.render_markdown(&mut md)?;
        let md_str = String::from_utf8_lossy(&md);
        let parser = pulldown_cmark::Parser::new(&md_str);
        let mut html = String::new();
        pulldown_cmark::html::push_html(&mut html, parser);
        write!(
            w,
            "<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{html}</body></html>"
        )
        .map_err(io)?;
        Ok(())
    }
}

fn write_json<T: serde::Serialize>(w: &mut dyn Write, v: &T, pretty: bool) -> CliResult<()> {
    let s = if pretty {
        serde_json::to_string_pretty(v).map_err(|e| CliError::Internal(format!("{e}")))?
    } else {
        serde_json::to_string(v).map_err(|e| CliError::Internal(format!("{e}")))?
    };
    w.write_all(s.as_bytes()).map_err(io)?;
    w.write_all(b"\n").map_err(io)?;
    Ok(())
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MED",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}

fn severity_styled(s: Severity, opts: &RenderOptions) -> String {
    let label = severity_label(s);
    if opts.no_color {
        return label.to_string();
    }
    let style = match s {
        Severity::Info => console::style(label).dim(),
        Severity::Low => console::style(label).cyan(),
        Severity::Medium => console::style(label).yellow(),
        Severity::High => console::style(label).red().bold(),
        Severity::Critical => console::style(label).red().bold().on_white(),
    };
    style.to_string()
}

fn io(e: std::io::Error) -> CliError {
    CliError::Internal(format!("write: {e}"))
}

// ---- ValidationReport ----

impl Renderable for ValidationReport {
    fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
        let header = if self.valid { "VALID" } else { "INVALID" };
        let header_styled = if opts.no_color {
            header.to_string()
        } else if self.valid {
            console::style(header).green().bold().to_string()
        } else {
            console::style(header).red().bold().to_string()
        };
        writeln!(w, "validation: {header_styled}").map_err(io)?;
        writeln!(
            w,
            "  errors: {}, warnings: {}, info: {}",
            self.errors.len(),
            self.warnings.len(),
            self.info.len()
        )
        .map_err(io)?;
        for issue in self.errors.iter().chain(self.warnings.iter()) {
            writeln!(
                w,
                "  [{}] {}: {}{}",
                severity_styled(issue.severity, opts),
                issue.code,
                issue.message,
                issue
                    .path
                    .as_deref()
                    .map(|p| format!(" ({p})"))
                    .unwrap_or_default(),
            )
            .map_err(io)?;
        }
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Validation report").map_err(io)?;
        writeln!(w, "- valid: **{}**", if self.valid { "yes" } else { "no" }).map_err(io)?;
        writeln!(w, "- errors: {}", self.errors.len()).map_err(io)?;
        writeln!(w, "- warnings: {}", self.warnings.len()).map_err(io)?;
        for issue in self.errors.iter().chain(self.warnings.iter()) {
            writeln!(
                w,
                "- `{}` **{}** {}{}",
                issue.code,
                severity_label(issue.severity),
                issue.message,
                issue
                    .path
                    .as_deref()
                    .map(|p| format!(" ({p})"))
                    .unwrap_or_default(),
            )
            .map_err(io)?;
        }
        Ok(())
    }
}

// ---- BundleSummary ----

impl Renderable for BundleSummary {
    fn render_human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(w, "agent: {} ({})", self.agent_name, self.agent_id).map_err(io)?;
        writeln!(w, "spec_version: {}", self.spec_version).map_err(io)?;
        if let Some(m) = &self.model {
            writeln!(w, "model: {m}").map_err(io)?;
        }
        if let Some(fp) = &self.model_fingerprint {
            writeln!(w, "fingerprint: {fp}").map_err(io)?;
        }
        writeln!(w, "tools: {}", self.tool_count).map_err(io)?;
        for t in &self.tools {
            writeln!(
                w,
                "  - {} ({})",
                t.name,
                t.protocol.as_deref().unwrap_or("?")
            )
            .map_err(io)?;
        }
        writeln!(w, "skills: {}", self.skill_count).map_err(io)?;
        if let Some(c) = &self.contract_id {
            writeln!(w, "contract: {c}").map_err(io)?;
        }
        writeln!(w, "files: {}", self.file_count).map_err(io)?;
        writeln!(w, "size: {} bytes", self.total_size_bytes).map_err(io)?;
        writeln!(w, "logical_hash: {}", self.logical_bundle_hash).map_err(io)?;
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Bundle summary").map_err(io)?;
        writeln!(w, "- agent: `{}` ({})", self.agent_id, self.agent_name).map_err(io)?;
        writeln!(w, "- spec_version: `{}`", self.spec_version).map_err(io)?;
        if let Some(m) = &self.model {
            writeln!(w, "- model: `{m}`").map_err(io)?;
        }
        writeln!(w, "- tools: {}", self.tool_count).map_err(io)?;
        writeln!(w, "- skills: {}", self.skill_count).map_err(io)?;
        writeln!(w, "- files: {}", self.file_count).map_err(io)?;
        writeln!(w, "- logical_hash: `{}`", self.logical_bundle_hash).map_err(io)?;
        Ok(())
    }
}

// ---- DiffReport ----

impl Renderable for DiffReport {
    fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
        writeln!(w, "diff:").map_err(io)?;
        writeln!(w, "  baseline: {}", self.baseline_hash).map_err(io)?;
        writeln!(w, "  candidate: {}", self.candidate_hash).map_err(io)?;
        writeln!(
            w,
            "  overall_risk: {}, replay_required: {}",
            severity_styled(self.overall_risk, opts),
            self.replay_required
        )
        .map_err(io)?;
        for ch in &self.changes {
            writeln!(
                w,
                "  [{}] {}: {} ({})",
                severity_styled(ch.severity, opts),
                ch.change_type,
                ch.path,
                ch.explanation
            )
            .map_err(io)?;
        }
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Diff report").map_err(io)?;
        writeln!(w, "- baseline: `{}`", self.baseline_hash).map_err(io)?;
        writeln!(w, "- candidate: `{}`", self.candidate_hash).map_err(io)?;
        writeln!(
            w,
            "- overall_risk: **{}**",
            severity_label(self.overall_risk)
        )
        .map_err(io)?;
        writeln!(w, "- replay_required: {}", self.replay_required).map_err(io)?;
        writeln!(w, "## Changes").map_err(io)?;
        for ch in &self.changes {
            writeln!(
                w,
                "- `{}` **{}** `{}` — {}",
                ch.change_type,
                severity_label(ch.severity),
                ch.path,
                ch.explanation
            )
            .map_err(io)?;
        }
        Ok(())
    }
}

// ---- ReplayReport ----

impl Renderable for ReplayReport {
    fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
        let label = if self.contract_passed { "PASS" } else { "FAIL" };
        let styled = if opts.no_color {
            label.to_string()
        } else if self.contract_passed {
            console::style(label).green().bold().to_string()
        } else {
            console::style(label).red().bold().to_string()
        };
        writeln!(w, "replay: {styled}").map_err(io)?;
        writeln!(w, "  bundle_hash: {}", self.bundle_hash).map_err(io)?;
        writeln!(w, "  contract: {}", self.contract_id).map_err(io)?;
        writeln!(
            w,
            "  traces: {} runs: {} mode: {}",
            self.total_traces, self.total_runs, self.mode
        )
        .map_err(io)?;
        writeln!(
            w,
            "  violations: critical={}, high={}, medium={}, low={}",
            self.aggregates.critical,
            self.aggregates.high,
            self.aggregates.medium,
            self.aggregates.low
        )
        .map_err(io)?;
        for v in &self.violations {
            writeln!(
                w,
                "    [{}] {} {} — {}",
                severity_styled(v.severity, opts),
                v.trace_id,
                v.check_id,
                v.message
            )
            .map_err(io)?;
        }
        for n in &self.notes {
            writeln!(w, "  note: {} — {}", n.code, n.message).map_err(io)?;
        }
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Replay report").map_err(io)?;
        writeln!(
            w,
            "- contract_passed: **{}**",
            if self.contract_passed { "yes" } else { "no" }
        )
        .map_err(io)?;
        writeln!(w, "- bundle_hash: `{}`", self.bundle_hash).map_err(io)?;
        writeln!(w, "- contract: `{}`", self.contract_id).map_err(io)?;
        writeln!(w, "- traces: {}", self.total_traces).map_err(io)?;
        writeln!(w, "- mode: `{}`", self.mode).map_err(io)?;
        writeln!(
            w,
            "- violations: critical={} high={} medium={} low={}",
            self.aggregates.critical,
            self.aggregates.high,
            self.aggregates.medium,
            self.aggregates.low
        )
        .map_err(io)?;
        for v in &self.violations {
            writeln!(
                w,
                "  - **{}** `{}` `{}`: {}",
                severity_label(v.severity),
                v.trace_id,
                v.check_id,
                v.message
            )
            .map_err(io)?;
        }
        Ok(())
    }
}

// ---- ReleaseAttestation ----

impl Renderable for ReleaseAttestation {
    fn render_human(&self, w: &mut dyn Write, _opts: &RenderOptions) -> CliResult<()> {
        writeln!(w, "attestation: release").map_err(io)?;
        writeln!(w, "  agent_id: {}", self.agent_id).map_err(io)?;
        writeln!(w, "  bundle_logical_hash: {}", self.bundle_logical_hash).map_err(io)?;
        writeln!(w, "  bundle_archive_hash: {}", self.bundle_archive_hash).map_err(io)?;
        if let Some(h) = &self.replay_report_hash {
            writeln!(w, "  replay_report_hash: {h}").map_err(io)?;
        }
        if let Some(a) = &self.atep_root_hash {
            writeln!(w, "  atep_root_hash: {a}").map_err(io)?;
        }
        if let Some(p) = self.contract_passed {
            writeln!(w, "  contract_passed: {p}").map_err(io)?;
        }
        match &self.signature {
            Some(s) => writeln!(w, "  signature: {} ({})", s.algorithm, s.key_id).map_err(io)?,
            None => writeln!(w, "  signature: <unsigned>").map_err(io)?,
        }
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Release attestation").map_err(io)?;
        writeln!(w, "- agent_id: `{}`", self.agent_id).map_err(io)?;
        writeln!(w, "- logical: `{}`", self.bundle_logical_hash).map_err(io)?;
        writeln!(w, "- archive: `{}`", self.bundle_archive_hash).map_err(io)?;
        if let Some(s) = &self.signature {
            writeln!(w, "- signature: `{}` (`{}`)", s.algorithm, s.key_id).map_err(io)?;
        } else {
            writeln!(w, "- signature: _unsigned_").map_err(io)?;
        }
        Ok(())
    }
}

// ---- VerificationResult ----

impl Renderable for VerificationResult {
    fn render_human(&self, w: &mut dyn Write, opts: &RenderOptions) -> CliResult<()> {
        let label = if self.valid { "VALID" } else { "INVALID" };
        let styled = if opts.no_color {
            label.to_string()
        } else if self.valid {
            console::style(label).green().bold().to_string()
        } else {
            console::style(label).red().bold().to_string()
        };
        writeln!(w, "verification: {styled}").map_err(io)?;
        for c in &self.checks {
            let mark = if c.passed { "ok" } else { "FAIL" };
            writeln!(
                w,
                "  [{mark}] {}{}",
                c.name,
                c.detail
                    .as_deref()
                    .map(|d| format!(" — {d}"))
                    .unwrap_or_default()
            )
            .map_err(io)?;
        }
        Ok(())
    }

    fn render_json(&self, w: &mut dyn Write, pretty: bool) -> CliResult<()> {
        write_json(w, self, pretty)
    }

    fn render_markdown(&self, w: &mut dyn Write) -> CliResult<()> {
        writeln!(w, "# Verification result").map_err(io)?;
        writeln!(w, "- valid: **{}**", if self.valid { "yes" } else { "no" }).map_err(io)?;
        for c in &self.checks {
            writeln!(
                w,
                "- {} `{}`{}",
                if c.passed { "ok" } else { "FAIL" },
                c.name,
                c.detail
                    .as_deref()
                    .map(|d| format!(" — {d}"))
                    .unwrap_or_default()
            )
            .map_err(io)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenomic_core::ValidationIssue;

    fn opts() -> RenderOptions {
        RenderOptions {
            no_color: true,
            no_unicode: false,
            width: None,
        }
    }

    #[test]
    fn validation_report_human_snapshot() {
        let mut r = ValidationReport::default();
        r.valid = false;
        r.push_error(ValidationIssue {
            code: "agenomic::bundle::missing_required_file".into(),
            severity: Severity::High,
            message: "missing required file: genome.yaml".into(),
            path: Some("genome.yaml".into()),
            hint: None,
            doc: None,
        });
        let mut buf = Vec::new();
        r.render_human(&mut buf, &opts()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        insta::assert_snapshot!(s);
    }

    #[test]
    fn validation_report_clean_snapshot() {
        let r = ValidationReport {
            valid: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        r.render_human(&mut buf, &opts()).unwrap();
        insta::assert_snapshot!(String::from_utf8(buf).unwrap());
    }
}
