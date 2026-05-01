//! Output rendering helper used by every command handler.

use std::io::Write;

use agentlock_core::{CliError, CliResult};
use agentlock_report::{RenderOptions, Renderable};

use crate::cli::OutputFormat;

pub fn render<R: Renderable + serde::Serialize>(
    value: &R,
    format: OutputFormat,
    no_color: bool,
) -> CliResult<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match format {
        OutputFormat::Human => {
            let opts = RenderOptions {
                no_color: no_color || !console::Term::stdout().features().colors_supported(),
                ..Default::default()
            };
            value.render_human(&mut handle, &opts)?;
        }
        OutputFormat::Json => value.render_json(&mut handle, false)?,
        OutputFormat::JsonPretty => value.render_json(&mut handle, true)?,
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(value)
                .map_err(|e| CliError::Internal(format!("yaml: {e}")))?;
            handle
                .write_all(s.as_bytes())
                .map_err(|e| CliError::Internal(format!("write: {e}")))?;
        }
    }
    Ok(())
}
