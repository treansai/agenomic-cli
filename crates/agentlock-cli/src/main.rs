//! `agentlock` CLI binary entry point.

mod cli;
mod commands;
mod render;

use agentlock_core::{CliError, ExitCode};
use clap::Parser;

use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .compact()
        .try_init()
        .ok();

    let format = cli.format;
    let no_color = cli.no_color || std::env::var("NO_COLOR").is_ok();

    let result = match &cli.command {
        Commands::Init(args) => commands::cmd_init(args),
        Commands::Validate(args) => commands::cmd_validate(args, format, no_color),
        Commands::Build(args) => commands::cmd_build(args, format, no_color),
        Commands::Inspect(args) => commands::cmd_inspect(args, format, no_color),
        Commands::Hash(args) => commands::cmd_hash(args, format, no_color),
        Commands::Diff(args) => commands::cmd_diff(args, format, no_color),
        Commands::Replay(args) => commands::cmd_replay(args, format, no_color),
        Commands::Attest(args) => commands::cmd_attest(args, format, no_color),
        Commands::Verify(args) => commands::cmd_verify(args, format, no_color),
        Commands::Trace(args) => commands::cmd_trace(args),
        Commands::Atep(args) => commands::cmd_atep(args),
        Commands::Cloud(args) => commands::cmd_cloud(args),
        Commands::Bundle(args) => commands::cmd_bundle(args),
        Commands::Doctor => commands::cmd_doctor(),
        Commands::Completions { shell } => commands::cmd_completions(*shell),
    };

    let exit = match result {
        Ok(code) => code,
        Err(e) => {
            let code = e.exit_code();
            print_error(&e);
            code
        }
    };
    std::process::exit(exit.as_i32());
}

fn print_error(e: &CliError) {
    // For machine-readable output we print JSON diagnostic; otherwise a
    // brief message. We don't use miette here because cloning the
    // diagnostic across an immutable reference is awkward; the human
    // message captures the salient information.
    eprintln!("error: {e}");
    if let Some(help) = miette_help(e) {
        eprintln!("       help: {help}");
    }
}

fn miette_help(e: &CliError) -> Option<String> {
    use miette::Diagnostic;
    e.help().map(|h| h.to_string())
}
