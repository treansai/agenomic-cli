//! Shared entry point for the `agenomic` and `agm` CLI binaries.

mod cli;
mod commands;
mod render;

use agenomic_core::CliError;
use clap::{CommandFactory, FromArgMatches};

use cli::{Cli, Commands};

pub fn run() -> i32 {
    let bin_name: &'static str = Box::leak(
        std::env::args_os()
            .next()
            .and_then(|s| {
                std::path::PathBuf::from(s)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "agenomic".to_string())
            .into_boxed_str(),
    );

    let mut cmd = Cli::command().name(bin_name).bin_name(bin_name);
    let matches = cmd.get_matches_mut();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

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
        Commands::Init(args) => commands::cmd_init(args, format),
        Commands::Update(args) => commands::cmd_update(args, format),
        Commands::Validate(args) => commands::cmd_validate(args, format, no_color),
        Commands::Build(args) => commands::cmd_build(args, format, no_color),
        Commands::Inspect(args) => commands::cmd_inspect(args, format, no_color),
        Commands::Run(args) => commands::cmd_run(args, format, no_color),
        Commands::Port(args) => commands::cmd_port(args, format, no_color),
        Commands::Compile(args) => commands::cmd_compile(args, format, no_color),
        Commands::Policy(args) => commands::cmd_policy(args, format, no_color),
        Commands::Governance(args) => commands::cmd_governance(args, format, no_color),
        Commands::Hash(args) => commands::cmd_hash(args, format, no_color),
        Commands::Diff(args) => commands::cmd_diff(args, format, no_color),
        Commands::Replay(args) => commands::cmd_replay(args, format, no_color),
        Commands::Attest(args) => commands::cmd_attest(args, format, no_color),
        Commands::Verify(args) => commands::cmd_verify(args, format, no_color),
        Commands::Trace(args) => commands::cmd_trace(args),
        Commands::Atep(args) => commands::cmd_atep(args),
        Commands::Cloud(args) => commands::cmd_cloud(args, cli.profile.as_deref()),
        Commands::Bucket(args) => commands::cmd_bucket(args, cli.profile.as_deref()),
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
    exit.as_i32()
}

fn print_error(e: &CliError) {
    eprintln!("error: {e}");
    if let Some(help) = miette_help(e) {
        eprintln!("       help: {help}");
    }
}

fn miette_help(e: &CliError) -> Option<String> {
    use miette::Diagnostic;
    e.help().map(|h| h.to_string())
}
