use std::fs;
use std::path::PathBuf;

use agentlock_bundle::{build_bundle, hash_source, load_bundle_from_source};
use agentlock_core::{
    default_attestation_output, init_bundle_dir, parse_trace_events, validate_bundle_dir,
    ReleaseAttestation, ReplayReport,
};
use agentlock_diff::{diff_bundles, render_diff};
use agentlock_replay_local::{LocalDeterministicProvider, ReplayProvider};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "agentlock")]
#[command(about = "Developer CLI for AgentLock bundles", version)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init {
        path: PathBuf,
    },
    Validate {
        path: PathBuf,
    },
    Build {
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        bundle_or_folder: PathBuf,
    },
    Hash {
        bundle_or_folder: PathBuf,
    },
    Diff {
        old: PathBuf,
        new: PathBuf,
    },
    Replay {
        bundle_or_folder: PathBuf,
        traces: PathBuf,
        #[arg(long, default_value_t = 1)]
        runs: u32,
    },
    Attest {
        bundle_or_folder: PathBuf,
        #[arg(long)]
        replay_report: PathBuf,
    },
}

pub fn run() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            init_bundle_dir(&path)?;
            println!("Initialized bundle at {}", path.display());
        }
        Commands::Validate { path } => {
            validate_bundle_dir(&path)?;
            println!("Bundle is valid: {}", path.display());
        }
        Commands::Build { path, output } => {
            let hash = build_bundle(&path, &output)?;
            println!("Built bundle: {}", output.display());
            println!("Bundle hash: {hash}");
        }
        Commands::Inspect { bundle_or_folder } => {
            let bundle = load_bundle_from_source(&bundle_or_folder)?;
            print_inspection(&bundle);
        }
        Commands::Hash { bundle_or_folder } => {
            let hash = hash_source(&bundle_or_folder)?;
            println!("{hash}");
        }
        Commands::Diff { old, new } => {
            let old_bundle = load_bundle_from_source(&old)?;
            let new_bundle = load_bundle_from_source(&new)?;
            println!("{}", render_diff(&diff_bundles(&old_bundle, &new_bundle)));
        }
        Commands::Replay {
            bundle_or_folder,
            traces,
            runs,
        } => {
            let bundle = load_bundle_from_source(&bundle_or_folder)?;
            let events = parse_trace_events(&traces)?;
            let provider = LocalDeterministicProvider;
            let mut report = provider.replay(&bundle, &events, runs)?;
            report.bundle_hash = hash_source(&bundle_or_folder)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Attest {
            bundle_or_folder,
            replay_report,
        } => {
            let bundle = load_bundle_from_source(&bundle_or_folder)?;
            let bundle_hash = hash_source(&bundle_or_folder)?;
            let report = read_replay_report(&replay_report)?;

            anyhow::ensure!(
                report.contract_id == bundle.behavior_contract.contract.id,
                "replay report contract_id `{}` does not match bundle contract `{}`",
                report.contract_id,
                bundle.behavior_contract.contract.id
            );

            let attestation = ReleaseAttestation {
                attestation_version: 1,
                bundle_hash,
                behavior_contract_id: bundle.behavior_contract.contract.id.clone(),
                generated_at: Utc::now(),
                replay_summary: report.summary.clone(),
                contract_result: if report.summary.contract_passed {
                    "pass".to_owned()
                } else {
                    "fail".to_owned()
                },
                replay_report_path: replay_report.display().to_string(),
                signature: None,
            };

            let output = default_attestation_output(&bundle_or_folder);
            let json = serde_json::to_string_pretty(&attestation)?;
            fs::write(&output, json)
                .with_context(|| format!("failed to write `{}`", output.display()))?;
            println!("Wrote {}", output.display());
        }
    }

    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .without_time()
        .try_init();
}

fn print_inspection(bundle: &agentlock_core::LoadedBundle) {
    let tools = if bundle.genome.tools.is_empty() {
        "none".to_owned()
    } else {
        bundle
            .genome
            .tools
            .iter()
            .map(|tool| tool.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let knowledge = if bundle.genome.knowledge_snapshots.is_empty() {
        "none".to_owned()
    } else {
        bundle
            .genome
            .knowledge_snapshots
            .iter()
            .map(|snapshot| snapshot.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    println!("agent_id: {}", bundle.genome.agent.id);
    println!("name: {}", bundle.genome.agent.name);
    println!("version: {}", bundle.genome.agent.version);
    println!("model_provider: {}", bundle.genome.model.provider);
    println!("model: {}", bundle.genome.model.model);
    println!("tools: {tools}");
    println!("knowledge_snapshots: {knowledge}");
    println!(
        "behavior_contract_id: {}",
        bundle.behavior_contract.contract.id
    );
}

fn read_replay_report(path: &PathBuf) -> Result<ReplayReport> {
    let json =
        fs::read_to_string(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    serde_json::from_str(&json)
        .with_context(|| format!("invalid replay report JSON in `{}`", path.display()))
}
