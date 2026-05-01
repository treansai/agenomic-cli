//! Top-level clap definitions.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    JsonPretty,
    Yaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LevelArg {
    Basic,
    Strict,
    Ci,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    pub fn to_severity(self) -> agentlock_core::Severity {
        match self {
            Self::Info => agentlock_core::Severity::Info,
            Self::Low => agentlock_core::Severity::Low,
            Self::Medium => agentlock_core::Severity::Medium,
            Self::High => agentlock_core::Severity::High,
            Self::Critical => agentlock_core::Severity::Critical,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "agentlock", version, about = "AgentLock CLI", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[arg(global = true, long, env = "AGENTLOCK_PROFILE")]
    pub profile: Option<String>,

    #[arg(global = true, long, env = "AGENTLOCK_NO_COLOR")]
    pub no_color: bool,

    #[arg(global = true, long = "format", value_enum, env = "AGENTLOCK_FORMAT", default_value = "human")]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize an empty agent bundle in the current directory.
    Init(InitArgs),
    /// Validate a bundle directory or archive.
    Validate(ValidateArgs),
    /// Build a `.bundle.tar.zst` from a directory.
    Build(BuildArgs),
    /// Inspect a bundle directory or archive.
    Inspect(InspectArgs),
    /// Print the canonical hash of a bundle.
    Hash(HashArgs),
    /// Diff two bundles.
    Diff(DiffArgs),
    /// Run a deterministic offline replay.
    Replay(ReplayArgs),
    /// Create a release attestation.
    Attest(AttestArgs),
    /// Verify an attestation.
    Verify(VerifyArgs),
    /// Trace utilities.
    Trace(TraceCommand),
    /// ATEP store and event utilities.
    Atep(AtepCommand),
    /// Cloud authentication.
    Cloud(CloudCommand),
    /// Bundle utilities (extract, manifest).
    Bundle(BundleCommand),
    /// Run system diagnostics.
    Doctor,
    /// Print shell completion script.
    Completions {
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Parser)]
pub struct InitArgs {
    #[arg(default_value = ".")]
    pub path: PathBuf,
    #[arg(long)]
    pub agent_id: Option<String>,
    #[arg(long, default_value = "Example Agent")]
    pub name: String,
}

#[derive(Debug, Parser)]
pub struct ValidateArgs {
    pub target: PathBuf,
    #[arg(long, value_enum, default_value = "strict")]
    pub level: LevelArg,
}

#[derive(Debug, Parser)]
pub struct BuildArgs {
    pub input: PathBuf,
    #[arg(long, short)]
    pub output: PathBuf,
    #[arg(long, default_value_t = 3)]
    pub compression_level: i32,
    #[arg(long)]
    pub strict: bool,
    #[arg(long)]
    pub allow_symlinks: bool,
}

#[derive(Debug, Parser)]
pub struct InspectArgs {
    pub target: PathBuf,
}

#[derive(Debug, Parser)]
pub struct HashArgs {
    pub target: PathBuf,
    #[arg(long)]
    pub prefix: bool,
}

#[derive(Debug, Parser)]
pub struct DiffArgs {
    pub baseline: PathBuf,
    pub candidate: PathBuf,
    #[arg(long, value_enum, default_value = "critical")]
    pub fail_on: SeverityArg,
    #[arg(long)]
    pub ignore_prompts_whitespace: bool,
}

#[derive(Debug, Parser)]
pub struct ReplayArgs {
    pub bundle: PathBuf,
    pub traces: Option<PathBuf>,
    #[arg(long)]
    pub from_atep: Option<PathBuf>,
    #[arg(long)]
    pub contract: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    pub runs_per_trace: u32,
    #[arg(long, value_enum, default_value = "critical")]
    pub fail_on: SeverityArg,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct AttestArgs {
    pub bundle: PathBuf,
    #[arg(long)]
    pub replay_report: Option<PathBuf>,
    #[arg(long)]
    pub atep: Option<PathBuf>,
    #[arg(long)]
    pub sign_with: Option<PathBuf>,
    #[arg(long, default_value = "attestation.json")]
    pub output: PathBuf,
    #[arg(long)]
    pub generate_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct VerifyArgs {
    pub attestation: PathBuf,
    #[arg(long)]
    pub atep: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct TraceCommand {
    #[command(subcommand)]
    pub command: TraceSub,
}

#[derive(Debug, Subcommand)]
pub enum TraceSub {
    /// Validate a JSONL trace file against the schema.
    Validate { path: PathBuf },
    /// Summarize a JSONL trace file.
    Summarize { path: PathBuf },
}

#[derive(Debug, Parser)]
pub struct AtepCommand {
    #[command(subcommand)]
    pub command: AtepSub,
}

#[derive(Debug, Subcommand)]
pub enum AtepSub {
    /// Initialize a new ATEP store.
    Init {
        path: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Append an event to an ATEP store.
    Append {
        path: PathBuf,
        #[arg(long)]
        stream: String,
        #[arg(long, name = "type")]
        event_type: String,
        #[arg(long)]
        payload_file: Option<PathBuf>,
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Verify all events and segment merkle roots.
    Verify {
        path: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Inspect store metadata.
    Inspect { path: PathBuf },
    /// Reconstruct agent state at an optional clock.
    ReplayState {
        path: PathBuf,
        #[arg(long)]
        at: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
pub struct CloudCommand {
    #[command(subcommand)]
    pub command: CloudSub,
}

#[derive(Debug, Subcommand)]
pub enum CloudSub {
    Login {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        api_key: String,
    },
    Whoami,
    Logout,
}

#[derive(Debug, Parser)]
pub struct BundleCommand {
    #[command(subcommand)]
    pub command: BundleSub,
}

#[derive(Debug, Subcommand)]
pub enum BundleSub {
    Extract {
        archive: PathBuf,
        destination: PathBuf,
    },
    Manifest {
        target: PathBuf,
    },
}
