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
    pub fn to_severity(self) -> agenomic_core::Severity {
        match self {
            Self::Info => agenomic_core::Severity::Info,
            Self::Low => agenomic_core::Severity::Low,
            Self::Medium => agenomic_core::Severity::Medium,
            Self::High => agenomic_core::Severity::High,
            Self::Critical => agenomic_core::Severity::Critical,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "agenomic", version, about = "Agenomic CLI", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[arg(global = true, long, env = "AGENOMIC_PROFILE")]
    pub profile: Option<String>,

    #[arg(global = true, long, env = "AGENOMIC_NO_COLOR")]
    pub no_color: bool,

    #[arg(
        global = true,
        long = "format",
        value_enum,
        env = "AGENOMIC_FORMAT",
        default_value = "human"
    )]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize an empty agent bundle in the current directory.
    Init(InitArgs),
    /// Re-detect, merge into the existing bundle, and commit the change.
    Update(UpdateArgs),
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
    Completions { shell: clap_complete::Shell },
}

/// A detection source selectable via `--from` (every source except defaults).
/// Variant names render as the kebab-case labels in §2.2 (`package-json`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SourceArg {
    Pyproject,
    PackageJson,
    Cargo,
    GoMod,
    AgenomicYaml,
    Readme,
    Git,
    Dockerfile,
}

impl SourceArg {
    /// Map to the detection crate's [`agenomic_detect::Source`].
    pub fn to_source(self) -> agenomic_detect::Source {
        use agenomic_detect::Source;
        match self {
            SourceArg::Pyproject => Source::Pyproject,
            SourceArg::PackageJson => Source::PackageJson,
            SourceArg::Cargo => Source::Cargo,
            SourceArg::GoMod => Source::GoMod,
            SourceArg::AgenomicYaml => Source::AgenomicYaml,
            SourceArg::Readme => Source::Readme,
            SourceArg::Git => Source::Git,
            SourceArg::Dockerfile => Source::Dockerfile,
        }
    }
}

#[derive(Debug, Parser)]
pub struct InitArgs {
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Override the detected agent id.
    #[arg(long)]
    pub agent_id: Option<String>,
    /// Override the detected agent name.
    #[arg(long)]
    pub name: Option<String>,
    /// Restrict detection to these sources (repeatable).
    #[arg(long = "from", value_enum)]
    pub from: Vec<SourceArg>,
    /// Skip detection entirely; behave like the legacy scaffolder.
    #[arg(long)]
    pub no_detect: bool,
    /// Overwrite existing bundle files.
    #[arg(long)]
    pub force: bool,
    /// Print the genome that would be written; write nothing; exit 0.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct UpdateArgs {
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Commit message override (default: the auto-generated template).
    #[arg(long, short)]
    pub message: Option<String>,
    /// Force the auto-commit on (default: on when inside a git repo).
    #[arg(long)]
    pub commit: bool,
    /// Write the files but do not commit.
    #[arg(long = "no-commit")]
    pub no_commit: bool,
    /// Sign the commit (currently unsupported by the offline commit path).
    #[arg(long)]
    pub sign: bool,
    /// Commit even with unrelated dirty changes or a detached/protected HEAD.
    #[arg(long)]
    pub allow_dirty: bool,
    /// Drop list items that detection produced before but no longer does.
    #[arg(long)]
    pub prune: bool,
    /// Logical step label (sanitised to [a-z0-9_-]); appears in the commit.
    #[arg(long)]
    pub step: Option<String>,
    /// Print the diff vs. current files; exit 0; write nothing; no commit.
    #[arg(long)]
    pub dry_run: bool,
    /// Restrict detection to these sources (repeatable).
    #[arg(long = "from", value_enum)]
    pub from: Vec<SourceArg>,
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
    /// Push an agent and its bundle to Agenomic Cloud.
    ///
    /// Creates the agent if `--agent-id` is not given, then uploads the
    /// `.bundle.tar.zst` as a base64 payload to `POST /v1/bundles`.
    // Has its own `--version` (bundle label); disable the auto version flag
    // that `propagate_version` would otherwise add (clap 4.6 rejects the clash).
    #[command(disable_version_flag = true)]
    PushAgent {
        /// Path to the bundle archive (`.bundle.tar.zst`) to upload.
        bundle: PathBuf,
        /// Agent name. Used both as the agent's display name and (when
        /// creating a new agent) as the source for its slug.
        #[arg(long)]
        name: String,
        /// Optional human description, stored on the agent record.
        #[arg(long)]
        description: Option<String>,
        /// Bundle version label (e.g. `v0.1.0`). Defaults to "v0.1.0".
        #[arg(long, default_value = "v0.1.0")]
        version: String,
        /// Reuse an existing agent by id instead of creating a new one.
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Create a release pinning a bundle to an agent at a version label.
    #[command(disable_version_flag = true)]
    PushRelease {
        /// Agent id (UUID) to release for.
        #[arg(long)]
        agent_id: String,
        /// Bundle id (UUID) to release.
        #[arg(long)]
        bundle_id: String,
        /// Release version label (e.g. `v1.0.0`).
        #[arg(long)]
        version: String,
        /// Optional release notes (markdown), stored on the release.
        #[arg(long)]
        notes: Option<String>,
    },
    /// Enqueue a deterministic replay job for an agent.
    PushReplay {
        /// Agent id (UUID) to replay.
        #[arg(long)]
        agent_id: String,
        /// Optional release id (UUID) to pin the replay to.
        #[arg(long)]
        release_id: Option<String>,
        /// Trace ids (UUIDs) to feed into the replay. Repeat the flag for
        /// multiple traces; an empty list runs the worker against the
        /// agent's standard probe set.
        #[arg(long = "trace-id", value_name = "UUID")]
        trace_ids: Vec<String>,
        /// Run mode: `deterministic` (default) or `statistical`.
        #[arg(long, default_value = "deterministic")]
        mode: String,
    },
    /// Sign a release with a replay job's evidence.
    PushAttestation {
        /// Release id (UUID) being attested.
        #[arg(long)]
        release_id: String,
        /// Replay job id (UUID) whose report becomes the evidence.
        #[arg(long)]
        replay_job_id: String,
    },
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
