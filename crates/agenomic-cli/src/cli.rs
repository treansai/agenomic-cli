//! Top-level clap definitions.

use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RuntimeAdapterArg {
    Plain,
    Langgraph,
    Crewai,
}

impl RuntimeAdapterArg {
    pub fn to_runtime_adapter(self) -> agenomic_bundle::RuntimeAdapter {
        match self {
            Self::Plain => agenomic_bundle::RuntimeAdapter::Plain,
            Self::Langgraph => agenomic_bundle::RuntimeAdapter::Langgraph,
            Self::Crewai => agenomic_bundle::RuntimeAdapter::Crewai,
        }
    }
}

/// Version string reported by `--version`, resolved at build time.
///
/// Priority:
/// 1. `AGENOMIC_VERSION` (build env) — the release workflow sets this to the
///    pushed git tag (e.g. `v0.2.0-rc.0`) so every published target, including
///    the cross-compiled ones built in a git-less container, reports the tag.
/// 2. `git describe` against the worktree — a working build reports the nearest
///    `v*` tag plus commit/dirty info (e.g. `v0.2.0-rc.0-3-gabc1234-modified`).
/// 3. `v` + the crate version — when built outside a git checkout (source
///    tarball) with no override.
///
/// The invariant the release relies on: tag `vX` ⇒ the binary reports `vX`.
pub const VERSION: &str = match option_env!("AGENOMIC_VERSION") {
    Some(v) => v,
    None => git_version::git_version!(
        args = ["--tags", "--always", "--dirty=-modified", "--match=v*"],
        cargo_prefix = "v",
        fallback = "unknown",
    ),
};

#[derive(Debug, Parser)]
#[command(name = "agenomic", version = VERSION, about = "Agenomic CLI", long_about = None)]
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
    /// Inspect a bundle directory, an archive, or an `agent://` reference.
    Inspect(InspectArgs),
    /// Resolve an `agent://` reference and launch the bundled agent.
    Run(RunArgs),
    /// Propose an `execution:` block for an existing codebase.
    Port(PortArgs),
    /// LLM-assisted completion of the fields detection cannot know
    /// (domain, criticality, description, skills, behavior rules,
    /// orchestration manifest descriptions).
    Enrich(EnrichArgs),
    /// Compile a genome into per-framework runtime adapters (`runtime/*.compiled`).
    Compile(CompileArgs),
    /// Evaluate the bundle's OPA/Rego policies against a launch context.
    Policy(PolicyCommand),
    /// Governance agents over flagged production traces (diagnostic / hypothesis / adversarial).
    Governance(GovernanceCommand),
    /// Tool Boundary Gate — deterministic, at-the-effect enforcement of tool calls.
    Gate(GateCommand),
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
    /// Online tracking of production agents (drift / loops / intent / harness).
    Track(TrackCommand),
    /// Review · Monitor · Protect — the continuous safety loop.
    Rmp(RmpCommand),
    /// Review: evaluate an agent with scenarios, risk matrix, and replay.
    Review(ReviewCliCommand),
    /// Monitor: observe live agent execution (RMP layer over tracking).
    Monitor(MonitorCliCommand),
    /// Protect: alerts, recommendations, and action plans from findings.
    Protect(ProtectCliCommand),
    /// Append-only, tamper-evident cryptographic event ledger.
    Ledger(LedgerCommand),
    /// Offline-verifiable evidence proof bundles (ledger-backed).
    Evidence(EvidenceCommand),
    /// Cloud authentication.
    Cloud(CloudCommand),
    /// Cloud administration (billing reconciliation, webhook events).
    Admin(AdminCommand),
    /// Bucket selection for cloud pushes.
    Bucket(BucketCommand),
    #[command(about = "Managed prompts: list, get, push, pull, render and export")]
    Prompts(PromptsCommand),
    #[command(about = "Release channels: list, history and the promotion hand-off")]
    Channels(ChannelsCommand),
    #[command(
        about = "Knowledge bases: documents, search, versions, publication, export and import"
    )]
    Knowledge(KnowledgeCommand),
    /// Bundle utilities (extract, manifest, runtime compilation).
    Bundle(BundleCommand),
    /// Model provider utilities (list providers, test connectivity).
    #[command(visible_alias = "provider")]
    Providers(ProvidersCommand),
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
    /// After detection, run the LLM enrichment pass (`agm enrich`) to fill
    /// the fields static analysis cannot know (domain, criticality,
    /// description, skills, behavior rules). Requires a provider API key.
    #[arg(long)]
    pub agent: bool,
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
    /// After the merge, run the LLM enrichment pass (`agm enrich`).
    #[arg(long)]
    pub agent: bool,
}

#[derive(Debug, Parser)]
pub struct EnrichArgs {
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Provider: `direct` (default — the genome's vendor via ANTHROPIC_API_KEY /
    /// OPENAI_API_KEY) or `cloud` (routes through Agenomic Cloud using your
    /// `agm cloud login` credentials; the internal model is reached server-side).
    /// A vendor name (`anthropic`/`openai`) forces that vendor in direct mode.
    /// Falls back to AGENOMIC_ENRICH_PROVIDER when unset.
    #[arg(long, env = "AGENOMIC_ENRICH_PROVIDER")]
    pub provider: Option<String>,
    /// Shortcut for `--provider cloud` (requires `agm cloud login`).
    #[arg(long)]
    pub cloud: bool,
    /// Model to call in direct mode (defaults to the genome's `runtime.model_id`).
    /// In cloud mode it is an optional hint; the server selects the model.
    /// Falls back to AGENOMIC_ENRICH_MODEL when unset.
    #[arg(long, env = "AGENOMIC_ENRICH_MODEL")]
    pub model: Option<String>,
    /// Print the proposed enrichment as JSON; write nothing; exit 0.
    #[arg(long)]
    pub dry_run: bool,
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
    /// Bundle directory, bundle archive, or `agent://<org>/<slug>` reference.
    pub target: String,
    /// When `target` is an `agent://` reference, look up the bundle in the
    /// current project's `./.agenomic/bundles/` instead of the global cache.
    #[arg(long)]
    pub local: bool,
    /// When `target` is an `agent://` reference, resolve the bundle from
    /// this explicit path instead of any cache.
    #[arg(long)]
    pub bundle_path: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct RunArgs {
    /// `agent://<org>/<slug>[@<qualifier>]` reference to launch.
    pub reference: String,
    /// Look up the bundle in `./.agenomic/bundles/` instead of the global cache.
    #[arg(long)]
    pub local: bool,
    /// Resolve the bundle from this explicit path instead of any cache.
    #[arg(long)]
    pub bundle_path: Option<PathBuf>,
    /// Extra `KEY=VALUE` env entries merged into the child (repeatable).
    /// Useful for satisfying required env vars from a profile.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// Hostname or CIDR added to the network allow-list. MVP-advisory only.
    #[arg(long = "allow-network", value_name = "HOST")]
    pub allow_network: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct PortArgs {
    /// Path to the codebase to analyse.
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

/// A compile target selectable via `--target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TargetArg {
    Plain,
    Langgraph,
    Crewai,
    GoogleAdk,
    Docker,
    Wasm,
}

impl TargetArg {
    pub fn to_target(self) -> agenomic_compile::CompileTarget {
        use agenomic_compile::CompileTarget;
        match self {
            TargetArg::Plain => CompileTarget::Plain,
            TargetArg::Langgraph => CompileTarget::LangGraph,
            TargetArg::Crewai => CompileTarget::CrewAi,
            TargetArg::GoogleAdk => CompileTarget::GoogleAdk,
            TargetArg::Docker => CompileTarget::Docker,
            TargetArg::Wasm => CompileTarget::Wasm,
        }
    }
}

#[derive(Debug, Parser)]
pub struct CompileArgs {
    /// Bundle directory containing `genome.yaml` and `prompts/`.
    #[arg(default_value = ".")]
    pub bundle: PathBuf,
    /// Target framework(s) to compile (repeatable). Defaults to all when
    /// neither `--target` nor `--all` is given.
    #[arg(long = "target", value_enum)]
    pub target: Vec<TargetArg>,
    /// Compile every supported target.
    #[arg(long)]
    pub all: bool,
    /// Write under this directory instead of `<bundle>/runtime/`.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Generate but do not write; print the file list (and the manifest) only.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: PolicySub,
}

#[derive(Debug, Subcommand)]
pub enum PolicySub {
    /// Evaluate `policies/*.rego` against an input document.
    Eval {
        /// Bundle directory containing a `policies/` folder.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// JSON input document. Defaults to a context derived from the bundle's
        /// `execution:` block when omitted.
        #[arg(long)]
        input: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
pub struct GovernanceCommand {
    #[command(subcommand)]
    pub command: GovernanceSub,
}

/// Shared ATEP-emission flags for the governance subcommands. When both are
/// set, the engine's results are sealed onto the store's signed `governance`
/// stream as a hash-linked batch.
#[derive(Debug, Parser, Clone)]
pub struct AtepEmitArgs {
    /// Emit the results as signed events on the ATEP `governance` stream at
    /// this store directory (must already be `agenomic atep init`-ialized).
    #[arg(long)]
    pub atep: Option<PathBuf>,
    /// ed25519 signing key for the emitted events. Required with `--atep`.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
    /// Also append the results to the cryptographic event ledger (dual-emit
    /// alongside the signed ATEP `governance` stream, never instead of it).
    #[arg(long)]
    pub ledger: bool,
    /// Ledger data root override (default `.agenomic/ledger`).
    #[arg(long)]
    pub ledger_store: Option<PathBuf>,
    /// Ledger key store override (default `~/.config/agenomic/keys`).
    #[arg(long)]
    pub ledger_keys: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum GovernanceSub {
    /// Cluster a JSONL stream of flagged traces (Mode 1: failure clustering).
    Cluster {
        /// Path to the JSONL traces file, or `-` for stdin.
        traces: PathBuf,
        #[command(flatten)]
        emit: AtepEmitArgs,
    },
    /// Generate textual remediation proposals from clusters (Mode 2: hypothesis generation).
    Hypothesize {
        /// Path to a clusters JSON file (output of `governance cluster`), or `-` for stdin.
        clusters: PathBuf,
        #[command(flatten)]
        emit: AtepEmitArgs,
    },
    /// Critique a single proposal (Mode 3: adversarial reviewer). Exits 16 on Block.
    Critique {
        /// Path to a proposal JSON file, or `-` for stdin.
        proposal: PathBuf,
        #[command(flatten)]
        emit: AtepEmitArgs,
    },
    /// Run the full Diagnostic → Hypothesis → Adversarial chain end-to-end.
    Audit {
        /// Path to the JSONL traces file, or `-` for stdin.
        traces: PathBuf,
        /// Exit 16 when at least one proposal lands at `Verdict::Block`.
        #[arg(long)]
        fail_on_block: bool,
        #[command(flatten)]
        emit: AtepEmitArgs,
    },
}

#[derive(Debug, Parser)]
pub struct GateCommand {
    #[command(subcommand)]
    pub command: GateSub,
}

#[derive(Debug, Subcommand)]
pub enum GateSub {
    /// Evaluate a proposed tool call at the boundary. Deterministic and
    /// LLM-free: exits 0 (allow), 16 (block), or 18 (human review required).
    Check {
        /// Tool-call JSON file, or `-` for stdin.
        tool_call: PathBuf,
        /// Directory with a `policies/` folder (Rego) and an optional `gate.json`.
        #[arg(long, default_value = ".")]
        policy: PathBuf,
        /// Override the gate rule set (defaults to `<policy>/gate.json`, then built-ins).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// A signed human-approval JSON to resume a held call
        /// (role / justification / timestamp).
        #[arg(long)]
        approval: Option<PathBuf>,
        /// On an approved resume, also record `tool.call.executed`.
        #[arg(long)]
        executed: bool,
        #[command(flatten)]
        emit: AtepEmitArgs,
    },
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
    /// Verify this run's ledger chain BEFORE replaying (exit 19 on failure)
    /// and attach the ledger proof to the replay report. The ledger proves
    /// provenance/integrity of the recorded events; replay itself stays
    /// statistical.
    #[arg(long)]
    pub from_ledger: Option<String>,
    /// Ledger data root override (default `.agenomic/ledger`).
    #[arg(long)]
    pub ledger_store: Option<PathBuf>,
    /// Ledger key store override (default `~/.config/agenomic/keys`).
    #[arg(long)]
    pub ledger_keys: Option<PathBuf>,
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

#[derive(Debug, Parser)]
pub struct BucketCommand {
    #[command(subcommand)]
    pub command: BucketSub,
}

/// Cloud administration commands. Require a Cloud profile whose API key
/// belongs to a workspace owner; the server enforces authorization.
#[derive(Debug, Parser)]
pub struct AdminCommand {
    #[command(subcommand)]
    pub command: AdminSub,
}

#[derive(Debug, Subcommand)]
pub enum AdminSub {
    /// Stripe billing administration.
    Billing(AdminBillingCommand),
}

#[derive(Debug, Parser)]
pub struct AdminBillingCommand {
    #[command(subcommand)]
    pub command: AdminBillingSub,
}

#[derive(Debug, Subcommand)]
pub enum AdminBillingSub {
    /// Reconcile the workspace's local billing projection against live
    /// Stripe state (repairs missed or out-of-order webhooks).
    Reconcile {
        /// Workspace (org) id. Defaults to the API key's workspace.
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Inspect or replay journaled Stripe webhook events.
    Event(AdminBillingEventCommand),
}

#[derive(Debug, Parser)]
pub struct AdminBillingEventCommand {
    #[command(subcommand)]
    pub command: AdminBillingEventSub,
}

#[derive(Debug, Subcommand)]
pub enum AdminBillingEventSub {
    /// Show one journaled webhook event (redacted; no raw payload).
    Inspect {
        /// Stripe event id (`evt_…`).
        stripe_event_id: String,
        /// Workspace (org) id. Defaults to the API key's workspace.
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Re-run one journaled webhook event through the idempotent processor.
    Retry {
        /// Stripe event id (`evt_…`).
        stripe_event_id: String,
        /// Workspace (org) id. Defaults to the API key's workspace.
        #[arg(long)]
        workspace: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum BucketSub {
    /// Select the active bucket for subsequent cloud pushes.
    Use {
        /// Bucket name/slug. Created if it does not already exist.
        #[arg(long)]
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CloudSub {
    Login {
        /// Cloud endpoint URL. Defaults to the hosted Agenomic Cloud.
        #[arg(long, default_value = agenomic_config::DEFAULT_ENDPOINT)]
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
pub struct ProvidersCommand {
    #[command(subcommand)]
    pub command: ProvidersSub,
}

#[derive(Debug, Subcommand)]
pub enum ProvidersSub {
    /// List the model providers Agenomic understands and whether each is
    /// configured in the current environment.
    List,
    /// Validate a provider's credentials and basic connectivity.
    ///
    /// For `huggingface`, this checks the token (`HUGGINGFACE_API_TOKEN` /
    /// `HF_TOKEN`) against the Hub and, when a model is given or
    /// `HUGGINGFACE_DEFAULT_MODEL` is set, resolves its metadata. Tokens are
    /// never printed.
    Test {
        /// Provider name or alias (e.g. `huggingface`, `hf`, `hugging_face`).
        provider: String,
        /// Optional model id to resolve metadata for (defaults to
        /// `HUGGINGFACE_DEFAULT_MODEL` when unset).
        #[arg(long)]
        model: Option<String>,
        /// Optional model revision (branch/tag/commit). Defaults to `main`.
        #[arg(long)]
        revision: Option<String>,
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
    CompileRuntime {
        /// Bundle directory to compile. Archives are not supported yet.
        target: PathBuf,
        /// Adapter(s) to emit. Empty = `plain` plus any framework-specific
        /// adapter implied by the genome (`langgraph` / `crewai`).
        #[arg(long = "adapter", value_enum)]
        adapters: Vec<RuntimeAdapterArg>,
        /// Override the destination directory. Defaults to `<target>/runtime`.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
pub struct TrackCommand {
    #[command(subcommand)]
    pub command: TrackSub,
}

/// Terminal status to apply when stopping a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SessionStatusArg {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Subcommand)]
pub enum TrackSub {
    /// Start an online tracking session for a bundle/release. The bundle's
    /// genome + lockfile seed the drift baseline; the behavior contract and
    /// policies feed the runtime harness at `stop`/`report` time.
    Start {
        /// Bundle directory (defaults to the current directory).
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// Release id to bind the session to.
        #[arg(long)]
        release: Option<String>,
        /// Deployment environment.
        #[arg(long, default_value = "production")]
        env: String,
        /// Tracking config (YAML/JSON). Defaults to built-in thresholds.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the agent id (default: read from the genome/lockfile).
        #[arg(long)]
        agent: Option<String>,
        /// Store root directory (default: `<cwd>/.agenomic/tracking`).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Bind the session to the cryptographic event ledger: session
        /// lifecycle and every ingested event are appended (hash-committed)
        /// to the ledger.
        #[arg(long)]
        ledger: bool,
        /// Ledger data root override (default `.agenomic/ledger`).
        #[arg(long)]
        ledger_store: Option<PathBuf>,
        /// Ledger key store override (default `~/.config/agenomic/keys`).
        #[arg(long)]
        ledger_keys: Option<PathBuf>,
    },
    /// Ingest a runtime event into a session (idempotent; safe to retry).
    Event {
        /// Target session id.
        #[arg(long)]
        session: String,
        /// Event JSON file, or `-` for stdin.
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Print a session's recorded events and alerts.
    Tail {
        #[arg(long)]
        session: String,
        /// Show at most this many trailing events.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Show a session's status and summary metrics.
    Status {
        #[arg(long)]
        session: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Build and export the online tracking report.
    Report {
        #[arg(long)]
        session: String,
        /// Write the JSON report to this path (in addition to rendering it).
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Attach the ledger proof block (root hash, run chain head, block
        /// ids, verification/gap/queue-loss status, signing key ids). The
        /// session must have been started with `--ledger`.
        #[arg(long)]
        include_ledger_proof: bool,
    },
    /// Stop a session: run the harness, finalize, and persist the report.
    Stop {
        #[arg(long)]
        session: String,
        /// Terminal status to record.
        #[arg(long, value_enum, default_value = "completed")]
        status: SessionStatusArg,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

/// Shared session-store flag for the RMP command family.
#[derive(Debug, Parser, Clone)]
pub struct RmpStoreArgs {
    /// RMP store root (default `<cwd>/.agenomic/rmp`).
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// Tracking store root for the live path
    /// (default `<cwd>/.agenomic/tracking`).
    #[arg(long)]
    pub tracking_store: Option<PathBuf>,
}

/// Shared ledger flags for the RMP command family.
#[derive(Debug, Parser, Clone)]
pub struct RmpLedgerArgs {
    /// Record RMP lifecycle events and live events into the cryptographic
    /// ledger.
    #[arg(long)]
    pub ledger: bool,
    /// Ledger data root override (default `.agenomic/ledger`).
    #[arg(long)]
    pub ledger_store: Option<PathBuf>,
    /// Ledger key store override (default `~/.config/agenomic/keys`).
    #[arg(long)]
    pub ledger_keys: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct RmpCommand {
    #[command(subcommand)]
    pub command: RmpSub,
}

#[derive(Debug, Subcommand)]
pub enum RmpSub {
    /// Start an RMP session for a bundle: creates the umbrella session and
    /// the underlying live-monitoring (tracking) session.
    Start {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// Release id to bind the session to.
        #[arg(long)]
        release: Option<String>,
        /// Deployment environment.
        #[arg(long, default_value = "production")]
        env: String,
        /// Override the agent id (default: read from the genome/lockfile).
        #[arg(long)]
        agent: Option<String>,
        #[command(flatten)]
        stores: RmpStoreArgs,
        #[command(flatten)]
        ledger: RmpLedgerArgs,
    },
    /// Show an RMP session's status and stage completion.
    Status {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Build (and persist) the unified RMP report.
    Report {
        #[arg(long)]
        session: String,
        /// Write the JSON report to this path (in addition to rendering it).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Attach the ledger proof (session must have been started with
        /// `--ledger`).
        #[arg(long)]
        include_ledger_proof: bool,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Run the Review stage for a bundle inside an RMP session (or
    /// standalone when --session is omitted).
    Review {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// RMP session to attach the review to.
        #[arg(long)]
        session: Option<String>,
        /// Scenario JSON file(s) (single object or array; repeatable).
        #[arg(long = "scenario")]
        scenarios: Vec<PathBuf>,
        /// Risk matrix JSON file.
        #[arg(long)]
        risk_matrix: Option<PathBuf>,
        /// Trace fixtures (JSONL) for deterministic replay.
        #[arg(long)]
        traces: Option<PathBuf>,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Show the Monitor stage status for an RMP session.
    Monitor {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Run the Protect stage over the session's findings.
    Protect {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Derive scenario enrichment proposals from a findings JSON file.
    EnrichScenarios {
        /// Findings JSON (array of findings, or an object with `findings`).
        #[arg(long)]
        from_findings: PathBuf,
        /// Write the proposals JSON to this path.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Review and act on a session's scenario-enrichment proposals — the
    /// human-approval step that closes the Review → Monitor → Protect →
    /// Review loop. Every transition is recorded on the ledger when the
    /// session is bound with `--ledger`.
    Proposals {
        #[command(subcommand)]
        action: ProposalAction,
    },
    /// Generate the action plan for one alert.
    ActionPlan {
        #[arg(long)]
        alert: String,
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Export the audit-ready evidence bundle for a session.
    ExportEvidence {
        #[arg(long)]
        session: String,
        /// Output directory for the evidence bundle.
        #[arg(long)]
        output: PathBuf,
        /// Also export the offline-verifiable ledger proof bundle members.
        #[arg(long)]
        include_ledger: bool,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProposalAction {
    /// List a session's enrichment proposals with their approval status.
    List {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Approve a proposal (draft/pending → approved). A reviewer identity is
    /// mandatory for proposals that require human approval.
    Approve {
        proposal_id: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        reviewer: Option<String>,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Reject a proposal (draft/pending → rejected).
    Reject {
        proposal_id: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        reviewer: Option<String>,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Apply an approved proposal: add its scenario to the Review corpus so
    /// the next `review` run covers the production incident that spawned it.
    Apply {
        proposal_id: String,
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Parser)]
pub struct ReviewCliCommand {
    #[command(subcommand)]
    pub command: ReviewSub,
}

#[derive(Debug, Subcommand)]
pub enum ReviewSub {
    /// Run a review pass over a bundle.
    Run {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// Scenario JSON file(s) (repeatable).
        #[arg(long = "scenario")]
        scenarios: Vec<PathBuf>,
        /// Risk matrix JSON file.
        #[arg(long)]
        risk_matrix: Option<PathBuf>,
        /// Trace fixtures (JSONL) for deterministic replay.
        #[arg(long)]
        traces: Option<PathBuf>,
        /// Write the review outcome JSON to this path.
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Manage the persistent scenario corpus of a bundle.
    Scenarios(ReviewScenariosCommand),
    /// Show (or initialize) the bundle's risk matrix.
    RiskMatrix {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Show a stored review outcome.
    Report {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Parser)]
pub struct ReviewScenariosCommand {
    #[command(subcommand)]
    pub command: ReviewScenariosSub,
}

#[derive(Debug, Subcommand)]
pub enum ReviewScenariosSub {
    /// List the scenario corpus.
    List {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Validate and add a scenario file to the corpus.
    Add {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// Scenario JSON file (single object or array).
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Parser)]
pub struct MonitorCliCommand {
    #[command(subcommand)]
    pub command: MonitorSub,
}

#[derive(Debug, Subcommand)]
pub enum MonitorSub {
    /// Start a live monitor session for a bundle (tracking + RMP layer).
    Start {
        /// Bundle directory.
        #[arg(default_value = ".")]
        bundle: PathBuf,
        /// Release id to bind the session to.
        #[arg(long)]
        release: Option<String>,
        /// Deployment environment.
        #[arg(long, default_value = "production")]
        env: String,
        /// Tracking config (YAML/JSON).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the agent id.
        #[arg(long)]
        agent: Option<String>,
        #[command(flatten)]
        stores: RmpStoreArgs,
        #[command(flatten)]
        ledger: RmpLedgerArgs,
    },
    /// Ingest a runtime event (idempotent; safe to retry).
    Event {
        #[arg(long)]
        session: String,
        /// Event JSON file, or `-` for stdin.
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Print the session's recent events and alerts.
    Tail {
        #[arg(long)]
        session: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// List the monitor findings derived from the session so far.
    Findings {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Derive scenario enrichment proposals from the session's findings
    /// (the Monitor → Review feedback edge).
    EnrichReview {
        #[arg(long)]
        session: String,
        /// Write the proposals JSON to this path.
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Stop the session: run the harness and persist the monitor outcome.
    Stop {
        #[arg(long)]
        session: String,
        #[arg(long, value_enum, default_value = "completed")]
        status: SessionStatusArg,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Parser)]
pub struct ProtectCliCommand {
    #[command(subcommand)]
    pub command: ProtectSub,
}

#[derive(Debug, Subcommand)]
pub enum ProtectSub {
    /// List (generating if needed) the alerts for a session.
    Alerts {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Generate the action plan for one alert.
    ActionPlan {
        #[arg(long)]
        alert: String,
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// List the recommendations for a session.
    Recommendations {
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
    /// Show the resolved notification routes for one alert (dispatch is
    /// integration-specific; the OSS CLI prints and records the routing).
    Notify {
        #[arg(long)]
        alert: String,
        #[arg(long)]
        session: String,
        #[command(flatten)]
        stores: RmpStoreArgs,
    },
}

#[derive(Debug, Parser)]
pub struct LedgerCommand {
    #[command(subcommand)]
    pub command: LedgerSub,
}

/// Shared location flags for the ledger subcommands.
#[derive(Debug, Parser, Clone)]
pub struct LedgerDirs {
    /// Ledger data root (store, WAL, dead-letter, blocks).
    /// Default: `<cwd>/.agenomic/ledger`.
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// Signing-key store directory.
    /// Default: `~/.config/agenomic/keys`.
    #[arg(long)]
    pub keys: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum LedgerSub {
    /// Initialize the ledger layout and generate a signing key if absent.
    Init {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Show the ledger overview: entries, runs, chain head, blocks, WAL
    /// health, dead-letter backlog.
    Status {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Seal all unsealed entries into a signed block (explicit flush
    /// trigger).
    Seal {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Append one event (JSON file, or `-` for stdin) to the ledger.
    Append {
        /// Event JSON: `{agent_id, run_id, event_type, payload, ...}`.
        #[arg(long)]
        event: PathBuf,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Print the most recent entries (optionally for one run).
    Tail {
        /// Only entries of this run.
        #[arg(long)]
        run: Option<String>,
        /// Show at most this many trailing entries.
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Run the full offline verification engine (exit 19 on failure).
    Verify {
        /// Verify a single run's chain instead of the whole ledger.
        #[arg(long)]
        run: Option<String>,
        /// Verify a single block against its covered entries.
        #[arg(long)]
        block: Option<String>,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Export entries as a verifiable JSONL chain.
    Export {
        /// Only entries of this run.
        #[arg(long)]
        run: Option<String>,
        /// Output path for the JSONL export.
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Show one entry in full (by ledger entry id or producer event id).
    Inspect {
        /// `ledger_entry_id` or `event_id`.
        #[arg(long)]
        entry: String,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Ingestion queue management.
    Queue(LedgerQueueCommand),
    /// Signing-key lifecycle.
    Keys(LedgerKeysCommand),
}

#[derive(Debug, Parser)]
pub struct LedgerQueueCommand {
    #[command(subcommand)]
    pub command: LedgerQueueSub,
}

#[derive(Debug, Subcommand)]
pub enum LedgerQueueSub {
    /// Show durable queue state: pending WAL records, damage, dead letters.
    Status {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Drain pending WAL records into the signed ledger.
    Flush {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Re-attempt pending WAL records (same recovery path as flush).
    Retry {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Dead-letter management.
    DeadLetter(LedgerDeadLetterCommand),
}

#[derive(Debug, Parser)]
pub struct LedgerDeadLetterCommand {
    #[command(subcommand)]
    pub command: LedgerDeadLetterSub,
}

#[derive(Debug, Subcommand)]
pub enum LedgerDeadLetterSub {
    /// List dead-lettered events with reasons and attempt counts.
    List {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Re-submit dead-lettered events; records are removed only on success.
    Replay {
        /// Replay one record instead of all.
        #[arg(long)]
        id: Option<String>,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
}

#[derive(Debug, Parser)]
pub struct LedgerKeysCommand {
    #[command(subcommand)]
    pub command: LedgerKeysSub,
}

#[derive(Debug, Subcommand)]
pub enum LedgerKeysSub {
    /// Generate the first signing key (use `rotate` to supersede one).
    Generate {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// List keys with status (active / rotated / revoked) and usage.
    List {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Rotate: new active key; the old key keeps verifying history.
    Rotate {
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Revoke a non-active key (entries it signed are flagged, not failed).
    Revoke {
        /// Key id (`ed25519:<8hex>`).
        key_id: String,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Print (or write) a key's public half as SPKI PEM.
    ExportPublic {
        /// Key id; defaults to the active key.
        #[arg(long)]
        key: Option<String>,
        /// Write to this file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
}

#[derive(Debug, Parser)]
pub struct EvidenceCommand {
    #[command(subcommand)]
    pub command: EvidenceSub,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceSub {
    /// Assemble an offline-verifiable proof bundle from the ledger.
    /// Locally-signed bundles are technical integrity evidence with a
    /// non-probative status; org-attested probative packs are a hosted
    /// service.
    Export {
        /// Scope the bundle to one run (omit for the whole ledger).
        #[arg(long)]
        run: Option<String>,
        /// Output directory for the bundle.
        #[arg(long)]
        output: PathBuf,
        /// Include the ledger chain, blocks, Merkle data, signatures, and
        /// verification report (the §5.10 members).
        #[arg(long)]
        include_ledger: bool,
        /// Existing replay report to include as `replay_report.json`.
        #[arg(long)]
        replay_report: Option<PathBuf>,
        /// Existing policy results to include as `policy_results.json`.
        #[arg(long)]
        policy_results: Option<PathBuf>,
        /// Existing risk summary to include as `risk_summary.md`.
        #[arg(long)]
        risk_summary: Option<PathBuf>,
        #[command(flatten)]
        dirs: LedgerDirs,
    },
    /// Verify a proof bundle completely offline (no keystore, no network —
    /// public keys ship inside the bundle). Exit 19 on failure.
    Verify {
        /// Bundle directory.
        bundle: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct PromptsCommand {
    #[command(subcommand)]
    pub command: PromptsSub,
}

#[derive(Debug, Subcommand)]
pub enum PromptsSub {
    #[command(about = "List the managed prompts of the workspace")]
    List(PromptsListArgs),
    #[command(about = "Download one prompt version as an agenomic.prompt_file/v1 document")]
    Get(PromptsGetArgs),
    #[command(about = "Publish a local prompt file as a new immutable version")]
    Push(PromptsPushArgs),
    #[command(about = "Download prompt versions into <DIR>/<prompt_id>/<n>.prompt.json")]
    Pull(PromptsPullArgs),
    #[command(
        about = "Render a prompt locally (offline for a file or a bundle)",
        group(ArgGroup::new("source").required(true).args(["target", "bundle"]))
    )]
    Render(PromptsRenderArgs),
    #[command(
        about = "Export a signed prompt bundle and print its digests for pinning",
        group(ArgGroup::new("selector").required(true).args(["channel", "release"]))
    )]
    Export(PromptsExportArgs),
}

#[derive(Debug, Parser)]
pub struct PromptsListArgs {
    #[arg(long, help = "Substring over prompt id, name, description and tags")]
    pub query: Option<String>,
    #[arg(long = "tag", help = "Tag filter; repeat for several (all must match)")]
    pub tags: Vec<String>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200), help = "Page size (1 to 200)")]
    pub limit: Option<u32>,
    #[arg(long, help = "Cursor returned by a previous page")]
    pub cursor: Option<String>,
}

#[derive(Debug, Parser)]
pub struct PromptsGetArgs {
    #[arg(help = "Prompt reference: prm_x, prm_x:7, prm_x@alias or agenomic:// URI")]
    pub reference: String,
    #[arg(
        short = 'o',
        long = "output",
        help = "Write the prompt file here instead of stdout"
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct PromptsPushArgs {
    #[arg(help = "agenomic.prompt_file/v1 JSON file")]
    pub file: PathBuf,
    #[arg(long, help = "Change message (overrides the file's change_message)")]
    pub message: Option<String>,
    #[arg(long, help = "Validate and digest locally; send nothing")]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct PromptsPullArgs {
    #[arg(help = "Prompt id or reference (prm_x, prm_x:7, prm_x@alias)")]
    pub reference: String,
    #[arg(long, help = "Download every version of the prompt")]
    pub all: bool,
    #[arg(long, default_value = ".", help = "Destination directory")]
    pub dir: PathBuf,
}

#[derive(Debug, Parser)]
pub struct PromptsRenderArgs {
    #[arg(help = "Prompt file, or a version, alias or URI reference")]
    pub target: Option<String>,
    #[arg(
        long = "var",
        value_name = "NAME=VALUE",
        help = "String variable; repeat for several"
    )]
    pub vars: Vec<String>,
    #[arg(long = "vars", value_name = "FILE", help = "JSON object of variables")]
    pub vars_file: Option<PathBuf>,
    #[arg(long, value_name = "FILE", requires_all = ["slot", "workspace", "agent"], help = "Offline prompt bundle to render from")]
    pub bundle: Option<PathBuf>,
    #[arg(long, requires = "bundle", help = "Slot path of the bundle manifest")]
    pub slot: Option<String>,
    #[arg(
        long,
        requires = "bundle",
        help = "Expected workspace id of the bundle"
    )]
    pub workspace: Option<String>,
    #[arg(long, requires = "bundle", help = "Expected agent id of the bundle")]
    pub agent: Option<String>,
    #[arg(
        long,
        requires = "bundle",
        help = "Pinned prompt_bundle_digest (from `prompts export`)"
    )]
    pub expect_bundle_digest: Option<String>,
    #[arg(
        long,
        value_name = "PEM",
        requires = "bundle",
        help = "Trusted ed25519 public key that signed the bundle"
    )]
    pub trust_key: Option<PathBuf>,
    #[arg(long, help = "Also render on the server and compare the rendered hash")]
    pub server: bool,
}

#[derive(Debug, Parser)]
pub struct PromptsExportArgs {
    #[arg(long, help = "Agent id (uuid)")]
    pub agent: String,
    #[arg(long, help = "Channel to export (for example production)")]
    pub channel: Option<String>,
    #[arg(long, help = "Release id (uuid) to export")]
    pub release: Option<String>,
    #[arg(short = 'o', long = "output", help = "Bundle file to write")]
    pub output: PathBuf,
    #[arg(
        long,
        value_name = "PEM",
        help = "Verify the signature with this trusted ed25519 public key"
    )]
    pub trust_key: Option<PathBuf>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=365), help = "Bundle availability in days (1 to 365, server default 30)")]
    pub expires_in_days: Option<u32>,
}

#[derive(Debug, Parser)]
pub struct ChannelsCommand {
    #[command(subcommand)]
    pub command: ChannelsSub,
}

#[derive(Debug, Subcommand)]
pub enum ChannelsSub {
    #[command(about = "List the release channels of an agent")]
    List {
        #[arg(long, help = "Agent id (uuid)")]
        agent: String,
    },
    #[command(about = "Show the move history of one channel")]
    History {
        #[arg(long, help = "Agent id (uuid)")]
        agent: String,
        #[arg(help = "Channel name")]
        channel: String,
        #[arg(long, help = "Only events after this generation")]
        after: Option<i64>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200), help = "Page size (1 to 200)")]
        limit: Option<u32>,
    },
    #[command(
        about = "Preview a promotion and print where to complete it; never moves the channel"
    )]
    Promote {
        #[arg(long, help = "Agent id (uuid)")]
        agent: String,
        #[arg(help = "Channel name")]
        channel: String,
        #[arg(long, help = "Candidate release id (uuid)")]
        release: String,
        #[arg(
            long,
            env = "AGENOMIC_WEB_URL",
            help = "Web app address used to print an absolute move URL"
        )]
        web_url: Option<String>,
    },
    #[command(
        about = "Preview a rollback and print where to complete it; never moves the channel"
    )]
    Rollback {
        #[arg(long, help = "Agent id (uuid)")]
        agent: String,
        #[arg(help = "Channel name")]
        channel: String,
        #[arg(long, help = "Explicit rollback target release id (uuid)")]
        to_release: Option<String>,
        #[arg(
            long,
            env = "AGENOMIC_WEB_URL",
            help = "Web app address used to print an absolute move URL"
        )]
        web_url: Option<String>,
    },
}

#[derive(Debug, Parser)]
pub struct KnowledgeCommand {
    #[arg(
        long,
        global = true,
        help = "Print the raw JSON response (same as --format json)"
    )]
    pub json: bool,
    #[command(subcommand)]
    pub command: KnowledgeSub,
}

#[derive(Debug, Subcommand)]
pub enum KnowledgeSub {
    #[command(about = "List the knowledge bases of the workspace")]
    List(KnowledgeListArgs),
    #[command(about = "Show one knowledge base with its statistics and health")]
    Get {
        #[arg(help = "Knowledge base id (kb_...)")]
        kb_id: String,
    },
    #[command(about = "Create a knowledge base")]
    Create(KnowledgeCreateArgs),
    #[command(about = "Upload files and directories as documents of the working set")]
    Upload(KnowledgeUploadArgs),
    #[command(about = "Search a knowledge base", disable_version_flag = true)]
    Search(KnowledgeSearchArgs),
    #[command(
        about = "Run a structured query, for example 'get \"Authentication\" from \"security.md\"'",
        disable_version_flag = true
    )]
    Query(KnowledgeQueryArgs),
    #[command(
        about = "Answer a question from the evidence of a knowledge base",
        disable_version_flag = true
    )]
    Answer(KnowledgeAnswerArgs),
    #[command(about = "List the versions of a knowledge base")]
    Versions(KnowledgeVersionsArgs),
    #[command(about = "Create, diff and verify versions")]
    Version(KnowledgeVersionCommand),
    #[command(
        about = "Publish a version (If-Match on the publication generation)",
        disable_version_flag = true
    )]
    Publish(KnowledgePublishArgs),
    #[command(about = "Move the published pointer back (If-Match on the publication generation)")]
    Rollback(KnowledgeRollbackArgs),
    #[command(about = "Show a knowledge job, or wait until it ends")]
    Job(KnowledgeJobArgs),
    #[command(
        about = "Export a knowledge base to a JSON file",
        disable_version_flag = true
    )]
    Export(KnowledgeExportArgs),
    #[command(about = "Import a knowledge base from an exported JSON file")]
    Import(KnowledgeImportArgs),
}

#[derive(Debug, Parser)]
pub struct KnowledgeListArgs {
    #[arg(long, help = "Substring over kb id, name and description")]
    pub query: Option<String>,
    #[arg(long, help = "Status filter, for example active or archived")]
    pub status: Option<String>,
    #[arg(long, help = "Tag filter")]
    pub tag: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200), help = "Page size (1 to 200)")]
    pub limit: Option<u32>,
    #[arg(long, help = "Cursor returned by a previous page")]
    pub cursor: Option<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeCreateArgs {
    #[arg(help = "Knowledge base id, kb_ followed by lowercase letters, digits, _ and -")]
    pub kb_id: String,
    #[arg(long, help = "Display name")]
    pub name: String,
    #[arg(long, help = "Description")]
    pub description: Option<String>,
    #[arg(long = "tag", help = "Tag; repeat for several")]
    pub tags: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeUploadArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(
        required = true,
        help = "Files or directories; directories are walked recursively"
    )]
    pub paths: Vec<PathBuf>,
    #[arg(
        long = "glob",
        value_name = "PATTERN",
        help = "Only upload directory entries whose relative path matches; repeat for several"
    )]
    pub globs: Vec<String>,
    #[arg(long, help = "Document path prefix, for example guides")]
    pub prefix: Option<String>,
    #[arg(long, help = "Collection of the uploaded documents")]
    pub collection: Option<String>,
    #[arg(long = "tag", help = "Document tag; repeat for several")]
    pub tags: Vec<String>,
    #[arg(
        long,
        value_parser = ["public", "internal", "confidential", "restricted"],
        help = "Classification of the uploaded documents"
    )]
    pub classification: Option<String>,
    #[arg(long, help = "Change message of the new revisions")]
    pub message: Option<String>,
    #[arg(
        long,
        help = "Content type of every file (default application/octet-stream: the format follows the extension)"
    )]
    pub content_type: Option<String>,
    #[arg(long, help = "Wait for the ingestion jobs and fail when one fails")]
    pub wait: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 600,
        help = "Longest wait with --wait"
    )]
    pub timeout: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KnowledgeMode {
    Keyword,
    Semantic,
    Hybrid,
    Section,
    Exact,
}

impl KnowledgeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Semantic => "semantic",
            Self::Hybrid => "hybrid",
            Self::Section => "section",
            Self::Exact => "exact",
        }
    }
}

#[derive(Debug, Parser)]
pub struct KnowledgeSearchArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Search text")]
    pub query: String,
    #[arg(long, help = "Version: 3, v3, published or draft (default: published)")]
    pub version: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50), help = "Number of results (1 to 50)")]
    pub top_k: Option<u32>,
    #[arg(long, value_enum, help = "Retrieval mode (default hybrid)")]
    pub mode: Option<KnowledgeMode>,
    #[arg(long, help = "Also print the delimited evidence rendered for a model")]
    pub context: bool,
}

#[derive(Debug, Parser)]
pub struct KnowledgeQueryArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Query in text form, for example 'get \"Authentication\" from \"security.md\"'")]
    pub query: String,
    #[arg(long, help = "Version: 3, v3, published or draft (default: published)")]
    pub version: Option<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeAnswerArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Question")]
    pub question: String,
    #[arg(long, help = "Version: 3, v3, published or draft (default: published)")]
    pub version: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50), help = "Number of evidence items (1 to 50)")]
    pub top_k: Option<u32>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeVersionsArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200), help = "Page size (1 to 200)")]
    pub limit: Option<u32>,
    #[arg(long, help = "Cursor returned by a previous page")]
    pub cursor: Option<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeVersionCommand {
    #[command(subcommand)]
    pub command: KnowledgeVersionSub,
}

#[derive(Debug, Subcommand)]
pub enum KnowledgeVersionSub {
    #[command(about = "Snapshot the working set into a new immutable version")]
    Create(KnowledgeVersionCreateArgs),
    #[command(
        about = "Compare a version with its parent or another version",
        disable_version_flag = true
    )]
    Diff(KnowledgeVersionDiffArgs),
    #[command(
        about = "Recompute the digests of a version on the server",
        disable_version_flag = true
    )]
    Verify(KnowledgeVersionVerifyArgs),
}

#[derive(Debug, Parser)]
pub struct KnowledgeVersionCreateArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(long, help = "Change message of the version")]
    pub message: Option<String>,
    #[arg(
        long,
        help = "Draft revision the version must snapshot (default: the one read from the knowledge base)"
    )]
    pub expected_draft_revision: Option<u64>,
    #[arg(long, help = "Wait for the build job and fail when it fails")]
    pub wait: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 600,
        help = "Longest wait with --wait"
    )]
    pub timeout: u64,
}

#[derive(Debug, Parser)]
pub struct KnowledgeVersionDiffArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Version number: 3 or v3")]
    pub version: String,
    #[arg(long, help = "Version to compare with (default: the parent version)")]
    pub against: Option<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeVersionVerifyArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Version number: 3 or v3")]
    pub version: String,
}

#[derive(Debug, Parser)]
pub struct KnowledgePublishArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(help = "Version number to publish: 3 or v3")]
    pub version: String,
    #[arg(long, help = "Reason recorded with the publication")]
    pub reason: Option<String>,
}

#[derive(Debug, Parser)]
pub struct KnowledgeRollbackArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(
        long = "to",
        help = "Version to return to (default: the previously published one)"
    )]
    pub to: Option<String>,
    #[arg(long, help = "Reason recorded with the rollback")]
    pub reason: String,
}

#[derive(Debug, Parser)]
pub struct KnowledgeJobArgs {
    #[arg(help = "Job id (kjob_...)")]
    pub job_id: String,
    #[arg(
        long,
        help = "Poll until the job succeeds, fails or is cancelled; fail unless it succeeds"
    )]
    pub wait: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 600,
        help = "Longest wait with --wait"
    )]
    pub timeout: u64,
}

#[derive(Debug, Parser)]
pub struct KnowledgeExportArgs {
    #[arg(help = "Knowledge base id (kb_...)")]
    pub kb_id: String,
    #[arg(
        long,
        help = "Version: 3, v3 or published; draft or no version exports the working set"
    )]
    pub version: Option<String>,
    #[arg(short = 'o', long = "output", help = "JSON file to write")]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct KnowledgeImportArgs {
    #[arg(help = "JSON file written by `agenomic knowledge export`")]
    pub file: PathBuf,
    #[arg(
        long,
        help = "Id of the new knowledge base (default: the exported one)"
    )]
    pub kb_id: Option<String>,
    #[arg(
        long,
        help = "Name of the new knowledge base (default: the exported one)"
    )]
    pub name: Option<String>,
}
