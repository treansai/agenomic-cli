# Changelog

All notable changes to `agenomic-cli` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0-alpha.0] - 2026-07-13

### Added

- **Review · Monitor · Protect (RMP).** A new `agenomic-rmp` crate and the
  `agenomic rmp` / `review` / `monitor` / `protect` command families implement
  the continuous safety loop for production agents. **Review** evaluates an
  agent with structured test scenarios, a typed risk matrix (likelihood ×
  impact × impact drivers, agent-type assessment), deterministic replay
  against the behavior contract, regression detection over evaluation
  history, and a release recommendation. **Monitor** wraps the online
  tracking engine and appends every live event to the cryptographic ledger
  through the durable WAL pipeline (`durable_low_latency` default; crash
  recovery, idempotent ingestion, dead-letter queue). **Protect** derives
  session-level anomalies (repeated failures, missing human approval,
  dangerous autonomy), generates deduplicated/routed/throttled alerts,
  deterministic recommendations (high-impact kinds always require human
  approval), ordered action plans, and audit-ready evidence bundles. The
  loop closes through scenario enrichment proposals: production findings
  become new Review scenarios via an explicit
  `draft → pending_review → approved → applied` workflow. All lifecycle
  events (`rmp.*`, `review.*`, `monitor.*`, `protect.*`) are recorded into
  the signed ledger when enabled, with redaction applied before anything is
  hash-committed. New schemas (`schemas/rmp-*.schema.json`), docs
  (`docs/review-monitor-protect.md`, `docs/rmp/`), and examples
  (`examples/rmp/`). No LLM is called anywhere in the loop; an optional
  provider interface exists for advisory suggestions only.

- **Google ADK / `agents-cli` support.** A new `google-adk` compile target lowers
  a genome into a Google [Agent Development Kit](https://github.com/google/adk-python)
  agent exposing the conventional `root_agent` (with `__init__.py` for discovery),
  runnable via `adk run` / `adk web` and deployable through Google's
  [`agents-cli`](https://github.com/google/agents-cli). The system prompt and each
  skill prompt fold into the agent instruction; declared MCP tools are emitted as
  typed stub callables. Gemini models bind natively; other providers route through
  ADK's `LiteLlm` wrapper. Detection now recognises the `google-adk` /
  `google-agents-cli` dependencies (framework `google-adk`, provider `google`), and
  `bundle compile-runtime` gains a matching `google-adk` launch-plan adapter.
- **Hugging Face provider.** Hugging Face is now a first-class model provider
  (aliases `huggingface`, `hf`, `hugging_face`). Genomes can declare a Hugging
  Face model with optional `task`, `revision`, `endpoint_url`, `organization`,
  and `parameters`; the lockfile pins `revision`, `resolved_commit`, `task`, a
  redacted `endpoint_ref`, and `endpoint_hash` / `metadata_hash` /
  `parameter_hash` for reproducibility. New `agm providers list` and
  `agm provider test <provider>` commands; `agm enrich` and `agm validate`
  understand the provider, and `agm diff` reports `model_provider_changed`,
  `model_revision_changed` (replay required), `model_task_changed`,
  `model_endpoint_changed`, and `model_parameters_changed`. Tokens
  (`HUGGINGFACE_API_TOKEN` / `HF_TOKEN`) are read only from the environment and
  never appear in logs, traces, lockfiles, reports, or errors. New example at
  `examples/huggingface-agent/` and docs at `docs/providers/huggingface.md`.

## [0.2.0-rc.0] - 2026-06-24

### Added

- **Signed `governance` ATEP stream.** The `governance` stream — defined since
  the ATEP MVP but never written — now carries a tamper-evident audit trail.
  All four `agenomic governance` subcommands accept `--atep <store>
  --signing-key <key>`; each engine result is sealed as a `governance.*` event
  (`cluster_detected` / `proposal_generated` / `critique_recorded` /
  `audit_completed`), chained onto the stream head (parents = prior causal
  hash) with continued `stream_seq`, and verifiable via `agenomic atep verify`.
  Pure descriptor builders live in `agenomic_governance::events`; the CLI does
  the sealing. Also fixes a latent `AtepStore::append_batch` bug (write-only
  segment handle failed the read-back CRC) and adds `AtepStore::stream_head`.
- **Governance agents (Point 4 / BACKEND_GAPS Gap 5).** New `agenomic-governance`
  crate plus `agenomic governance {cluster,hypothesize,critique,audit}`. Three
  pure, deterministic engines over flagged production traces:
  - `DiagnosticAgent` — groups traces by `(signal, skill)`, mines keywords
    (Mode 1: failure clustering).
  - `HypothesisAgent` — emits typed `Proposal`s (`extend_skill_examples`,
    `narrow_skill_scope`, `add_policy_rule`, `escalation_overhaul`, `none`).
    **Never mutates a bundle** (Mode 2: hypothesis generation).
  - `AdversarialReviewer` — fail-closed rule battery, verdict `pass` / `warn` /
    `block` (Mode 3: adversarial review). `block` exits 16.
  `audit` chains the three end-to-end. Modes 4 (human-approval gate) and 5
  (shadow deployment) layer above this — these engines produce the artifacts
  that gate consumes.
- **`entrypoint.kind` accepts `docker` and `wasm`.** `agenomic run` now
  dispatches via `agenomic_os::launch_for_kind` to a per-kind launcher: the
  existing `CommandLauncher`, a new `DockerLauncher` (`docker run --rm -i
  --network=none|bridge -e <NAME> <image>`), and a new `WasmLauncher`
  (`wasmtime run [--dir …] [-S http] <module>`). All three go through the
  same fail-closed env filter, working-directory containment, and trace
  pipeline. Declared env vars are forwarded *by name only* — values come
  from the filtered child env so secrets stay out of `argv`. Schema and
  `ExecutionContract` updated; `entrypoint.image` (docker) and
  `entrypoint.module` (wasm) are validated at parse time.

### Internal

- **`agenomic compile` — genome → runtime adapters.** New `agenomic-compile`
  crate and command that lower a bundle's `genome.yaml` into runnable,
  self-contained source under `runtime/<target>.compiled/`. Targets: `plain`
  (FastAPI + provider SDK), `langgraph`, `crewai`, `docker` (the `plain` service
  as a pinned OCI image), and `wasm` (a `componentize-py` WASI component with
  prompts inlined). Output is deterministic;
  each tree embeds its prompts and a `manifest.json` pinning per-file BLAKE3 and
  the source genome hash. Flags: `--target` (repeatable), `--all`, `--output`,
  `--dry-run`. See `docs/bundle-format.md` and `docs/command-reference.md`.
- **OPA/Rego policy enforcement.** New `agenomic-policy` crate (wrapping the
  pure-Rust `regorus` engine) evaluates `policies/*.rego` against a launch
  context. `agenomic policy eval` reports the decision; `agenomic run` now runs
  the same gate **fail-closed before spawning** the agent whenever a bundle ships
  `.rego` policies. Policies use `package agenomic` with a default-false `allow`
  rule and an optional `deny[reason]` set; denial exits 16. Adds an example
  `policies/launch.rego` to the claims-agent bundle.

- **Repo-aware `agm init`.** When run in a project with a recognised manifest
  (`pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, `agenomic.yaml`),
  `init` now detects agent id (git remote), name/description/authors,
  framework, model provider + default model id, entrypoint, tools, and memory
  backend, and writes them into the generated bundle. New flags: `--from`,
  `--no-detect`, `--force`, `--dry-run`. See `docs/init-and-update.md`.
- **`agm update`.** Re-detects, merges into the existing bundle while preserving
  hand-edits (via a `.agenomic/provenance.yaml` sidecar), re-emits the canonical
  files, and auto-commits via `gix` (offline, pure-Rust). Flags `--message`,
  `--commit`/`--no-commit`, `--sign`, `--allow-dirty`, `--prune`, `--step`,
  `--dry-run`, `--from`. Refuses (exit 2) on protected branches / unrelated dirty
  trees; exits 1 when there are no changes.
- New `agenomic-detect` crate (detection, inference, merge, emission, provenance,
  git) and `[init]`/`[update]` tables in `agenomic.toml`.

### Changed

- **`--version` now reports the git tag (git-based versioning).** `agenomic
  --version` / `agm --version` resolve the version at build time: the release
  workflow injects the pushed tag (e.g. `v0.2.0-rc.0`) via `AGENOMIC_VERSION`, so
  every published target — including the cross-compiled ones built in a git-less
  container — reports the tag. Local builds derive it from `git describe --tags
  --match=v*` (nearest version tag plus commit/dirty info), falling back to the
  crate version when built outside a git checkout. Tagging `vX` therefore yields
  a binary whose `--version` is `vX`.
- **Cloud endpoint defaults to `https://api.agenomic.io`.** `agenomic cloud
  login` no longer requires `--endpoint`, and the cloud push commands
  (`push-agent`, `push-release`, `push-replay`, `push-attestation`), `bucket
  use`, and `whoami` fall back to the hosted cloud when no endpoint is
  configured — set `--endpoint` / `AGENOMIC_ENDPOINT` only to target a
  self-hosted or staging deployment. The default is the **API gateway**
  (`api.agenomic.io`), not the dashboard (`app.agenomic.io`): the dashboard
  does not serve the `/v1/*` routes the CLI calls and 404s on them. The "no
  endpoint configured" error is gone; a missing API key still fails with exit 5.
- `agm init` in a populated directory that already has a `genome.yaml` now
  refuses with exit 2 and points at `agm update` (use `--force` to overwrite).
  Empty/no-manifest directories are unchanged (byte-identical legacy scaffold).

### Fixed

- **Default cloud endpoint no longer points at the dashboard.** It was
  `https://app.agenomic.io` (the web UI), so a fresh `agm cloud login --api-key
  …` followed by `whoami`/any push hit the dashboard and 404'd on `/v1/*`. The
  default is now the API gateway `https://api.agenomic.io`.
- **`agm cloud push-agent --agent-id <id>` gives an actionable error when the
  agent doesn't exist.** `--agent-id` reuses an existing agent; if it was never
  pushed, the move-to-bucket step returned an opaque `move_agent_to_bucket: HTTP
  404`. The CLI now explains the id wasn't found and that omitting `--agent-id`
  creates the agent from `--name`. Other errors (auth, 5xx) are unchanged.
- **`agm build` no longer packs build artifacts and scratch files into the
  bundle.** The directory walk now excludes `*.bundle.tar.zst` (so re-building in
  place can't fold a prior archive into itself), `.agenomic-*` scratch/cache
  files (e.g. `.agenomic-detect.json`, `.agenomic-validate.json`), and `.claude/`
  tooling config.
- `agm cloud whoami` now surfaces the "wrong endpoint?" hint on HTTP status
  errors too (previously only on parse errors), and its HTML detector
  recognises Next.js error pages by their `_next/static` marker. Pointing
  `--endpoint` at the web origin now yields an actionable message instead of
  a raw 404 body.
- `agenomic completions` / full `--help` no longer panic under clap 4.6
  (the `cloud push-agent`/`push-release` `--version` args clashed with the
  auto version flag).
