# Changelog

All notable changes to `agenomic-cli` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
