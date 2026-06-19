# Command reference

Every `agenomic` command, their flags, and exit codes.

## Global flags

| Flag | Env | Description |
| --- | --- | --- |
| `--profile <NAME>` | `AGENOMIC_PROFILE` | Override the active profile |
| `--no-color` | `AGENOMIC_NO_COLOR` | Disable ANSI color in human output |
| `--format <FORMAT>` | `AGENOMIC_FORMAT` | `human` (default), `json`, `json-pretty`, `yaml` |

## Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | All good |
| 1 | ValidationFailed | A schema or required-file check failed |
| 2 | InvalidUsage | clap rejected the command-line args |
| 3 | InternalError | Unexpected I/O / serialization failure |
| 4 | SecurityViolation | Path traversal, symlink, or credential file detected |
| 5 | CloudAuthFailed | 401 from the cloud, or no credentials configured |
| 6 | NetworkError | Cloud HTTP failure after retries |
| 7 | ContractFailed | `agenomic replay` saw violations at or above `--fail-on` |
| 8 | DiffRiskExceeded | `agenomic diff` found a change at or above `--fail-on` |
| 9 | AttestationVerificationFailed | `agenomic verify` failed a check |
| 10 | AtepIntegrityFailed | ATEP signature, merkle root, or CRC failed |
| 14 | OsContractInvalid | `execution:` block missing or malformed |
| 16 | OsPolicyViolation | A Rego policy gate denied `run`/`policy eval`, or env/permission policy failed |

## Commands

### `agenomic init [PATH]`

Scaffold a bundle directory with `genome.yaml`, `agent.lock.yaml`,
`behavior.contract.yaml`, and `prompts/system.md`.

When `PATH` already contains a recognised project manifest
(`pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, or an
existing `agenomic.yaml`), `init` runs detection and fills the
generated files with values taken from the repository — project name,
authors, description, framework (`langgraph` / `langchain` /
`openai-agents` / `crewai` / `llama-index` / `custom`), model
provider, entrypoint, tools, and memory backend.

Flags: `--name`, `--agent-id`, `--from <SOURCE>...`, `--no-detect`,
`--force`, `--dry-run`. Full detection rules, precedence chain, and
the generated `provenance:` block: see
[`init-and-update.md`](init-and-update.md).

### `agenomic update [PATH]`

Re-run detection on the project and merge new findings into the
existing bundle. Hand-edits are preserved. When invoked inside a git
repo, `update` stages the four bundle files and creates a commit by
default (`chore(agenomic): update bundle (<step> <hash>)`), so every
change to the agent's genome is paired with a reviewable commit.

Flags: `--message`, `--commit / --no-commit`, `--sign`,
`--allow-dirty`, `--prune`, `--step <NAME>`, `--dry-run`,
`--from <SOURCE>...`. Merge semantics, commit format, CI integration,
and exit codes: see [`init-and-update.md`](init-and-update.md).

> Note: `--sign` is not yet supported by the offline (`gix`) commit
> path; use `--no-commit` then `git commit -S` to sign manually.

### `agenomic validate <PATH> [--level basic|strict|ci]`

Validate a bundle directory or `.tar.zst` archive.

### `agenomic build <DIR> --output <FILE> [--compression-level N] [--strict] [--allow-symlinks]`

Build a `.bundle.tar.zst`.

### `agenomic compile [BUNDLE] [--target plain|langgraph|crewai|docker|wasm]... [--all] [--output DIR] [--dry-run]`

Compile the bundle's `genome.yaml` into runnable runtime adapters under
`runtime/<target>.compiled/` (the `genome → runtime` step of the bundle format).
With no `--target` and no `--all`, every target is compiled. Targets:

- `plain` — FastAPI service calling the provider SDK directly.
- `langgraph` — a `StateGraph` with one node per skill.
- `crewai` — a Crew with one `Task` per skill.
- `docker` — the `plain` service packaged as an OCI image (pinned `Dockerfile`).
- `wasm` — a `componentize-py` WASI component exporting `agenomic:agent/invoke`
  (prompts inlined; outbound model calls need a WASI-HTTP-capable host).

Each compiled tree is self-contained: the system prompt and skill prompts are
embedded under `prompts/`, and a `manifest.json` pins the BLAKE3 of every
generated file plus the source genome hash, so a downstream `attest` can sign
exactly what was emitted. Output is deterministic for a given genome. MCP tool
bindings are emitted as typed stubs (server + version recorded); wiring them to
live MCP servers is the operator's integration step.

`--dry-run` prints the file list without writing. `--output DIR` writes under
`DIR/<target>.compiled/` instead of `<bundle>/runtime/`.

### `agenomic governance cluster <TRACES.jsonl>`

Group a stream of flagged production traces by `(signal, skill)` and surface
the top keywords per cluster (Mode 1 of Point 4 — "failure clustering"). Input
is one JSON object per line with `{trace_id, agent_id, skill, signal,
input_snippet, output_snippet}`; pass `-` for stdin. Output is deterministic.

### `agenomic governance hypothesize <CLUSTERS.json>`

Turn each cluster into a textual remediation proposal (Mode 2 — "hypothesis
generation"). The hypothesis agent **never mutates a bundle**; it produces JSON
a human reads. Action kinds: `extend_skill_examples`, `narrow_skill_scope`,
`add_policy_rule`, `escalation_overhaul`, `none`.

### `agenomic governance critique <PROPOSAL.json>`

Adversarially review one proposal (Mode 3 — "adversarial reviewer"). Heuristics
include "evidence base too small (<3 traces)", "large prompt expansion risks
over-triggering", "scope narrowing without explicit exclusions masks the
failure", and "policy rule lacks an anchoring keyword". Verdict is `pass` /
`warn` / `block`; **exits `16` (OsPolicyViolation) on `block`**.

### `agenomic governance audit <TRACES.jsonl> [--fail-on-block]`

Run the full Diagnostic → Hypothesis → Adversarial chain end-to-end and emit
clusters + proposals + critiques in one document. With `--fail-on-block`, exits
16 when any proposal lands at `Verdict::Block`. Useful as a single CI step or
as the input to a downstream human-approval gate (Mode 4).

#### Signed audit trail: `--atep <STORE> --signing-key <KEY>`

All four governance subcommands accept `--atep <STORE>` and `--signing-key
<KEY>` (used together). When set, the engine's results are sealed onto the
store's ATEP `governance` stream as a hash-linked batch of signed events:
`governance.cluster_detected`, `governance.proposal_generated`,
`governance.critique_recorded`, and — for `audit` — a closing
`governance.audit_completed` summary. Each batch chains onto the stream's
existing head (parents = prior event's causal hash) and continues `stream_seq`,
so repeated runs build one tamper-evident trail. The store must already be
`agenomic atep init`-ialized for the same agent; verify the trail with
`agenomic atep verify <STORE> --public-key <KEY>.pub`. The result body gains an
`atep` object reporting `events_appended`, `stream_seq_start`, `signer_key_id`,
and the new `store_merkle_root`.

### `agenomic policy eval [BUNDLE] [--input FILE]`

Evaluate the bundle's `policies/*.rego` (OPA/Rego) against a launch context and
print the decision. Policies declare `package agenomic` with a fail-closed
`allow` rule (defaults to `false`) and an optional `deny[reason]` set; the final
verdict is `allow == true AND deny is empty`. Exits `16` (OsPolicyViolation)
when the launch is denied.

With `--input FILE` the JSON document is used verbatim; otherwise the context is
derived from the genome's `agent` and `execution:` blocks (`agent_id`,
`criticality`, `runtime_kind`, `working_directory`, `env_required`,
`network_allow`, `network_allow_count`, `fs_read`, `fs_write`). The same gate
runs automatically inside `agenomic run` before the agent is spawned whenever a
bundle ships `.rego` policies.

### `agenomic inspect <PATH>`

Print a high-level bundle summary.

### `agenomic hash <PATH> [--prefix]`

Print the canonical `logical_bundle_hash`.

### `agenomic diff <BASELINE> <CANDIDATE> [--fail-on critical] [--ignore-prompts-whitespace]`

Diff two bundles. Exits 8 if any change ≥ `--fail-on`.

### `agenomic replay <BUNDLE> [TRACES] [--from-atep DIR] [--contract FILE] [--runs-per-trace N] [--fail-on SEV] [--output FILE]`

Run a deterministic local replay.

### `agenomic attest <BUNDLE> [--replay-report FILE] [--atep DIR] [--sign-with KEY] [--generate-key PATH] --output FILE`

Create a release attestation. With `--generate-key PATH` only generates a
fresh ed25519 key.

### `agenomic verify <ATTESTATION> [--atep DIR]`

Verify an attestation. With `--atep DIR`, additionally re-checks that the
ATEP store's merkle root matches the embedded `atep_root_hash`.

### `agenomic atep init <PATH> --agent-id <ID> --signing-key <FILE>`

Initialize a new ATEP store.

### `agenomic atep append <PATH> --stream <S> --type <T> [--payload-file FILE] --signing-key <FILE>`

Append a single signed event to a stream.

### `agenomic atep verify <PATH> --public-key <FILE>`

Verify all segment merkle roots and event signatures.

### `agenomic atep inspect <PATH>`

Print the manifest.

### `agenomic atep replay-state <PATH> [--at RFC3339] [--output FILE]`

Reconstruct an `AgentState` projection.

### `agenomic cloud login [--endpoint URL] --api-key KEY`

Persist a Cloud profile (mode 0600 credentials file). `--endpoint`
defaults to the API gateway `https://api.agenomic.io`, so it only needs
to be set for self-hosted or staging deployments. Point it at the API
host, not the dashboard (`app.agenomic.io`), which 404s on `/v1/*`.

### `agenomic cloud whoami`

Call `/v1/whoami` against the configured profile.

### `agenomic cloud logout`

Delete credentials for the active profile.

### `agenomic bucket use --name NAME`

Set the active cloud bucket for the selected profile. If the bucket does
not exist yet, the CLI creates it first.

### `agenomic cloud push-agent <BUNDLE> --name NAME [--description TEXT] [--version V] [--agent-id UUID]`

Push a bundle into Agenomic Cloud. When `--agent-id` is omitted the CLI
creates a new agent first, then uploads the bundle.

Bucket selection precedence for push:

1. The profile's active bucket from `agenomic bucket use`
2. The implicit `default` bucket

If the selected bucket does not exist yet, `push-agent` creates it and
moves the target agent into it before uploading the bundle.

### `agenomic cloud push-release --agent-id UUID --bundle-id UUID --version V [--notes TEXT]`

Create a release pinned to an existing bundle.

### `agenomic cloud push-replay --agent-id UUID [--release-id UUID] [--trace-id UUID ...] [--mode deterministic|statistical]`

Enqueue a cloud replay job.

### `agenomic cloud push-attestation --release-id UUID --replay-job-id UUID`

Create a cloud attestation from an existing release + replay job.

### `agenomic bundle extract <ARCHIVE> <DIR>`

Extract a `.bundle.tar.zst`.

### `agenomic bundle manifest <PATH>`

Print the canonical Merkle manifest as JSON.

### `agenomic bundle compile-runtime <DIR> [--adapter plain|langgraph|crewai ...] [--output-dir DIR]`

Compile `genome.yaml` into deterministic `runtime/*.compiled` adapter
artifacts. With no `--adapter`, the compiler emits `plain` plus any
framework-specific adapter implied by the genome (`langgraph` /
`crewai`). The generated files are metadata + execution plans, not
framework source code.

### `agenomic trace validate <PATH>` and `agenomic trace summarize <PATH>`

Validate / summarize a JSONL trace file.

### `agenomic doctor`

Run system diagnostics; emits JSON.

### `agenomic completions <SHELL>`

Print a shell completion script (bash, zsh, fish, powershell, elvish).
