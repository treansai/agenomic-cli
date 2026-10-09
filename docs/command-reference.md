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
| 16 | OsPolicyViolation | A Rego policy gate denied `run`/`policy eval`, or the Tool Boundary Gate blocked a tool call |
| 18 | ToolBoundaryReviewRequired | `agenomic gate check` held a tool call for human review |
| 19 | LedgerIntegrityFailed | `agenomic ledger verify` found tampering, a chain break, or a conflict |
| 21 | CloudConflict | The cloud answered 409 (for example `prompt_version_conflict` on `agenomic prompts push`, `knowledge_publication_conflict` on `agenomic knowledge publish`) |

On the `prompts`, `channels` and `knowledge` commands, a refusal from the
cloud maps by HTTP status: 409 gives 21, 401 and 403 give 5, 400, 404
and 422 give 1, and any other status gives 6. The message names the
error code of the cloud (`{"error": {"code", "message"}}`) when the body
has one; the `knowledge` commands also print the error `details`.

## Commands

### `agenomic init [PATH]`

Scaffold a bundle directory with `genome.yaml`, `agent.lock.yaml`,
`behavior.contract.yaml`, and `prompts/system.md`.

When `PATH` already contains a recognised project manifest
(`pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, or an
existing `agenomic.yaml`), `init` runs detection and fills the
generated files with values taken from the repository: project name,
authors, description, framework (`google-adk` / `langgraph` /
`langchain` / `openai-agents` / `crewai` / `llama-index` / `custom`),
model provider, entrypoint, tools, and memory backend.

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

### `agenomic compile [BUNDLE] [--target plain|langgraph|crewai|google-adk|docker|wasm]... [--all] [--output DIR] [--dry-run]`

Compile the bundle's `genome.yaml` into runnable runtime adapters under
`runtime/<target>.compiled/` (the `genome → runtime` step of the bundle format).
With no `--target` and no `--all`, every target is compiled. Targets:

- `plain`: FastAPI service calling the provider SDK directly.
- `langgraph`: a `StateGraph` with one node per skill.
- `crewai`: a Crew with one `Task` per skill.
- `google-adk`: a Google Agent Development Kit agent exposing `root_agent`,
  runnable with `adk run` / `adk web` and deployable via Google's
  [`agents-cli`](https://github.com/google/agents-cli). Gemini models bind
  natively; other providers route through ADK's `LiteLlm` wrapper.
- `docker`: the `plain` service packaged as an OCI image (pinned `Dockerfile`).
- `wasm`: a `componentize-py` WASI component exporting `agenomic:agent/invoke`
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
the top keywords per cluster (Mode 1 of Point 4, "failure clustering"). Input
is one JSON object per line with `{trace_id, agent_id, skill, signal,
input_snippet, output_snippet}`; pass `-` for stdin. Output is deterministic.

### `agenomic governance hypothesize <CLUSTERS.json>`

Turn each cluster into a textual remediation proposal (Mode 2, "hypothesis
generation"). The hypothesis agent **never mutates a bundle**; it produces JSON
a human reads. Action kinds: `extend_skill_examples`, `narrow_skill_scope`,
`add_policy_rule`, `escalation_overhaul`, `none`.

### `agenomic governance critique <PROPOSAL.json>`

Adversarially review one proposal (Mode 3, "adversarial reviewer"). Heuristics
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
`governance.critique_recorded`, and (for `audit`) a closing
`governance.audit_completed` summary. Each batch chains onto the stream's
existing head (parents = prior event's causal hash) and continues `stream_seq`,
so repeated runs build one tamper-evident trail. The store must already be
`agenomic atep init`-ialized for the same agent; verify the trail with
`agenomic atep verify <STORE> --public-key <KEY>.pub`. The result body gains an
`atep` object reporting `events_appended`, `stream_seq_start`, `signer_key_id`,
and the new `store_merkle_root`.

### `agenomic gate check <TOOL-CALL.json> [--policy DIR] [--rules FILE] [--approval FILE] [--executed]`

Run a proposed tool call through the **Tool Boundary Gate**: deterministic,
at-the-effect enforcement that never calls an LLM. Layers a non-negotiable rule
set (tool allowlist & scopes, self-modification, path traversal / sensitive
files, PII / exfiltration to unapproved external recipients, irreversible
effects) over the reused fail-closed Rego gate. Arguments are `untrusted` by
default; provenance from model / tool / MCP / skill content is held to stricter
rules. Exits `0` (allow), `16` (block), or `18` (human review required).

`--policy DIR` (default `.`) holds a `policies/` folder (Rego) and an optional
`gate.json` rule override (also selectable via `--rules FILE`). With
`--atep <STORE> --signing-key <KEY>` the passage is sealed as signed events:
`tool.call.proposed`, `policy.check.performed`, `tool.call.approved|blocked` on
the `policy` stream, and `human.review.requested` on the `governance` stream.
`--approval <FILE>` resumes a held call with a signed reviewer decision
(`role` / `justification` / `timestamp`), emitting
`human.review.approved|rejected|modified` and, with `--executed`,
`tool.call.executed`. See `docs/tool-boundary-gate.md`.

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

### Managed prompts

The `prompts` and `channels` commands are documented in
[prompts.md](prompts.md). Offline commands need no profile; the others
use the active cloud profile and send `x-api-key`.

#### `agenomic prompts list [--query Q] [--tag T]... [--limit N] [--cursor C]`

`GET /v1/prompts`. Table by default, the raw page with `--format json`.

#### `agenomic prompts get <REF> [-o FILE]`

Downloads one version as an `agenomic.prompt_file/v1` document. `REF`
is `prm_x` (latest version), `prm_x:7`, `prm_x@alias` (resolved once
through `POST /v1/prompts/resolve`) or an `agenomic://` URI of the
current workspace. The content digest of the version and of every
fragment is recomputed locally; a mismatch exits 1.

#### `agenomic prompts push <FILE> [--message M] [--dry-run]`

Validates the file against `schemas/prompt-file.schema.json`, checks
its `content_digest` when present, validates the template locally and
computes the digest. Without `--dry-run` it publishes with
`POST /v1/prompts/{id}/versions` (creating the prompt first when the
cloud answers `prompt_not_found`) and requires the server digest to
equal the local one. A stale `parent_version` exits 21.

#### `agenomic prompts pull <PROMPT_ID|REF> [--all] [--dir DIR]`

Writes `DIR/<prompt_id>/<n>.prompt.json`. `--all` takes a bare prompt
id and downloads every version.

#### `agenomic prompts render <FILE|REF> [--var NAME=VALUE]... [--vars FILE] [--server]`

#### `agenomic prompts render --bundle FILE --slot SLOT --workspace UUID --agent UUID (--expect-bundle-digest D | --trust-key PEM)`

Renders with the `agenomic-fstring/v1` renderer, version `"1"`. A file
or a bundle renders offline; a reference downloads the version first.
`--server` also calls `POST /v1/prompts/render` and exits 1 when the
`rendered_hash` differs. Render errors exit 1 before anything else
happens.

#### `agenomic prompts export --agent UUID (--channel NAME | --release UUID) -o FILE [--trust-key PEM] [--expires-in-days N]`

`GET /v1/agents/{id}/prompt-bundle`. Verifies every digest, the closure
and the scope (and the signature with `--trust-key`, exit 9 when it
fails) before writing the file, then prints `prompt_bundle_digest` to
pin offline loads.

#### `agenomic channels list --agent UUID`

`GET /v1/agents/{id}/channels`: name, release, release id, generation
and protection of every channel of the agent.

#### `agenomic channels history --agent UUID <CHANNEL> [--after N] [--limit N]`

`GET /v1/agents/{id}/channels/{name}/history`: generation, action, from
and to releases, actor and reason of each move, oldest first. The human
output prints the `--after` value of the next page.

#### `agenomic channels promote --agent UUID <CHANNEL> --release UUID [--web-url URL]`

#### `agenomic channels rollback --agent UUID <CHANNEL> [--to-release UUID] [--web-url URL]`

Hand-off commands. They call only the read-only move preview
(`GET /v1/agents/{id}/channels/{name}/move-preview`), print the
current release and the release the move would point the channel to
(`candidate` for a promotion; `target` for a rollback, which is the
`--to-release` value or the default target, with a `default` line
when they differ), their genome and manifest digests, the gates, the
approvals, the reasons why this credential cannot move the channel
(always `session_required` for an API key) and the web address where
an authorized person completes the move with a session, then exit 0.
They never move a channel: channel moves are session only and the CLI
authenticates with an API key. `--format json` prints
`{action, channel, moved: false, move_url, preview}` with the cloud's
preview unchanged. An unknown release or channel exits 1.

### Knowledge bases

The `knowledge` commands are documented in [knowledge.md](knowledge.md).
They all use the active cloud profile and send `x-api-key`. `--json`
(anywhere after `knowledge`) is the same as `--format json` and prints
the response unchanged. `VERSION` is `3`, `v3`, `published` or `draft`;
`N` is a version number (`3` or `v3`).

#### `agenomic knowledge list [--query Q] [--status S] [--tag T] [--limit N] [--cursor C]`

`GET /v1/knowledge-bases`: id, status, health, published and latest
versions, document count and name.

#### `agenomic knowledge get <KB_ID>`

`GET /v1/knowledge-bases/{kb_id}`: reference, status, health, published
version and manifest digest, draft revision, publication generation,
document and job counts.

#### `agenomic knowledge create <KB_ID> --name NAME [--description D] [--tag T]...`

`POST /v1/knowledge-bases`.

#### `agenomic knowledge upload <KB_ID> <PATH>... [--glob P]... [--prefix P] [--collection C] [--tag T]... [--classification C] [--message M] [--content-type T] [--wait] [--timeout S]`

Uploads every file, walking directories recursively (hidden entries,
symbolic links and credential files skipped), one
`POST .../documents/upload` per file with the raw bytes streamed and the
percent-encoded `x-agenomic-*` headers. An upload of identical bytes is
reported as `unchanged`. `--wait` polls the ingestion jobs and exits 1
when one fails or is cancelled.

#### `agenomic knowledge search <KB_ID> <QUERY> [--version VERSION] [--top-k K] [--mode keyword|semantic|hybrid|section|exact] [--context]`

#### `agenomic knowledge query <KB_ID> <TEXT> [--version VERSION]`

#### `agenomic knowledge answer <KB_ID> <QUESTION> [--version VERSION] [--top-k K]`

`POST .../search`, `.../query` (text form, for example
`get "Authentication" from "security.md"`) and `.../answer`. Retrieved
text is printed with control and invisible formatting characters
replaced by spaces.

#### `agenomic knowledge versions <KB_ID> [--limit N] [--cursor C]`

#### `agenomic knowledge version create <KB_ID> [--message M] [--expected-draft-revision R] [--wait] [--timeout S]`

#### `agenomic knowledge version diff <KB_ID> <N> [--against N]`

#### `agenomic knowledge version verify <KB_ID> <N>`

`version create` sends the draft revision it read (or
`--expected-draft-revision`) as `expected_draft_revision`. `version
verify` exits 1 when a digest or the signature does not verify.

#### `agenomic knowledge publish <KB_ID> <N> [--reason R]`

#### `agenomic knowledge rollback <KB_ID> [--to N] --reason R`

Read the knowledge base, then send its `publication_generation` in
`If-Match`. A 409 exits 21 with the error code and a hint; nothing moved.

#### `agenomic knowledge job <JOB_ID> [--wait] [--timeout S]`

`GET /v1/knowledge-jobs/{job_id}`. `--wait` polls until `succeeded`,
`failed` or `cancelled` and exits 1 unless the job succeeded, 6 on
timeout.

#### `agenomic knowledge export <KB_ID> [--version VERSION] -o FILE`

#### `agenomic knowledge import <FILE> [--kb-id KB_ID] [--name NAME]`

`export` writes the `agenomic.knowledge_export/v1` document of
`GET .../export[?version=N|published]` byte for byte; `--version draft`
or no `--version` exports the working set. `import` sends the file's
bytes unchanged as the `application/json` body of
`POST /v1/knowledge-bases/import[?kb_id=...&name=...]` and prints the
new knowledge base with the counts of imported documents and enqueued
jobs. A file above 17 MiB (the server's limit) or one that is not a JSON
object is refused before sending, with exit 1.

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

### `agenomic ledger init [--store DIR] [--keys DIR]`

Initialize the append-only cryptographic event ledger (default data root
`.agenomic/ledger`, keys `~/.config/agenomic/keys`) and generate an ed25519
signing key if none exists.

### `agenomic ledger append --event FILE`

Append one event (JSON: `agent_id`, `run_id`, `event_type`, `payload`, and
optional ids). The payload is committed by hash; raw content never enters
the ledger or the WAL. Same `event_id` + same payload is idempotent; a
divergent payload is a conflict (exit 19) recorded in the dead-letter store.

### `agenomic ledger status` / `agenomic ledger tail [--run ID] [--limit N]` / `agenomic ledger inspect --entry ID`

Overview (entries, runs, chain head, blocks, WAL health, dead letters),
trailing entries, and a single full entry by ledger or event id.

### `agenomic ledger seal`

Seal all unsealed entries into a signed Merkle block (blocks also seal
automatically by count/age and on shutdown).

### `agenomic ledger verify [--run ID | --block ID]`

Run the full offline verification engine (hashes, signatures, chains,
blocks, gaps, duplicates, key status, WAL health) with a structured report
and recommendations. Exit 19 on any integrity failure.

### `agenomic ledger export [--run ID] --output FILE`

Write the entries as a JSONL chain that re-verifies anywhere, offline.

### `agenomic ledger queue status|flush|retry` / `agenomic ledger queue dead-letter list|replay [--id ID]`

Durable-queue state and recovery: draining replays pending WAL records
idempotently; dead-letter records are re-submitted and removed only on
success.

### `agenomic ledger keys generate|list|rotate|revoke <KEY_ID>|export-public [--key ID] [--output FILE]`

Signing-key lifecycle: rotation keeps historical entries verifiable forever;
revoked keys flag (never silently fail) verification; export prints the
public half only.

### Ledger integrations

- `agenomic track start --ledger [--ledger-store DIR] [--ledger-keys DIR]`:
  bind the session: lifecycle + every ingested event are hash-committed to
  the ledger. `agenomic track report --include-ledger-proof` attaches the
  proof block (root hash, run chain head, block ids, key ids,
  verification/gap/queue-loss status); the report hash covers it.
- `agenomic governance <cluster|hypothesize|critique|audit> … --ledger`:
  dual-emit engine results to the ledger alongside the signed ATEP
  `governance` stream (never instead of it).
- `agenomic replay … --from-ledger RUN`: verify the run's ledger chain
  BEFORE replaying (exit 19 on failure) and attach the ledger proof to the
  replay report. Provenance/integrity only: replay stays statistical.

### `agenomic evidence export --include-ledger [--run ID] --output DIR [--replay-report F] [--policy-results F] [--risk-summary F]`

Assemble the offline-verifiable proof bundle (signed manifest, chain,
blocks, Merkle data, signatures, embedded public keys, verification
report). Locally-signed bundles are technical integrity evidence with a
non-probative status and the platform legal notice.

### `agenomic evidence verify <DIR>`

Re-verify a proof bundle on a clean machine (no keystore, no network);
public keys ship inside. Exit 19 on any failure.
