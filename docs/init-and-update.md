# `agm init` and `agm update` — repo-aware scaffolding and incremental commits

Status: **Specification, production-ready.** This document is the
contract for the `agm init` auto-detection pipeline and the new
`agm update` command. Any change to detection rules, default field
values, or commit semantics MUST update this document in the same PR.

Audience: contributors to `crates/agenomic-cli`, integrators writing
their own scaffolders, and reviewers diffing a generated `genome.yaml`
against the source repository.

---

## 1. Problem statement

Today `agm init [PATH]` writes a hard-coded `genome.yaml` with
`agent://example/new`, `name: "Example Agent"`, `model_provider:
openai`, empty `tools`, empty `skills`, empty `knowledge`. When the
target directory is already a real project (e.g.
`agenomic-codedrift`), every field is wrong and has to be re-typed by
hand. Reproduced symptom:

```
$ cd agenomic-codedrift
$ agm init .
initialized bundle at .
$ head genome.yaml
spec_version: '0.1'
agent:
  id: 'agent://example/new'      # <-- not detected
  name: 'Example Agent'          # <-- pyproject.toml has the real name
  domain: 'general'
runtime:
  model_provider: 'openai'       # <-- this repo uses anthropic + langgraph
  model_id: 'gpt-4o'
tools: []                        # <-- ruff, radon, bandit are declared
```

The fix has two parts:

1. **`agm init` becomes repo-aware.** When run inside a directory
   that already contains project manifests (`pyproject.toml`,
   `package.json`, `Cargo.toml`, `go.mod`, an existing
   `agenomic.yaml`, etc.), `init` inspects the manifests and fills in
   the generated files with detected values instead of placeholders.
2. **`agm update` is added.** Re-runs detection, merges new findings
   into the existing bundle (without clobbering hand edits), and
   creates a git commit recording the change. This turns the bundle
   into a living artifact that follows the codebase commit-by-commit.

---

## 2. `agm init` — repo-aware behaviour

### 2.1 Synopsis

```
agm init [PATH]
        [--name <NAME>]
        [--agent-id <ID>]
        [--from <SOURCE>...]
        [--no-detect]
        [--force]
        [--dry-run]
        [--format human|json|json-pretty|yaml]
```

`PATH` defaults to `.`. Behaviour by directory state:

| Directory state | Action |
| --- | --- |
| Empty / no recognised manifests | Scaffold with placeholders, exactly the legacy behaviour. |
| Recognised manifests, no `genome.yaml` yet | Run detection; write all four bundle files with detected values. |
| Recognised manifests, `genome.yaml` already present | Refuse with exit code `2`. The user should run `agm update`. `--force` overrides and overwrites. |

### 2.2 Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--name <NAME>` | detected | Override the detected agent name. |
| `--agent-id <ID>` | `agent://<org>/<name>` from git remote + project name | Override the agent id. |
| `--from <SOURCE>` | all enabled | Restrict detection sources. Repeatable. Values: `pyproject`, `package-json`, `cargo`, `go-mod`, `agenomic-yaml`, `readme`, `git`, `dockerfile`. |
| `--no-detect` | off | Skip detection entirely; behave like the legacy scaffolder. |
| `--force` | off | Overwrite existing files. |
| `--dry-run` | off | Print the genome that *would* be written, exit 0, write nothing. |
| `--format` | `human` | When combined with `--dry-run`, controls the output encoding. |

### 2.3 Detection sources, in priority order

Detection produces a single `DetectedGenome` value. Sources are
applied **lowest to highest priority** — later sources overwrite
earlier ones field-by-field. Empty fields are never written.

1. **Defaults.** Hard-coded placeholders. Same values as the legacy
   `cmd_init`.
2. **`git`.** `git remote get-url origin` → parsed for `<org>/<repo>`
   and used to seed `agent.id = agent://<org>/<repo>`.
3. **`readme`.** First H1 of `README.md` → candidate `agent.name`.
   First paragraph → candidate `description`.
4. **`go-mod` / `cargo` / `package-json`.** Standard manifest
   parsing. Sets `agent.name`, `description`, optionally
   `runtime.runtime_kind = "go" | "rust" | "node"`.
5. **`pyproject`.** Parsed via `toml`. Maps:
   - `[project].name` → `agent.name`
   - `[project].description` → `description`
   - `[project].authors[].name` → `agent.authors`
   - `[project].scripts` first key → `entrypoint`
   - `[project].dependencies` → see runtime/tool table in §2.4.
6. **`dockerfile`.** `ENTRYPOINT` / `CMD` → `entrypoint` fallback if
   nothing else set it.
7. **`agenomic-yaml`.** If `agenomic.yaml` already exists at the
   target, read it last so its values win. This is what makes a
   second `agm init` (or any `agm update`) idempotent.

The CLI logs the resolved precedence chain at `--format json` so
users can audit what overrode what:

```json
{
  "field": "runtime.model_provider",
  "value": "anthropic",
  "source": "pyproject",
  "evidence": "dependency `anthropic >= 0.45.0`"
}
```

### 2.4 Runtime and tool inference

Runtime kind is inferred from imports declared in manifests, **not**
from source-file scanning (source scanning is reserved for a future
`--deep` mode):

| Evidence in manifest | `runtime.framework` | `runtime.model_provider` |
| --- | --- | --- |
| `langgraph` dependency | `langgraph` | inherit from provider rule below |
| `langchain` or `langchain-*` dependency | `langchain` | inherit from provider rule below |
| `openai-agents` / `openai-swarm` | `openai-agents` | `openai` |
| `crewai` | `crewai` | inherit |
| `llama-index` | `llama-index` | inherit |
| `anthropic` SDK dependency | unchanged | `anthropic` |
| `openai` SDK dependency | unchanged | `openai` |
| `google-generativeai` / `vertexai` | unchanged | `google` |
| `cohere` | unchanged | `cohere` |
| None of the above | `custom` | `openai` (legacy default) |

`model_id` defaults per provider:

| Provider | `model_id` default |
| --- | --- |
| `anthropic` | `claude-sonnet-4-6` |
| `openai` | `gpt-4o` |
| `google` | `gemini-1.5-pro` |
| `cohere` | `command-r-plus` |

These defaults are written **only** when the source manifest gives no
explicit hint. If the project pins a model string in a config file
(e.g. `MODEL_ID = "claude-opus-4-7"` in `agenomic.yaml`,
`config.toml`, `.env.example`), that value wins.

Tools (`genome.yaml :: tools`) are inferred from a fixed allow-list
of well-known dependency names. Each entry yields one element in
`tools` whose `kind` is its category from the table below (e.g.
`linter`), and which is sorted by `(kind, name)` (§2.7):

| Dependency | Tool entry |
| --- | --- |
| `ruff`, `mypy`, `pylint`, `black` | linter |
| `radon`, `lizard` | complexity |
| `bandit`, `semgrep` | security |
| `pytest`, `unittest2` | test |
| `requests`, `httpx`, `aiohttp` | http |
| `pydantic` | schema |
| `redis`, `chromadb`, `weaviate-client`, `pinecone-client` | memory |
| `sqlalchemy`, `psycopg`, `asyncpg` | sql |

Memory inference: if any of `redis`, `chromadb`, `weaviate-client`,
`pinecone-client`, `langchain-community.vectorstores`, `langgraph
checkpoint` appears, set `runtime.memory.enabled = true` and
`runtime.memory.backend` to the matched name. Otherwise omit the
`memory` block entirely (do not write `enabled: false`).

### 2.5 Generated `genome.yaml` — full schema

Detection writes the same file the legacy command writes, but with
real values. The per-field evidence chain is written to a separate
`.agenomic/provenance.yaml` sidecar (below), **not** into `genome.yaml`:

```yaml
spec_version: '0.1'
agent:
  id: 'agent://traidano/agenomic-codedrift'
  name: 'codedrift-agent'
  domain: 'general'
  criticality: 'low'
  authors:
    - 'Traidano <dev@traidano.com>'
description: |
  E2E test agent — measures Claude code-quality drift over a fixed benchmark
runtime:
  framework: 'langgraph'
  runtime_kind: 'python'
  model_provider: 'anthropic'
  model_id: 'claude-sonnet-4-6'
  entrypoint: 'agenomic_codedrift.__main__:main'
tools:
  - { name: 'ruff',   kind: 'linter',     version: '>=0.6.0' }
  - { name: 'radon',  kind: 'complexity', version: '>=6.0.1' }
  - { name: 'bandit', kind: 'security',   version: '>=1.7.9' }
skills: []
knowledge: []
policies: []
```

Provenance is **not** written into `genome.yaml`. It is emitted to a
`.agenomic/provenance.yaml` **sidecar**, excluded from the bundle walk by
the `.agenomic/` default-exclude — and therefore from the canonical hash,
with no field-level exclusion needed in `agenomic-hash`. `agenomic hash`
and `agenomic validate` never see it. The sidecar:

```yaml
detector_version: '0.1.0'              # = the agenomic-spec crate version
detected_at: '2026-05-31T00:00:00Z'    # honours SOURCE_DATE_EPOCH
sources:
  - { field: 'agent.id',               value: 'agent://traidano/agenomic-codedrift', from: 'git',       evidence: 'origin=git@github.com:traidano/agenomic-codedrift.git' }
  - { field: 'runtime.model_provider', value: 'anthropic',                            from: 'pyproject', evidence: 'dependency anthropic>=0.45.0' }
  # … one entry per detected field; this is what `agm update` diffs against …
frozen: []          # fields kept because they were hand-edited
# last_update: { step, bundle_hash, changes }   # written by `agm update`
```

### 2.6 Exit codes

| Code | Condition |
| --- | --- |
| 0 | Init succeeded. |
| 2 | `genome.yaml` already present and `--force` not set. |
| 3 | Manifest existed but was unparseable (e.g. malformed `pyproject.toml`). The CLI prints the parser error and writes nothing. |
| 4 | Detection followed a symlink out of the workspace. Same defence as `agm build`. |

### 2.7 Determinism

Detection MUST be deterministic for a given working tree:

- Iteration over sources is alphabetical within each priority tier.
- Tool list is sorted by `(kind, name)`.
- `detected_at` is read from `SOURCE_DATE_EPOCH` if set; otherwise the
  current UTC time. CI MUST set `SOURCE_DATE_EPOCH`.
- The detector version is the crate version of `agenomic-spec`, not
  the binary version, so two `agm` builds at the same spec version
  produce identical output.

A snapshot test (`insta`) at
`crates/agenomic-cli/tests/snapshots/init_codedrift.snap` pins the
exact `genome.yaml` produced when run against a fixture mirroring
`agenomic-codedrift`. Changing detection rules requires updating that
snapshot.

---

## 3. `agm update` — incremental commits

### 3.1 Synopsis

```
agm update [PATH]
           [--message <MSG>]
           [--commit | --no-commit]
           [--sign]
           [--allow-dirty]
           [--step <NAME>]
           [--dry-run]
           [--format human|json|json-pretty|yaml]
```

`update` is the per-step counterpart to `init`. Each invocation:

1. Re-runs §2.3 detection.
2. **Merges** the result into the existing bundle: scalar fields are
   updated only when the new value has higher precedence (§2.3) than
   the value currently in the file; list fields are merged set-wise,
   preserving order; **hand-edited fields are preserved by default**
   (see §3.4).
3. Re-emits `genome.yaml`, `agent.lock.yaml`, `behavior.contract.yaml`
   in canonical form.
4. If `--commit` (default when the working tree is a git repo), stages
   the four bundle files and creates a commit.

### 3.2 Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--message <MSG>` | auto | Commit message. Default: `chore(agenomic): update bundle (<step> <hash-prefix>)`. |
| `--commit / --no-commit` | `--commit` if `.git` exists | Toggle the auto-commit. With `--no-commit`, files are written and left unstaged. |
| `--sign` | off | Pass `-S` to `git commit`. Requires `user.signingkey`. |
| `--allow-dirty` | off | Commit even if there are unrelated unstaged changes. Default refuses. |
| `--step <NAME>` | inferred | Logical step label. Free-form, sanitised to `[a-z0-9_-]`. Appears in the commit message and in `provenance.step`. |
| `--dry-run` | off | Print the diff vs. current files; exit 0; no writes, no commit. |

### 3.3 What counts as a "step"

A "development step" is any moment the user wants to checkpoint:
adding a tool, switching a model, changing the entrypoint, importing
a new dependency. The expected workflow:

```
# day 1
$ agm init                              # writes initial bundle
$ git add . && git commit -m "init bundle"

# day 2 — add bandit to pyproject.toml
$ agm update --step "add-security-scan"
✓ tools[+] bandit (security, >=1.7.9)
✓ committed: chore(agenomic): update bundle (add-security-scan a1b2c3d)

# day 3 — switch provider
$ vim pyproject.toml      # swap anthropic for openai
$ agm update --step "switch-provider"
✓ runtime.model_provider anthropic → openai
✓ runtime.model_id        claude-sonnet-4-6 → gpt-4o
✓ committed: chore(agenomic): update bundle (switch-provider f4e5d6a)
```

The point of the auto-commit is that every change to the agent's
genome is paired with a reviewable commit, so `git log -- genome.yaml`
becomes the change log of the agent.

### 3.4 Merge semantics

Hand-edits MUST be preserved. The merge algorithm:

1. Load the current `genome.yaml` into `Current`.
2. Run detection → `Detected`.
3. For each leaf field `f`:
   - If `Current[f]` is **set and not equal** to the prior detection
     output (recorded in `provenance.sources`), `Current[f]` was
     hand-edited. **Keep it.** Append an entry to `provenance.frozen`.
   - Otherwise replace with `Detected[f]`.
4. For list fields, perform a set-merge keyed by `name` (tools,
   skills, knowledge) or by `id` (policies). Removed-upstream items
   are kept unless `--prune` is passed.

The `provenance.sources` block from §2.5 is essential here: it
records what detection *did* on the previous run, which is how the
merger distinguishes "user edited this" from "detection used to
think this".

### 3.5 Commit format

Default commit message:

```
chore(agenomic): update bundle (<step> <short-hash>)

Detected changes:
- runtime.model_provider: anthropic → openai
- runtime.model_id:        claude-sonnet-4-6 → gpt-4o
- tools[+]: bandit (security, >=1.7.9)
- tools[-]: pylint

Bundle hash: b3:<full-hash>
```

The logical bundle hash is the BLAKE3 Merkle root (`b3:`/`blake3:`), the same
value `agenomic hash` prints — there is no separate sha256. `<short-hash>` is
its first 12 hex chars.

`<short-hash>` is the first 12 chars of the new bundle's
`logical_bundle_hash` (so `git log` lines up with `agenomic hash`).
The hash and the changes list are also written to
`provenance.last_update` for machine consumption.

Commits are deterministic given a fixed `SOURCE_DATE_EPOCH` and the
same working tree — required so two developers running `agm update`
on the same change produce the same diff.

### 3.6 Refusing to commit

`agm update --commit` refuses (exit 2) when:

- Not inside a git repo.
- Working tree has unrelated changes — i.e. staged/unstaged changes to
  files other than the bundle files **and** the detection-source manifests
  (`pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, `agenomic.yaml`,
  `README.md`, `Dockerfile`). Editing a manifest and then running `update`
  is therefore allowed; use `--allow-dirty` to override the rest.
- Detached HEAD, unless `--allow-dirty`.
- The active branch matches `protected_branches` in `agenomic.toml`
  (default: `main`, `master`, `release/*`). The user must
  explicitly run on a feature branch.

### 3.7 Exit codes

| Code | Condition |
| --- | --- |
| 0 | Update succeeded (changes committed, or no-op with `--no-commit`). |
| 1 | Detection ran but produced no changes; no commit created. (`agm update --dry-run` always returns 0.) |
| 2 | Refused per §3.6. |
| 3 | Merge conflict the algorithm could not resolve. The file is left untouched; the conflict is printed. |
| 4 | Path traversal during detection. |

### 3.8 CI integration

In CI, the recommended invocation is:

```
agm update --no-commit --format json > /tmp/agenomic-update.json
test "$(jq '.changed | length' /tmp/agenomic-update.json)" = "0" \
  || { echo "::error::genome.yaml is stale, run 'agm update' locally"; exit 1; }
```

This makes a stale bundle a CI failure without ever auto-committing
on a build server.

---

## 4. Configuration

Both commands read `agenomic.toml` at the workspace root (if
present):

```toml
[init]
default_domain      = "general"
default_criticality = "low"
sources             = ["pyproject", "package-json", "cargo", "go-mod",
                       "agenomic-yaml", "readme", "git", "dockerfile"]

[update]
auto_commit         = true
sign                = false
protected_branches  = ["main", "master", "release/*"]
commit_template     = "chore(agenomic): update bundle ({step} {hash})"
```

Anything not in the file falls back to the defaults in §2 and §3.

---

## 5. Backwards compatibility

- `agm init` invoked in an empty directory behaves exactly as
  before. Snapshot test `init_empty.snap` pins this.
- `agm init` invoked in a populated directory used to overwrite
  files; it now refuses (exit 2) and points the user at `agm update`.
  This is a **breaking change**. Since the CLI is pre-1.0 (`0.x`), it ships
  on the `0.x` line without a spec-version bump: `spec_version` and the
  `agenomic-spec` crate stay at `0.1`.
- `agm update` is new; no compatibility burden.
- Provenance is a `.agenomic/provenance.yaml` **sidecar**, not a key in
  `genome.yaml`, so `genome.yaml` and existing bundle hashes are unchanged
  and the validator needs no extension.

---

## 6. Implementation pointers

Files in `crates/agenomic-cli` that this spec touches:

- `src/cli.rs` — extend `InitArgs`, add `UpdateArgs`, add
  `Commands::Update`.
- `src/commands.rs` — replace `cmd_init` with a thin wrapper that
  calls into `agenomic-detect`; add `cmd_update`.
- `src/lib.rs` — wire `Commands::Update => cmd_update`.

New crate: `crates/agenomic-detect`:

- `detect::run(path) -> DetectedGenome`
- `detect::Source` enum, one variant per source in §2.3.
- `merge::merge(current, detected, prior_provenance) -> MergeResult`.
- All file I/O via `agenomic-fs` (atomic writes, symlink rejection).
- All git interaction via `gix` (pure-Rust; no shelling out, no network).

Tests:

- `tests/snapshots/init_empty.snap` — legacy behaviour.
- `tests/snapshots/init_codedrift.snap` — fixture mirroring the
  `agenomic-codedrift` repo (pyproject with langgraph + anthropic +
  ruff/radon/bandit).
- `tests/snapshots/update_no_change.snap` — exits 1, no commit.
- `tests/snapshots/update_provider_swap.snap` — model swap.
- `tests/snapshots/update_user_edit_preserved.snap` — hand-edit kept.
- `proptest!` over arbitrary `(current, detected)` pairs: merge is
  idempotent (`merge(merge(a, b), b) == merge(a, b)`) and
  hand-edits are never silently overwritten.

---

## 7. Reproducing the original report

```
$ cd agenomic-codedrift
$ agm init . --dry-run --format yaml
```

After this spec is implemented the output MUST match the
`genome.yaml` in §2.5 byte-for-byte (modulo `detected_at` when
`SOURCE_DATE_EPOCH` is unset).
