# Implementation plan — repo-aware `agm init` + incremental `agm update`

**Status: Phase 0 COMPLETE — all §4 answers SIGNED OFF (2026-06-01). Cleared for
Phase 1 on explicit "go". Decisions locked: Q1 new `agenomic-detect` crate · Q2
provenance sidecar `.agenomic/provenance.yaml` · Q3 reuse exit 1 for no-change ·
Q4 `gix` (pending `cargo deny`) · Q5 keep spec `0.1`.**

Contract: [`docs/init-and-update.md`](../init-and-update.md) (§ refs below point
there) and the `init`/`update` entries in
[`docs/command-reference.md`](../command-reference.md).

Branch: `feat/agm-init-update`, forked from `origin/claude/elegant-clarke-T6cNj`
(the docs-only spec branch) so it carries the spec + the prior `feat/git-version-in-cli`
work. cli has **no `develop`** — its integration branch is `main`; PR target is `main`.

---

## 0. What the code-read changed about the spec's assumptions

The mandatory reading surfaced four facts that the spec did not account for. Each
feeds a §4 answer below; collecting them here first because they are the spine of
the plan.

1. **The canonical hash is a raw-byte BLAKE3 Merkle root with no field-level
   exclusion.** `compute_manifest` (`crates/agenomic-hash/src/merkle.rs:92`) walks
   the dir via `walk_bundle(root, WalkOptions::default())` and leaf-hashes raw file
   bytes (`leaf_hash`, `merkle.rs:31`). There is no `exclude_from_hash` mechanism
   anywhere. So the spec's "`provenance:` is a top-level key in `genome.yaml`
   excluded from the hash" (§2.5/§5) **cannot be honored as written** without either
   polluting the byte-hash or relocating provenance. → **Q2**.
2. **`.agenomic/` is already excluded from the walk.** `DEFAULT_EXCLUDES`
   (`crates/agenomic-fs/src/walk.rs:25`) contains `".agenomic/"`. A provenance
   *sidecar* written to `.agenomic/provenance.yaml` is therefore excluded from the
   bundle manifest and the logical hash **for free**, with zero changes to
   `agenomic-hash`. This makes the clean Q2 option essentially free.
3. **`agenomic-spec` is deliberately I/O-free** (schema embedding + version
   negotiation only — `crates/agenomic-spec/src/lib.rs`). Detection does file I/O +
   git, so it must NOT live in `agenomic-spec`. → **Q1: new `crates/agenomic-detect`.**
4. **The non-error exit pattern already exists.** `cmd_validate`
   (`commands.rs:90-101`) returns `Ok(ExitCode::SecurityViolation)` /
   `Ok(ExitCode::ValidationFailed)`; `cmd_diff` returns `Ok(ExitCode::DiffRiskExceeded)`.
   So init's "refuse" and update's "no-change/refuse" exits need **no new exit
   codes** — they are `Ok(ExitCode::…)` returns (or `CliError` variants mapping to
   existing codes). → **Q3.**

Additional confirmations: `genome.schema.json` has top-level
`additionalProperties: true` (so any `provenance` key validates under 0.1 already);
the binary is `0.1.0` and `SUPPORTED_SPEC_VERSIONS = ["0.1"]`
(`agenomic-spec/src/lib.rs:9`); `golden.rs` hashes 4 fixed pairs (decoupled from
`genome.yaml`, so it does NOT fire on provenance changes — but a real bundle's
`logical_bundle_hash` and the `init_codedrift` snapshot DO change if provenance
goes inline); `git-version = "0.3"` is already staged in `Cargo.toml:52` (the
`feat/git-version-in-cli` work) but is **binary** version, distinct from the
**detector** version (= `agenomic-spec` crate version) required by §2.7.

---

## 1. §4 arbitration — proposed answers (ALL need sign-off)

### Q1 — Where detection lives → **new `crates/agenomic-detect`** ✅ recommend

`agenomic-spec` is schema/version-only and must stay that way. A dedicated crate
keeps git + filesystem + manifest-parsing out of the schema crate.

- **Depends on:** `agenomic-core` (errors/exit), `agenomic-fs` (atomic write,
  walk, security excludes), `agenomic-spec` (detector version const + canonical
  defaults), `serde`, `serde_yaml`, `toml` (all already in `[workspace.dependencies]`),
  and `gix` (new — see Q4). Dev: `proptest`, `insta`, `tempfile`.
- **Does NOT depend on `agenomic-hash`.** The update short-hash is computed by the
  CLI layer (`cmd_update` calls `agenomic_hash::compute_manifest` on the bundle
  dir) and passed into emission/commit, keeping `agenomic-detect`'s dep graph tight.
- `detector_version`: add `pub const DETECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");`
  to `agenomic-spec` (its crate version is `0.1.0`, matching the §2.5 snapshot's
  `detector_version: '0.1.0'`). `agenomic-detect` reads `agenomic_spec::DETECTOR_VERSION`.

*Trade-off:* one more workspace crate to maintain vs. a clean dependency boundary.
Low controversy.

### Q2 — provenance vs the hash → **(a) sidecar `.agenomic/provenance.yaml`** ✅ recommend

Write the provenance block (the §2.5 `detector_version`/`detected_at`/`sources`,
plus §3.4 `frozen` and §3.5 `last_update`) to **`.agenomic/provenance.yaml`**, NOT
inside `genome.yaml`. `.agenomic/` is already in `DEFAULT_EXCLUDES`, so it is
excluded from the bundle walk → excluded from the manifest → excluded from
`logical_bundle_hash`. `genome.yaml` stays byte-pure; `agenomic-hash`,
`golden.rs`, `inspect`, `diff`, and the strict-validated `examples/*` are all
untouched. The merge algorithm (§3.4) reads prior detection from the sidecar's
`sources`.

| Option | Hash purity | agenomic-hash change | Spec fidelity | Verdict |
| --- | --- | --- | --- | --- |
| (a) sidecar `.agenomic/provenance.yaml` | pure | none | relocates provenance | **recommend** |
| (b) strip `provenance:` in hasher | polluted | special-case genome.yaml | literal | discouraged (prompt §3.1) |
| (c) tooling-only under `.agenomic/` | pure | none | relocates provenance | equivalent to (a) |

*Trade-off / why sign-off is needed:* this **edits the contract**. §2.5, §5, and
§3.4 currently say provenance is a top-level key in `genome.yaml`. Choosing (a)
means rewriting those sections to put it in the sidecar (the spec's own preamble
authorizes "any change to … commit semantics MUST update this document in the same
PR"). The cost is that `genome.yaml` is slightly less self-documenting; the win is
the byte-hash invariant (AGENTS.md product-invariant #2) is preserved with no
hasher surgery.

### Q3 — exit-code mapping → **reuse 0–10, add `CliError` variants (no new codes)** ✅ recommend, with one flag

`ExitCode` 0–10 is frozen (`exit.rs`). No renumbering, no new code, with **one
decision to confirm**.

| Command / condition | Exit | Mechanism |
| --- | --- | --- |
| init OK | 0 | `Ok(ExitCode::Success)` |
| init: `genome.yaml` present, no `--force` (§2.6) | 2 | new `CliError::InitWouldOverwrite{path}` → `InvalidUsage`, with `help("run \`agm update\`, or pass --force")` |
| init: unparseable manifest (§2.6) | 3 | reuse `CliError::Schema`/`Internal` → `InternalError`; nothing written |
| init/update: symlink/`..` during detect (§2.6/§3.7) | 4 | reuse `agenomic_fs` → `CliError::SymlinkRejected`/`PathTraversal` → `SecurityViolation` |
| update OK (committed, or no-op `--no-commit`) | 0 | `Ok(ExitCode::Success)` |
| **update: detection produced no changes (§3.7)** | **1** | `Ok(ExitCode::ValidationFailed)` after rendering the "no changes" report |
| update: refused per §3.6 | 2 | new `CliError::UpdateRefused{reason}` → `InvalidUsage` |
| update: unresolvable merge conflict (§3.7) | 3 | new `CliError::UpdateMergeConflict{detail}` (or reuse `Internal`) → `InternalError` |

*The one item needing explicit sign-off:* update's **"no changes → exit 1"**
overloads the `ValidationFailed` name. Returning `Ok(ExitCode::ValidationFailed)`
is the literal spec behavior and keeps `git log`/CI scripts (which test for `1`)
working, but the name reads wrong. Alternative: add `ExitCode::NoChanges = 11`
(allowed — adding is non-breaking) and update §3.7 + the command-reference exit
table to say `11`. **Recommend: reuse `1`** (spec-faithful, scripts already expect
it); flag the name overload in the spec.

### Q4 — git library → **`gix` (pure Rust)** ✅ recommend

| | `gix` | `git2` (libgit2-sys) |
| --- | --- | --- |
| Cross-compile `aarch64-unknown-linux-gnu` via `cross` (`release.yml:18`) | clean, no C | C toolchain / vendored libgit2 friction |
| Offline invariant (AGENTS.md #1) | local-only, no network | same |
| License vs `deny.toml` | MIT OR Apache-2.0 (in allow-list) | crate MIT/Apache; vendored libgit2 = GPL-2.0-w/-linking-exception (ambiguous vs allow-list) |
| Commit-creation ergonomics | lower-level (build tree → commit object → update ref) | one-liner `index.add_path` + `repo.commit` |
| Dep-tree size | larger (many gitoxide crates; `multiple-versions = "warn"`, tolerated) | smaller |

The spec §6 names `git2`, but its binding constraint is *"library, no shelling
out, no network"* — `gix` satisfies that and wins on the cross-compile matrix and
license clarity. Used for: reading `remote.origin.url` (Q1 git source), branch
name / dirty-tree / detached-HEAD checks (§3.6), and creating the commit (§3.1).

*Trade-off / sign-off:* `gix`'s commit API is more verbose than `git2`'s — budget
extra care in P7. **Action before P1:** add `gix` to a throwaway build and run
`cargo deny check` to confirm the full transitive tree clears licenses + advisories
(`unknown-git = "warn"`, `wildcards = "deny"`). If `cargo deny` flags `gix`, fall
back to `git2` and accept the cross-compile cost. Update spec §6 `git2`→`gix`.

### Q5 — spec-version gating → **keep `0.1`; do NOT bump to `0.2`** ✅ recommend

§5 ties the breaking `init` change to "agenomic-spec 0.2", but:

- `detector_version` = `agenomic-spec` crate version, and §2.5's snapshot pins
  `detector_version: '0.1.0'`. Bumping the crate to `0.2.0` would contradict that
  snapshot.
- The emitted `spec_version` stays `'0.1'` per §2.5 itself, and `SUPPORTED_SPEC_VERSIONS`
  / the embedded schema set are all `0.1`.
- With Q2 (sidecar), `genome.yaml` gains **no** new keys → no schema/validator
  change is needed at all (and `additionalProperties: true` already accepts extras).

The only "breaking" behavior is init refusing on a populated dir instead of
overwriting. The binary is `0.1.0` (semver `0.x`), so a breaking *CLI* change is
acceptable without a spec-version bump. **Recommend:** keep `0.1`; reconcile §5 to
gate the breaking behavior on the CLI `0.x` line, not a spec bump.

*Trade-off:* slightly weaker formal versioning story; mitigated by pre-1.0 status
and the snapshot/CI guardrails.

---

## 2. Spec reconciliations to land in P10 (consequences of §4 answers)

The spec's own preamble requires updating `docs/init-and-update.md` in the same PR
when detection/commit semantics change. Pending sign-off, P10 will:

- **§2.5 / §5 / §3.4** — relocate provenance from "top-level key in `genome.yaml`"
  to the `.agenomic/provenance.yaml` sidecar; restate "excluded from hash" as
  "lives under `.agenomic/`, excluded from the bundle walk". (Q2)
- **§6** — `git2` → `gix`. (Q4)
- **§3.5** — `Bundle hash: sha256:<full-hash>` → blake3 `logical_bundle_hash`
  (`b3:<hex>` via `format_hash`); the codebase has no sha256 logical hash. Short-hash
  = first 12 hex chars of that blake3 root (matches `agenomic hash`).
- **§5** — relax the "gated on agenomic-spec 0.2" sentence to a CLI `0.x` breaking
  change. (Q5)
- **command-reference.md** — if Q3 alternative is chosen, add code `11`; else leave
  the exit table and note update's `1` overload.

---

## 3. Crate / module layout & public API surface (`crates/agenomic-detect`)

```
crates/agenomic-detect/
  Cargo.toml
  src/
    lib.rs          # re-exports; crate doc
    model.rs        # DetectedGenome, Field<T>, FieldSource, Evidence, ToolEntry, MemoryInfo
    detect.rs       # run(path, &DetectOptions) -> CliResult<DetectedGenome>; precedence chain
    infer.rs        # framework/provider/model_id tables, tool allow-list, memory backend (§2.4)
    emit.rs         # DetectedGenome -> canonical bytes for the 4 bundle files (§2.5)
    provenance.rs   # Provenance{detector_version,detected_at,sources,frozen,last_update}; sidecar read/write
    merge.rs        # merge(current, detected, prior) -> MergeResult (§3.4); idempotent
    git.rs          # gix: origin_url(path), repo_state(path), commit_bundle(...) (§3.1/§3.6)
    sources/
      mod.rs        # Source enum (one variant per §2.3), alphabetical-within-tier ordering
      defaults.rs   # tier 1 — legacy placeholders
      git.rs        # tier 2 — origin remote -> agent.id
      readme.rs     # tier 3 — H1 -> name, first para -> description
      manifest.rs   # tier 4 — go.mod / Cargo.toml / package.json
      pyproject.rs  # tier 5 — pyproject.toml (toml crate)
      dockerfile.rs # tier 6 — ENTRYPOINT/CMD fallback
      agenomic_yaml.rs # tier 7 — existing agenomic.yaml (idempotence anchor)
```

**Public API (the surface other crates call):**

```rust
// model.rs
pub struct DetectedGenome { /* agent, runtime, tools, skills, knowledge, policies + per-field FieldSource */ }
pub struct ToolEntry { pub name: String, pub kind: ToolKind, pub version: Option<String> }
pub enum   ToolKind { Linter, Complexity, Security, Test, Http, Schema, Memory, Sql }
pub enum   Source { Defaults, Git, Readme, GoMod, Cargo, PackageJson, Pyproject, Dockerfile, AgenomicYaml }
pub struct Evidence { pub field: String, pub value: String, pub source: Source, pub evidence: String }

// detect.rs
pub struct DetectOptions { pub only: Option<Vec<Source>>, pub no_detect: bool, pub name_override: Option<String>, pub agent_id_override: Option<String> }
pub fn run(path: &Path, opts: &DetectOptions) -> CliResult<DetectedGenome>;

// emit.rs
pub struct EmittedBundle { pub genome: Vec<u8>, pub lock: Vec<u8>, pub contract: Vec<u8>, pub system_prompt: Vec<u8> }
pub fn emit(g: &DetectedGenome) -> CliResult<EmittedBundle>;
pub fn write_bundle(dir: &Path, b: &EmittedBundle, force: bool) -> CliResult<()>; // via agenomic_fs::write_atomic

// provenance.rs
pub struct Provenance { /* detector_version, detected_at, sources, frozen, last_update */ }
pub fn provenance_path(dir: &Path) -> PathBuf;            // dir/.agenomic/provenance.yaml
pub fn load_provenance(dir: &Path) -> CliResult<Option<Provenance>>;
pub fn write_provenance(dir: &Path, p: &Provenance) -> CliResult<()>;

// merge.rs
pub struct MergeResult { pub merged: DetectedGenome, pub changes: Vec<Change>, pub frozen: Vec<String>, pub conflicts: Vec<Conflict> }
pub fn merge(current: &DetectedGenome, detected: &DetectedGenome, prior: Option<&Provenance>, prune: bool) -> CliResult<MergeResult>;

// git.rs (gix)
pub fn origin_url(path: &Path) -> CliResult<Option<String>>;
pub struct RepoState { pub is_repo: bool, pub branch: Option<String>, pub detached: bool, pub dirty_outside: Vec<String> }
pub fn repo_state(path: &Path, bundle_files: &[&str]) -> CliResult<RepoState>;
pub fn commit_bundle(path: &Path, files: &[&Path], message: &str, sign: bool) -> CliResult<String>; // returns commit oid
```

**`detected_at`/determinism (§2.7):** `detected_at` = `SOURCE_DATE_EPOCH` (RFC3339
UTC) if set, else `chrono::Utc::now()`. Sources iterate alphabetically within each
tier; tool list sorted by `(kind, name)`; emission uses a fixed key order matching
§2.5 (hand-built serializer or an `IndexMap`-backed value to guarantee byte order —
`serde_yaml` map ordering must be pinned).

---

## 4. Dependency additions (exact)

`[workspace.dependencies]` (root `Cargo.toml`):

```toml
agenomic-detect = { path = "crates/agenomic-detect", version = "0.1.0" }   # internal
gix = { version = "0.66", default-features = false, features = ["max-performance-safe"] }  # pin TBD after `cargo deny`
```

- `gix` version/features to be finalized in P1 against `cargo deny`; start
  `default-features = false` and enable only what `git.rs` needs (ref/config read,
  status, commit). Pure-Rust TLS not relevant (offline; no network features).
- `crates/agenomic-detect/Cargo.toml` deps: `agenomic-core`, `agenomic-fs`,
  `agenomic-spec`, `serde`, `serde_yaml`, `toml`, `gix` (all `workspace = true`);
  dev-deps `proptest`, `insta`, `tempfile`.
- `crates/agenomic-cli/Cargo.toml`: add `agenomic-detect = { workspace = true }`;
  dev-deps add `insta = { workspace = true }` + `serde_yaml = { workspace = true }`
  (snapshot tests) + `proptest` if any CLI-level proptest.
- Add `"crates/agenomic-detect"` to `members` in root `Cargo.toml`.
- No change to `deny.toml` expected (all licenses already allowed); **gate P1 on a
  green `cargo deny check`**.

---

## 5. Phase touch-list (files per phase; P1 gated on plan approval)

- **P1 — skeleton.** NEW `crates/agenomic-detect/{Cargo.toml,src/lib.rs,src/model.rs,src/detect.rs}`
  (defaults-only `run`). EDIT root `Cargo.toml` (`members` + `[workspace.dependencies]`
  `agenomic-detect`, `gix`). EDIT `crates/agenomic-spec/src/lib.rs` (+`DETECTOR_VERSION`).
  Verify `cargo deny check` green. `cargo build --workspace` green.
- **P2 — sources.** NEW `src/sources/*.rs` (precedence chain low→high; empty fields
  never overwrite; per-field `Evidence`). EDIT `src/detect.rs` to walk the chain.
  All git via `gix` (`src/git.rs::origin_url`), local-only.
- **P3 — inference.** NEW/EDIT `src/infer.rs` (framework/provider/model_id tables
  pinned to §2.4 literals `claude-sonnet-4-6`/`gpt-4o`/`gemini-1.5-pro`/`command-r-plus`;
  tool allow-list; memory backend; tool sort `(kind,name)`).
- **P4 — emission + provenance.** NEW `src/emit.rs` (+ `prompts/system.md`),
  `src/provenance.rs` (sidecar). Honor `SOURCE_DATE_EPOCH`. **Gated on Q2 sign-off.**
- **P5 — `agm init` repo-aware.** EDIT `crates/agenomic-cli/src/cli.rs` (`InitArgs`:
  +`from: Vec<Source>` repeatable, `no_detect`, `force`, `dry_run`; keep `path`,
  `agent_id`, `name`). EDIT `crates/agenomic-cli/src/commands.rs` (`cmd_init` →
  thin wrapper over `agenomic_detect`; three dir-state branches §2.1; **empty/no-manifest
  path byte-identical to current `commands.rs:30-39`**; `--dry-run` prints in
  `--format`, writes nothing, exit 0). EDIT `crates/agenomic-core/src/error.rs`
  (+`InitWouldOverwrite`). Keep `init_then_validate_then_build` green.
- **P6 — merge.** NEW `src/merge.rs` (§3.4; scalar by precedence; hand-edits frozen
  via sidecar `sources`/`frozen`; list set-merge keyed by `name`/`id`; `--prune`).
  Idempotent.
- **P7 — `agm update` + commit.** EDIT `cli.rs` (`UpdateArgs` + `Commands::Update`),
  `lib.rs` (`Commands::Update => cmd_update` at `lib.rs:45-61`), `commands.rs`
  (`cmd_update`: detect→merge→emit→`agenomic_hash::compute_manifest`→
  `agenomic_detect::git::commit_bundle`). Flags `--message/--commit/--no-commit/
  --sign/--allow-dirty/--step/--dry-run`. Refusals §3.6, exit codes §3.7. EDIT
  `error.rs` (+`UpdateRefused`, +`UpdateMergeConflict`). Short-hash = first 12 hex
  of `logical_bundle_hash`.
- **P8 — config.** EDIT `crates/agenomic-config/src/lib.rs`: add `InitConfig` +
  `UpdateConfig` structs, `pub init`/`pub update` on `ProjectConfig`, and **expose**
  `load_project_walking_up` (currently private, `lib.rs:226`) as a `pub fn`.
  `protected_branches` default `["main","master","release/*"]`.
- **P9 — tests** (see §6).
- **P10 — docs.** EDIT `docs/init-and-update.md` + `docs/command-reference.md` +
  `docs/ci-cd.md` (§3.8 stale-bundle check). EDIT `CHANGELOG.md` `[Unreleased]`.

---

## 6. Snapshot / proptest inventory

NEW dir `crates/agenomic-cli/tests/snapshots/` + a new integration test file
`crates/agenomic-cli/tests/init_update.rs` (drives the built binary like
`cli_smoke.rs`; uses `insta` + `SOURCE_DATE_EPOCH` pinned).

- `init_empty.snap` — legacy empty-dir output (establishes the byte-for-byte legacy
  genome; pairs with the unchanged `init_then_validate_then_build` smoke test).
- `init_codedrift.snap` — fixture mirroring `agenomic-codedrift` (pyproject +
  langgraph + anthropic + ruff/radon/bandit); must match §2.5 byte-for-byte modulo
  `detected_at`.
- `update_no_change.snap` — exit 1, no commit.
- `update_provider_swap.snap` — anthropic→openai + model_id swap.
- `update_user_edit_preserved.snap` — hand-edit kept (frozen via sidecar).

Proptests in `crates/agenomic-detect` (`proptest!`):
- merge idempotence: `merge(merge(a,b),b) == merge(a,b)`.
- hand-edits never silently overwritten.

Integration: the §7 reproduction (`agm init . --dry-run --format yaml` against the
codedrift fixture) as a test asserting the §2.5 output.

CI: add the §3.8 stale-bundle JSON check snippet to `docs/ci-cd.md`.

---

## 7. Definition-of-done crosswalk

Mirrors the prompt's DoD checklist; each item maps to a phase above. Determinism
(`SOURCE_DATE_EPOCH`, alphabetical tiers, `(kind,name)` tool sort, `detector_version`
= `agenomic-spec` crate version), offline invariant, no `unwrap`/`expect` outside
tests, and `cargo fmt`/`clippy -D warnings`/`test`/`deny` green on the matrix are
phase-exit gates, not a final step.

---

## 8. Sign-off record (LOCKED 2026-06-01)

1. **Q1 — APPROVED:** new `crates/agenomic-detect`.
2. **Q2 — APPROVED:** provenance to `.agenomic/provenance.yaml` sidecar. Spec
   §2.5/§5/§3.4 to be rewritten in P10 to relocate provenance out of `genome.yaml`.
3. **Q3 — APPROVED:** reuse exit codes 0–10 + new `CliError` variants; update's
   "no changes → exit 1" stays `Ok(ExitCode::ValidationFailed)` (reuse 1); flag the
   name overload in the spec.
4. **Q4 — APPROVED:** `gix`. P1 hard gate: a green `cargo deny check` over the full
   transitive tree; if it fails, fall back to `git2` and re-confirm. Spec §6
   `git2`→`gix` in P10.
5. **Q5 — APPROVED:** keep `spec_version` and the `agenomic-spec` crate at `0.1`;
   reconcile §5 to frame init's refuse-on-populated-dir as a CLI `0.x` breaking
   change.

Phase 1 begins on the user's explicit go.
