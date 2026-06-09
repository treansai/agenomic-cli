# Backend Gaps

This document tracks backend surfaces, behaviors, and integrations that are
referenced by the Agenomic spec or CLI but not yet implemented. New gaps are
appended; resolved gaps are removed in the PR that closes them.

The intent is to make missing capabilities explicit and refusable rather than
papered over with mocks. If a code path would require a missing capability,
it should fail closed with a diagnostic that references this file.

## Spec 0.2 — `execution` block & `agent://` (introduced)

### Resolver: remote `agent://` references

- **Status**: not implemented.
- **Affected**: `agenomic-os::resolver`, eventual `agenomic run agent://...`.
- **Expected behavior**: refuse with a diagnostic pointing here. Local
  references (file paths, in-repo bundles) MAY be resolved offline.
- **Required surfaces**:
  - registry lookup endpoint (org/slug → bundle source)
  - channel resolution (`@prod`, `@staging`, …)
  - content-addressable retrieval (`@sha256:…`)
  - publisher trust ledger

### Bundle signature verification on remote pulls

- **Status**: not implemented end-to-end.
- **Affected**: `agenomic-os::resolver`, `agenomic-os::materializer`.
- **Plan**: reuse `agenomic-attestation` for signature verification. Remote
  unsigned bundles MUST be refused by default (exit code reserved in
  `agenomic-os` PR-3).

### LangGraph / CrewAI detection

- **Status**: not implemented.
- **Affected**: `agenomic-detect` (extension), `agenomic port` command.
- **Plan**: extend `agenomic-detect` with framework-level heuristics
  (imports, file structure, manifest hints) in `agenomic-os` PR-2. Until
  then, `agenomic port` falls back to language/manifest detection only and
  marks framework-specific concerns as `NotYetAvailable`.

### Docker / wasm launchers

- **Status**: implemented (subprocess wrappers).
- **Affected**: `agenomic-os::launcher`.
- **What ships**: `entrypoint.kind` now accepts `command`, `docker`, or
  `wasm`. `DockerLauncher` invokes `docker run --rm -i --network=none|bridge
  -e <NAME> <image> [args…]`; `WasmLauncher` invokes `wasmtime run [--dir
  …] [-S http] <module> [args…]`. Both go through the same fail-closed env
  filter and trace pipeline as `CommandLauncher`. The `docker` and `wasm`
  CLIs must be on `PATH` (or overridden in tests); their absence surfaces as
  `OsError::LauncherFailed` (exit 15).
- **Still out of scope**: per-host network allow-listing (docker's
  `--network` is coarse), gVisor/Firecracker isolation, and a native
  embedded WASM runtime — covered by the sandbox-hardening track.

### Sandbox hardening (Linux namespaces, seccomp)

- **Status**: not implemented.
- **Affected**: `agenomic-os::policy`, `agenomic-os::launcher`.
- **MVP behavior**: env filtering, strict `current_dir`, no stdin by default,
  declared permissions enforced at the spec level. No kernel-level
  isolation.
- **Note**: OPA/Rego policy enforcement *is* now available — `agenomic-policy`
  evaluates `policies/*.rego` as a fail-closed gate before launch (see
  `agenomic run` / `agenomic policy eval`). That gate is a spec-level
  authorization decision, not kernel isolation; both layers are complementary.

### Runtime compile — live MCP tool transport

- **Status**: partially implemented.
- **Affected**: `agenomic-compile`, generated `runtime/*.compiled/` trees.
- **Implemented**: `agenomic compile` lowers a genome into deterministic,
  self-contained adapters for `plain` (FastAPI + provider SDK), `langgraph`,
  `crewai`, `docker` (the `plain` service as a pinned OCI image), and `wasm`
  (a `componentize-py` WASI component), each with a hashed `manifest.json`.
- **Gap**: declared MCP tools are emitted as typed stubs (server + version
  recorded) rather than live bindings; turning a stub into a real MCP call is
  the operator's integration step. The `docker`/`wasm` *artifacts* are emitted
  but are run by their own hosts — `agenomic run`'s launcher still handles
  `command` entrypoints only (see "Docker / wasm launchers"). For `wasm`,
  outbound model calls additionally require a WASI-HTTP-capable host.

### Governance agents (Point 4 / Gap 5)

- **Status**: partially implemented (CLI/local layer).
- **Implemented**: `agenomic-governance` crate plus `agenomic governance
  {cluster,hypothesize,critique,audit}`. Mode 1 (failure clustering) groups
  flagged traces by `(signal, skill)` with deterministic keyword mining.
  Mode 2 (hypothesis generation) emits typed `Proposal`s that never mutate
  the bundle. Mode 3 (adversarial reviewer) runs a fail-closed rule battery
  and returns `pass` / `warn` / `block` (block → exit 16). All three engines
  are pure functions — same input → byte-identical output — so they chain
  cleanly into a downstream attestation.
- **Gap**: Mode 4 (human approval gate) and Mode 5 (shadow / canary
  deployment at 0/5/25/100% traffic) belong above this layer; the CLI emits
  the artifacts a gate / replay-runner consumes but does not yet ship the
  gate itself. The cloud-side `AdversarialReview` entity from
  `agenomic-web/BACKEND_GAPS.md` Gap 5 is also still open — these engines
  are the local computation side of that workflow.

### Replay distribution

- **Status**: not implemented.
- **Affected**: `agenomic-replay-local` (would need a distributed sibling).
- **Plan**: orthogonal to `agenomic-os`. Tracked here so users do not
  expect cross-machine replay from `agenomic os replay` once that command
  ships.

## CURRENT_SPEC_VERSION bump to 0.2

- **Status**: deferred.
- **Affected**: `agenomic-spec::CURRENT_SPEC_VERSION`, examples under
  `examples/`, fixtures under `crates/agenomic-validate/tests/fixtures/`,
  insta snapshots, doctest strings in `agenomic-detect` and others.
- **Rationale**: the spec extension landed additively (schemas accept both
  `0.1` and `0.2`; `0.2` introduces the `execution` block and
  `execution_hash`). Bumping the emitted default to `0.2` will churn ~20+
  fixtures/snapshots and is best handled in a focused migration PR with a
  predictable diff.
- **Closing criteria**: dedicated PR retitled "bump CURRENT_SPEC_VERSION to
  0.2", updating examples/fixtures/snapshots and the init emission path,
  with all existing tests rebaselined.
