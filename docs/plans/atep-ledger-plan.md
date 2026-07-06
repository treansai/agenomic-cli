# Phase 0 plan — cryptographic ATEP ledger

**Status: Phase 0 COMPLETE — awaiting sign-off on every §2 arbitration (Q0–Q8)
and the §3 contradictions. NO implementation until an explicit "go". Every
subsequent phase (1–5) also ends with a gate.**

Prompt contract: internal/private, append-only, tamper-evident, signed event
ledger for all Agenomic runtime and governance events. Blockchain-style hash
chain, **not** a blockchain: no consensus, no distribution, no tokens. Two
non-negotiables: **no event loss** (durable or explicitly dead-lettered, never
silently dropped) and **never block agents by default** (hot path non-blocking;
blocking only in explicitly configured strict modes).

Branch: `claude/cryptographic-atep-ledger-qcbp7z`. Target repo: **agenomic-cli**
(confirmed below, §1). Integration branch is `main`; PR target is `main`.

---

## 0. What the code-read changed about the prompt's assumptions

The mandatory reading (all nine repos) surfaced facts that reshape the spec.
These are the spine of the plan; each feeds an arbitration answer in §2.

1. **The crate convention is `agenomic-*`, not `agentlock-*`.** All 23 crates in
   this workspace and all 34 in agenomic-cloud are `agenomic-*`
   (`Cargo.toml:3-25` here; `agenomic-cloud/Cargo.toml`). `AGENTLOCK-*` survives
   only inside frozen byte-level domain separators (`AGENTLOCK-LEAF-v1\0`,
   `AGENTLOCK-NODE-v1\0` — `crates/agenomic-hash/src/merkle.rs:24-26`, RFC 0002)
   which must never change. The prompt's suggested `atep-ledger` violates the
   convention → **Q1**.

2. **A signed, hash-linked, Merkle-rooted event log already exists on both
   sides.** This is the single most important finding: the ledger is an
   *extension and unification job*, not a green-field build.
   - **CLI:** ATEP (`crates/agenomic-atep`) is canonical-CBOR events with BLAKE3
     causal hashes (`ATEP-v1\0` domain, `event.rs:194-212`), Ed25519 over the
     32-byte hash, HLC clocks, append-only `.atep` segments with CRC32 +
     per-segment Merkle root (`segment.rs`), and `agenomic atep verify`. The
     governance audit trail already seals signed `governance.*` events onto it
     (`commands.rs:1191-1256`; BACKEND_GAPS "Audit trail (resolved)").
   - **CLI:** `agenomic-track` events are already hash-linked
     (`event_hash = blake3(AGENOMIC-TRACK-EVENT-v1\0 ‖ json ‖ prev)`,
     `crates/agenomic-track/src/event.rs:200-233`) with optional detached
     signatures, persisted to append-only JSONL.
   - **Cloud:** `agenomic-cloud/crates/agenomic-ledger` implements the RFC 0010
     run-trace ledger: canonical-JSON (JCS) event cores, per-run
     `prev_event_hash` chain, `blake3-merkle-v1` seal signed by org-scoped
     Ed25519 (KMS-wrapped, rotatable, `agenomic-crypto/src/store.rs`), plus a
     WORM Postgres schema (`migrations/20260722000001_evidence_ledger.sql`) and
     `POST /v1/runs/:run_id/events` / `seal` / `ledger/verify` routes.
   What does **not** exist anywhere: a durable local ingestion pipeline
   (queue/WAL/dead-letter/backpressure/crash-recovery), a global cross-run
   chain, block sealing, key rotation on the CLI side, latency modes, a unified
   verification engine with a structured report, or a `agenomic ledger` CLI.
   That is the actual scope of this work.

3. **Two canonicalization regimes coexist by design.** ATEP (RFC 0003) hashes
   canonical CBOR over field-ordered structs; the run-trace ledger (RFC 0010)
   and the cloud port (`agenomic-cloud/crates/agenomic-canonical`, an explicit
   byte-compatible port of `agenomic-spec/scripts/trace-crypto.js`) hash
   JCS/RFC-8785-flavoured canonical JSON. Both use BLAKE3 exclusively ("no
   divergent algorithm vs ATEP", `agenomic-canonical/src/lib.rs:20`). The
   ledger entry is a *new* envelope, so Q3 is a genuine choice — but both
   candidate implementations already exist in-tree → **Q3**.

4. **Q2 is answered by convention, not open.** BLAKE3 is the hash everywhere
   (ATEP, bundle Merkle, track events/reports, cloud ledger, fingerprints);
   SHA-256 appears only as the content-address form for genomes
   (`prefixed_sha256`, RFC 0010) and evidence-zip member digests. Choosing
   SHA-256 for the ledger would be the divergent choice RFC 0010 explicitly
   avoids → **Q2** is a confirmation, with FIPS legibility handled in docs.

5. **This workspace has no async pipeline today.** tokio 1.40 is a workspace
   dep but there is zero `tokio::spawn`, zero mpsc/bounded channel usage; the
   CLI is synchronous and bridges async via per-call `Runtime::new().block_on`
   (~15 sites in `commands.rs`). Phase 2's background workers introduce the
   first long-lived concurrent pipeline in the workspace — the design must own
   its runtime/threads rather than assume one exists (§5.3).

6. **No sqlx, no DB anywhere in this workspace.** Storage is files +
   `agenomic-fs::write_atomic` + 0600 secret mode. The prompt's "DB-backed
   store only if existing sqlx patterns make it cheap" resolves to: **no DB
   store in v1** (sqlx lives only in agenomic-cloud, which is out of scope).

7. **`NotYetAvailable` is a documentation convention, not a type.** Grep finds
   zero Rust occurrences; the in-code pattern is a fail-closed
   `CliError` variant with a stable `code(...)`, a `help(...)` pointing at
   `docs/BACKEND_GAPS.md`, and a reserved exit code
   (`crates/agenomic-core/src/{error,exit}.rs`). The exit-code catalog is a
   stable public contract, currently ending at 18 → the ledger reserves **19**.

8. **The golden `.atep` fixture is real but narrower than the prompt claims.**
   Exactly one exists: `agenomic-python/tests/fixtures/golden_atep_segments/
   golden_v1.atep` (+ `golden_pub.pem`), asserted readable by python/cli/cloud.
   Nothing in this repo reads it today. The ledger **never touches the ATEP
   wire format** (entries reference ATEP events by hash; they do not re-encode
   them), so the fixture stays byte-identical by construction. See §3.2 for a
   pre-existing python divergence discovered during recon (not self-resolved).

9. **The open-core boundary is already written down.** `agenomic/AGENTS.md`
   (superproject) defines three layers: open standard (spec/schemas), open
   tools (this CLI, SDKs, local replay/diff), paid platform (cloud registry,
   distributed replay, **signed attestations**, **AI Act evidence packs**,
   RBAC/SSO, approvals). Crucially, *local* signing is already open source
   (release attestations, ATEP event signing) — so "signed attestations" in the
   paid layer means the *hosted/KMS/org-managed* trust service, not the act of
   signing locally. This makes the prompt's proposed cut line consistent with
   shipped precedent → **Q0**.

10. **Statistical-replay language discipline is already enforced in code.**
    `agenomic-replay-local` is deterministic contract-checking over stored
    traces, mode `"deterministic_offline"`, and emits an explicit note that
    statistical replay across LLM stochasticity is a cloud/adapter concern
    (`lib.rs:100-112`). RFC 0010's replay taxonomy and the "simulation, non
    probant" rule are normative. The ledger proves provenance/integrity of
    recorded events only; all ledger docs/reports will use that framing and
    never claim deterministic replay.

11. **The evidence proof bundle has an existing shape to align with.**
    `agenomic-cloud/crates/agenomic-evidence-package` is a *pure, offline
    verifiable* signed-zip format with canonical members (`event_ledger.jsonl`,
    `run_seal.json`, `ledger_verification.json`, …), manifest signed per RFC
    0008 (`ed25519(blake3(JCS(manifest∖signature)))`), probative vs
    "simulation, non probant" status, and a legal notice. The prompt's §5.10
    file list overlaps but does not match member-for-member — the plan aligns
    names with the existing format and adds only what's missing (§7).

12. **Idempotency + conflict semantics have a cloud precedent to mirror.**
    Stripe-style idempotency keys (`agenomic-idempotency`), `UNIQUE(org, run,
    seq)` + `UNIQUE(org, run, event_hash)` constraints, append-only WORM
    triggers, and dedup-on-`event_id` ingest in tracking
    (`agenomic-tracking/src/service.rs:90-175`). The local pipeline adopts the
    same rules (§5.4) so a future cloud sync has no impedance mismatch.

---

## 1. Target workspace and dependency position (confirmation)

**Target: `treansai/agenomic-cli`** — the open-source, offline-first Rust
workspace. Rationale: the ledger's producers all live here (`agenomic-track`,
`agenomic-governance` via CLI, `agenomic-replay-local`, `agenomic-atep`); the
product guarantees (offline verification, no network in any command) are this
repo's stated invariants (`AGENTS.md` §Product invariants); and the monetized
side (agenomic-cloud) already has its own server ledger that a follow-up prompt
extends. agenomic-cloud, agenomic-web, and both SDKs receive **no changes** in
Phases 1–5 (seams documented in §8).

Dependency position (all arrows = "depends on"):

```
agenomic-core ← agenomic-fs ← agenomic-hash
                     ↑
        NEW LEDGER CRATE  → agenomic-core, agenomic-fs, agenomic-hash,
                            agenomic-atep (keys + event types only)
agenomic-track      —(no new dep; conversion lives in ledger crate)
agenomic-cli        → NEW LEDGER CRATE (commands + integrations)
```

The ledger crate must **not** be depended on by `agenomic-atep`, `-track`,
`-governance`, or `-replay-local` (no cycles; producers stay ledger-unaware).
All conversions (`TrackingEvent/AtepEvent/GovernanceEventDescriptor/
ReplayReport → LedgerEntry`) live in the ledger crate behind small `From`/
`TryFrom` impls; the CLI wires producers to the ledger exactly the way
`emit_governance_events` wires governance to ATEP today (`commands.rs:1191`).

---

## 2. Arbitration answers (ALL need sign-off; none self-resolved)

### Q0 — Open-core boundary → recommend: local ledger fully open; hosted trust services monetized ✅ most important decision

Proposed cut, consistent with `agenomic/AGENTS.md` and shipped precedent
(local attestation signing is already Apache-2.0):

**Open source (this repo, Phases 1–5):**
- Ledger entry model, canonicalization, hashing, global + per-run chains.
- Ed25519 signing with **local file keystore**, key generate/rotate/revoke,
  historical verification after rotation.
- Durable queue + WAL + dead-letter + recovery. Latency modes except
  `strict_cloud`.
- Blocks, Merkle roots, the full offline verification engine and report.
- `agenomic ledger …` CLI, tracking/governance/replay integrations.
- The **proof-bundle format** (§7): pure, offline-verifiable, aligned with
  `agenomic-evidence-package` — format and verifier are open.

**Monetized (agenomic-cloud, follow-up prompts; honest stubs here):**
- Cloud-managed/KMS keys (Scaleway Key Manager, org key custody, RLS).
- Hosted ingestion (`strict_cloud`, `cloud_sync`), hosted verification,
  retention/SLA, dashboards (agenomic-web).
- **Evidence-pack assembly as a service**: probative packs signed with
  org-custody KMS keys, compliance projections (Article 9/11/12/14), the
  "probative" status itself (locally assembled bundles are technically
  verifiable but carry the existing legal notice; the cloud service is what
  produces org-attested packs). This matches
  `agenomic-evidence-package-service`'s fail-closed-without-KMS design.

Adoption logic: the open local ledger is the demand generator (anyone can
verify offline, for free, forever); the paid layer sells custody, hosting,
retention, and compliance workflow — not the math.

### Q1 — Crate name → recommend: **`agenomic-ledger-local`**

- `atep-ledger` (prompt suggestion): ✗ violates the `agenomic-*` convention,
  and understates scope (the ledger records tracking/governance/replay events,
  not only ATEP).
- `agenomic-ledger`: matches convention but **collides with the existing
  `agenomic-cloud/crates/agenomic-ledger`**. The org does tolerate same-name
  crates across the two workspaces (`agenomic-core`, `-attestation`, `-config`,
  `-policy` exist in both), but those are same-role ports; here the two crates
  would be *different components* under one name, and neither workspace sets
  `publish = false`, so a future crates.io publish collides.
- **`agenomic-ledger-local`** ✅: mirrors the established cloud/local pairing
  precedent exactly — `agenomic-replay` (cloud) vs `agenomic-replay-local`
  (CLI), `agenomic-tracking` (cloud) vs `agenomic-track` (CLI). Unambiguous,
  publishable, self-describing.

CLI surface is unaffected by the crate name: `agenomic ledger …`.

### Q2 — Hash algorithm → recommend: **BLAKE3** (repo convention; not actually open)

BLAKE3 with the platform's `blake3:` string-prefix form and a new domain
separator `b"AGENOMIC-LEDGER-ENTRY-v1\0"` (pattern:
`AGENOMIC-TRACK-EVENT-v1\0`). Block Merkle roots reuse the RFC 0002/0010
`blake3-merkle-v1` construction with index-bound leaves (port of
`agenomic-canonical::merkle_root`). SHA-256 would be the divergent digest RFC
0010 explicitly rejects; auditor/FIPS legibility is addressed in
`docs/atep-ledger.md` (algorithm identifiers recorded on every entry via
`hash_algorithm`, enabling future algorithm agility without a format break).

### Q3 — Canonical serialization → recommend: **canonical JSON (RFC 8785/JCS), ported from `agenomic-canonical`**

The ledger entry is a JSON-native envelope over heterogeneous producers
(TrackingEvent, governance descriptors, replay reports are all serde-JSON;
ATEP events are referenced by `causal_hash`, never re-encoded). Choosing JCS:

- Reuses a **normative, already-written spec** (RFC 0010) and an existing
  byte-compatible Rust implementation
  (`agenomic-cloud/crates/agenomic-canonical/src/lib.rs`) plus its JS reference
  (`agenomic-spec/scripts/trace-crypto.js`) — offline verifiers in
  Python/TS/JS become trivial, which serves Q0's adoption goal.
- Converges the local ledger with the cloud run-trace ledger for the future
  sync path (same `event_hash` discipline, same genesis constant shape).
- CBOR-over-ordered-structs (the ATEP precedent) is the alternative: faster,
  binary, but couples entry hashing to Rust struct order and has no in-repo
  JSON-side verifier story.

Mechanics: port the needed functions (`canonical_json`, `prefixed_blake3`,
`merkle_root`, genesis constant) into the new crate as a `canonical` module,
with proptest cross-checks against the vendored test vectors from
`agenomic-canonical`'s test suite. (A shared published crate is desirable but
cross-repo extraction is out of scope for this prompt; the module is written so
it can be lifted verbatim later. Flagged in §8.)

Numbers rule (from `agenomic-canonical`): hashed surfaces carry no non-integer
floats; payloads are committed by `payload_hash`, never hashed inline.

### Q4 — `payload_storage_mode` default → recommend: **`hash_only`**

- Default `hash_only`: the entry stores `event_payload_hash` only — exactly the
  cloud ledger's row discipline ("the full payload never lives in the ledger
  row", `evidence.rs:1-16`). An immutable structure containing no personal data
  has no GDPR Art. 17 conflict; proof-of-existence without content disclosure
  works because signatures cover the canonical entry (which contains the hash,
  not the payload).
- `redacted_preview`: **opt-in**, with a documented caveat that previews of
  agent inputs/outputs may embed personal data into an append-only structure,
  and that redaction runs *before* preview storage and *before* signing.
- `encrypted_full_payload` (crypto-shredding: per-run payload keys, erasure =
  key deletion): **deferred to a follow-up**, with the storage-mode enum and
  entry fields designed now so it slots in without a schema break. Rationale:
  correct per-subject key management is its own design (key derivation,
  shred audit events, interaction with cloud sync) and doing it half-way in v1
  is worse than hash-only. Documented as a known limitation + BACKEND_GAPS
  entry.

### Q5 — Per-turn chains in v1 → recommend: **defer** (fields reserved, no third chain)

No producer has a first-class "turn" today: tracking has `agent.step.*`, ATEP
has streams + a causal DAG, the cloud ledger has per-run `seq` only. v1 ships
the global chain + per-run chain; entries carry `turn_id` and
`turn_sequence_number` (optional fields, populated when the producer supplies
them) so per-turn verification granularity is *recoverable by filtering the run
chain*, and a per-turn chain (`previous_turn_entry_hash`) can be added additively
later. A third mandatory chain in v1 buys little verification power and adds a
permanent format obligation.

### Q6 — `strict_cloud` → recommend: **yes, fail-closed `NotYetAvailable` stub**

No cloud API exists for this ledger's entries (`POST /v1/atep/segments` is
SDK-side only and unbacked; `POST /v1/runs/:run_id/events` is the RFC 0010
run-trace surface, not a LedgerEntry batch ingest). Per repo convention:
selecting `ledger_mode = strict_cloud` (or `cloud_sync_enabled = true`) fails
closed with a miette diagnostic (stable code `agenomic::ledger::cloud_unavailable`,
help pointing at `docs/BACKEND_GAPS.md`), and a new BACKEND_GAPS entry lists the
required cloud surfaces (batch ingest, chain query, verify, dead-letter replay,
key rotation, public-key export). The `cloud_sync_pending`/`cloud_synced`
durability states exist in the state machine from day one; no silent downgrade —
strict modes never degrade to a weaker mode.

### Q7 — Scaleway Key Manager → recommend: **follow-up, not v1**

v1 floor is the local file keystore (§5.2): Ed25519 PKCS#8 PEM, 0600, atomic
writes — extending the existing `agenomic-atep/src/keys.rs` primitives with a
`SigningKeyStore` trait (generate/rotate/revoke/list/export-public, immutable
key-op audit events appended to the ledger itself). The trait is deliberately
shaped after `agenomic-crypto::SigningKeyStore` (cloud) so the KMS-backed
implementation lands in the cloud follow-up without touching call sites. CLI
KMS signing without the cloud auth/tenancy stack would be a mock — exactly what
BACKEND_GAPS forbids.

### Q8 — Default on-disk location → recommend: **project-local `.agenomic/ledger/` for data; `~/.config/agenomic/keys/` for keys**

- Data (WAL segments, ledger store, blocks, dead-letter):
  `<project>/.agenomic/ledger/`. Precedent: tracking already defaults to
  `.agenomic/tracking` (`agenomic-track/src/store.rs:176`), and `.agenomic/` is
  in `DEFAULT_EXCLUDES` (`agenomic-fs/src/walk.rs:25`) so ledger state can
  never pollute bundle hashes — for free.
- Keys: `~/.config/agenomic/keys/` (via the existing `directories` config-dir
  convention, mode 0600), because signing keys are user-scoped, not
  project-scoped, and `AGENTS.md` security defaults already exclude `*.pem`,
  `*.key` from bundles. Both overridable via config/flags (§6).

---

## 3. Contradictions and pre-existing issues surfaced (NOT self-resolved)

1. **Prompt vs repo — co-signature gap.** The prompt states BACKEND_GAPS tracks
   "co-signature and adversarial-critique storage" gaps. The actual
   `docs/BACKEND_GAPS.md` has **no co-signature entry** and no co-signature
   feature exists in any repo (grep: zero hits for co-sign/cosign/multisig/
   threshold). The adversarial-critique *cloud storage* gap does exist
   (Gap 5 → `agenomic-web/BACKEND_GAPS.md`, `AdversarialReview` entity).
   Handling: ledger entry signatures are specified as single-signer detached
   signatures, structurally distinct from any future co-signature feature; if a
   co-signature spec exists elsewhere, please point to it at sign-off.
2. **Golden fixture byte-compat is currently broken — upstream of us.** The
   Python ATEP implementation diverges from RFC 0003/0002 as written: 8-byte LE
   body-length prefix in the causal hash (RFC says `u32_le`), and a
   non-domain-separated segment Merkle root (`agenomic-python/src/agenomic/
   atep/{event.py:78-109, segment.py:44-52}`). This plan **does not touch** ATEP
   or the fixture (blocking-arbitration rule respected); flagged because the
   prompt calls byte-for-byte compatibility a hard constraint and someone
   should own reconciling it.
3. **Prompt §5.8 event names vs shipped registries.** Three vocabularies exist:
   tracking (`agent.step.*` not `agent.turn.*`; no `tracking.session.*`,
   `notification.sent`, `replay.*`, `evidence.exported` today —
   `agenomic-track/src/event.rs:20-56`), the cloud/RFC 0010 registry
   (`llm.*`, `tool.call.proposed/approved/blocked/...`), and governance ATEP
   descriptors (`governance.cluster_detected/...` vs the prompt's
   `log_ingestion.normalized`-style names). Plan: the ledger records producers'
   **existing** event types verbatim (it extends, never renames); the prompt's
   missing event types (`agent.turn.*`, `tracking.session.*`, `replay.*`,
   `evidence.exported`, `notification.sent`, and the prompt's governance list)
   are introduced only where a Phase 5 integration genuinely emits them, and
   any addition to the tracking vocabulary is proposed at the Phase 5 gate —
   not silently invented in Phase 1.
4. **Prompt toolchain vs workspace reality.** "tokio + bounded channels" is
   fine (tokio 1.40 is a workspace dep) but the workspace has no long-lived
   async today; §5.3 specifies how the pipeline owns its runtime. "criterion
   only if the repo has the pattern" → repo has **no** criterion → no benches
   in v1 (latency targets asserted via integration tests with generous CI-safe
   bounds, plus a dropped-events==0 load test).
5. **`agenomic evidence` CLI does not exist.** Phase 5's
   `agenomic evidence export --include-ledger` is a new top-level command
   family. Per Q0 it ships the open **format assembly** locally (with the
   existing legal notice and non-probative framing for locally-signed packs);
   probative org-attested packs remain the cloud service.

---

## 4. Reuse inventory (no new event universe)

| Existing type/code | Where | Reuse in ledger |
|---|---|---|
| `TrackingEvent`, `TrackingEventType`, `Alert` | `agenomic-track/src/{event,alert}.rs` | Producer. `LedgerEntry::from_tracking(&TrackingEvent)` — maps `event_id`, `session_id`, seq, hashes; payload committed by hash of the canonical tracking event JSON. |
| `AtepEvent` (header, causal_hash, attestation) | `agenomic-atep/src/event.rs` | Producer. Entry references `causal_hash` as `event_payload_hash` (`atep:` provenance recorded in `ingestion_source`); ATEP bytes never re-encoded. |
| `GovernanceEventDescriptor` | `agenomic-governance/src/events.rs` | Producer. Same pattern as `emit_governance_events` (CLI-side wiring). |
| `ReplayReport`, `TraceEnvelope` | `agenomic-replay-local/src/lib.rs` | Producer (`replay.started/completed` entries carry `report_hash`); replay-from-ledger reads back tracking/ATEP-sourced entries. |
| Ed25519 key load/save/gen, `short_key_id` | `agenomic-atep/src/keys.rs` | Reused directly by the file keystore; rotation/revocation added on top. |
| Segment WAL pattern (framing, CRC32, Merkle, magic+tail) | `agenomic-atep/src/segment.rs` | Design template for the ledger WAL (§5.3) — same durability tricks, new format (entries aren't AtepEvents). |
| `canonical_json`, `event_hash`, `merkle_root`, genesis constant | `agenomic-cloud/crates/agenomic-canonical` (port) | Ported `canonical` module (Q3), with vendored test vectors. |
| `blake3-merkle-v1` domains, odd-node duplication | `agenomic-hash/src/merkle.rs` + RFC 0002 | Block Merkle roots (index-bound leaf variant per RFC 0010). |
| `write_atomic`, `set_secret_mode` | `agenomic-fs/src/atomic.rs` | All manifest/key/store writes. |
| `CliError` + stable codes + `ExitCode` catalog | `agenomic-core/src/{error,exit}.rs` | New variants; reserve exit **19 = LedgerIntegrityFailed**. |
| `Renderable`, render pipeline, `OutputFormat` | `agenomic-report`, `agenomic-cli/src/render.rs` | All `agenomic ledger` outputs (human + json/yaml). |
| Idempotency/conflict semantics | `agenomic-cloud/crates/agenomic-idempotency`, tracking ingest, WORM migration | Rules mirrored locally (§5.4) for future sync compatibility. |
| Evidence-package member set + RFC 0008 manifest signing | `agenomic-cloud/crates/agenomic-evidence-package` | Proof-bundle format alignment (§7). |
| `ReleaseAttestation.atep_root_hash` pattern | `agenomic-attestation/src/lib.rs` | Tracking report ledger-proof block mirrors this shape. |

Explicit non-goals: no new tracking/governance event structs, no ATEP schema
changes, no changes to `agenomic-track`'s store, no touching the golden
fixture.

---

## 5. Design sketch

### 5.1 Crate layout (`crates/agenomic-ledger-local`)

```
src/
├── lib.rs          // public API, crate docs, feature flags
├── entry.rs        // LedgerEntry, DurabilityStatus, VerificationStatus, ids
├── canonical.rs    // JCS port + entry_hash + domain separators (Q3)
├── convert.rs      // From TrackingEvent / AtepEvent / GovernanceEventDescriptor / ReplayReport
├── chain.rs        // global + per-run chain state, genesis, link rules
├── keystore.rs     // SigningKeyStore trait, FileKeyStore, rotate/revoke, key-op audit entries
├── store.rs        // LedgerStore trait, MemoryLedgerStore, FileLedgerStore
├── wal.rs          // append-only segments, CRC32, rotation, corruption detection, recovery
├── pipeline.rs     // hot path enqueue, workers, retry, dead-letter, backpressure, flush, modes
├── block.rs        // sealing policy (max entries / max age / flush / run-complete / shutdown), Merkle
├── verify.rs       // verification engine + structured VerificationReport (§5.9 of prompt)
├── proof.rs        // offline proof-bundle format (writer + verifier)
└── config.rs       // LedgerConfig (defaults per prompt §5.6, Q4/Q8 resolutions)
```

Entry fields as prompt §5.1 with these repo-grounded specifics:
`ledger_entry_id` = ULID (repo convention); `tenant_id/workspace_id` omitted in
v1 (single-tenant local; field reserved, tenant isolation = distinct store
roots + distinct keys); `genome_hash` = the existing `blake3-merkle-v1:` bundle
form; hashes `blake3:`-prefixed; signature = detached Ed25519 over
`blake3(AGENOMIC-LEDGER-ENTRY-v1\0 ‖ canonical_json(entry ∖ {signature, durability_status, verification_status}))`,
hex-encoded with `signing_key_id = ed25519:<8hex>` (ATEP conventions).
Mutable operational fields (`durability_status`, `verification_status`) are
excluded from the signed surface so state-machine progress never invalidates a
signature.

### 5.2 Keys

`FileKeyStore` at `~/.config/agenomic/keys/` (Q8): `ledger-<keyid>.pem` +
`.pub` + a `keys-manifest.json` (active key, rotation history, revocations)
written atomically. Rotation keeps old public keys resolvable forever
(historical verification); revocation marks keys untrusted-after-timestamp and
surfaces in verification reports. Every generate/rotate/revoke appends a
`ledger.key.*` entry to the ledger itself (immutable key-op audit trail).
Private keys never appear in logs/reports/errors (`secrecy` where held in
memory; existing 0600 + atomic-write discipline).

### 5.3 Ingestion pipeline (Phase 2)

Hot path (caller thread, sync, allocation-light): minimal envelope validation →
assign `event_id` (ULID) if missing → `try_send` on a **bounded**
`tokio::sync::mpsc` channel →<br>
— `best_effort_low_latency`: return;<br>
— `durable_low_latency` (default): WAL append + fsync-batched ack, then return;<br>
— `strict_verified`: wait for signed ledger append.<br>
Backpressure: bounded queue full ⇒ spill to WAL-backed disk queue up to
`queue_max_disk_bytes`; beyond that, explicit `LedgerBusy` failure state
(caller-visible, never a silent drop; in default mode the *agent* still
proceeds — the failure is recorded and surfaced in status/health, satisfying
both non-negotiables).

Workers: the `LedgerPipeline` handle owns either a dedicated
`tokio::runtime::Runtime` (multi-thread, small) or is constructed inside the
CLI's existing `block_on` bridges — decided at Phase 2 gate with a working
spike; the crate API is runtime-agnostic (`start(config) -> LedgerHandle`,
`LedgerHandle::{append, flush, shutdown, status}`). Stages: canonicalize → full
schema validation → hash+chain-link (single sequencer task per store: chain
linking is inherently serial — this is where strict per-run ordering is
enforced) → sign (batched) → persist → (cloud sync: Q6 stub). Retry worker with
capped exponential backoff; dead-letter store (`.agenomic/ledger/dead-letter/`)
with `agenomic ledger queue dead-letter list|replay`; idempotency per §5.4;
flush-on-shutdown; WAL replay on startup (idempotent by `event_id`+hash);
health/status snapshot (`agenomic ledger status`).

Durability state machine exactly as prompt §5.2, exposed via status APIs and
entry metadata.

WAL: length-prefixed frames of canonical entry bytes + per-frame CRC32,
segment header/tail magic, segment rotation by size/age, per-segment hash
chain + Merkle root (template: `agenomic-atep/src/segment.rs`), corruption
detection on open, truncated-tail recovery (keep good prefix, quarantine the
rest — never silently discard), optional zstd (workspace already ships zstd
for bundles; default off).

### 5.4 Idempotency / ordering (prompt §5.3, grounded)

Same `event_id` + same canonical hash → idempotent success (tracking-ingest
precedent). Same `event_id` + different hash → conflict entry-pair flagged,
first write wins, never overwritten (mirrors `UNIQUE(...event_hash)`
discipline). Sequence conflicts and gaps recorded and surfaced by `verify`;
out-of-order arrivals accepted, reordered by producer sequence where possible
inside the sequencer stage, gaps marked; history never rewritten.

### 5.5 CLI (Phase 4)

`LedgerCommand`/`LedgerSub` wrapper enum per house pattern (`cli.rs`), handlers
in a new `src/ledger.rs` module (precedent: `track.rs`), all outputs
`Renderable` (human + `--format json|json-pretty|yaml`), miette diagnostics
with stable `agenomic::ledger::*` codes, exit 19 on integrity failure. Full
verb set as prompt Phase 4 (`init status seal append tail verify export
inspect queue{status flush retry dead-letter{list replay}} keys{generate list
rotate export-public}`). `keys` also gains `revoke` (spec §5.5 requires the
lifecycle; prompt's verb list omits it — flagged rather than silently added:
**sign-off item**).

---

## 6. Configuration (deltas from prompt §5.6)

All keys as specified, with: `payload_storage_mode` default **`hash_only`**
(Q4; `encrypted_full_payload` variant reserved-but-rejected in v1 with a
diagnostic), `hash_algorithm` fixed `blake3` (Q2), `ledger_mode` default
`durable_low_latency`, `strict_cloud`/`cloud_sync_enabled=true` fail closed
(Q6), data root default `.agenomic/ledger` and keys root
`~/.config/agenomic/keys` (Q8). Config source: `agenomic.toml` `[ledger]`
table + env, via `agenomic-config` precedence rules.

---

## 7. Evidence proof bundle (format in core, assembly gated per Q0)

Open format module (`proof.rs`) producing a deterministic, offline-verifiable
directory/zip whose member names align with the shipped evidence-package
format first and the prompt second: `ledger_manifest.json` (RFC 0008-style
signed manifest), `run_chain.jsonl`, `atep_events.jsonl` (when ATEP-sourced),
`ledger_blocks.json`, `merkle_proofs.json`, `signatures.json`,
`public_keys.json`, `verification_report.json`, plus `replay_report.json` /
`policy_results.json` / `risk_summary.md` when the corresponding artifacts
exist (never fabricated — absent artifacts are absent, listed in the manifest
as such). Local assembly ships (open, carries the existing
`LEGAL_NOTICE`/non-probative framing for locally-signed bundles); org-attested
probative packs remain the cloud service (Q0). Verification requires no
network (test: verify on a clean tempdir with no config).

---

## 8. Integration map & seams (what exists vs honest stubs)

| Integration | Exists today | Phase 5 action |
|---|---|---|
| `agenomic track start --ledger` | tracking store + hash-linked events | Wire engine ingest → ledger append (CLI layer); session lifecycle entries. |
| `agenomic track report --include-ledger-proof` | `TrackingReport` + `report_hash` | Add ledger-proof block (root hash, run chain head, block ids, key ids, gap/queue-loss status) mirroring `atep_root_hash` precedent. |
| Governance → ledger | signed ATEP governance stream | Dual-emit: existing ATEP path untouched; ledger entries added alongside. Proposals/approvals recorded; **no approval automation** (human gate stays). |
| `agenomic replay --from-ledger <run_id>` | `--from-atep` precedent | New source: verify chain first (fail on invalid), feed entries, replay report gains ledger-proof block. Statistical framing preserved verbatim. |
| `agenomic evidence export --include-ledger` | no CLI command; cloud has pack service | New command using `proof.rs` (Q0 framing). |
| Cloud sync / `strict_cloud` | no API | `NotYetAvailable` fail-closed + BACKEND_GAPS entry (Q6). |
| Python/TS SDK surface | tracking clients only | Out of scope; seam = the JSONL export + JCS canonicalization (verifiable from any language). |
| Shared canonicalization crate | cloud-only crate | Out of scope to extract; module written lift-ready. BACKEND_GAPS note. |

New BACKEND_GAPS entries at Phase 5: cloud ledger ingestion/verification APIs;
`encrypted_full_payload` (crypto-shredding); KMS-backed keystore; SDK surfaces;
canonicalization crate extraction.

---

## 9. Phase gates & test strategy

Phases exactly as the prompt (1 core model+crypto → 2 durable pipeline → 3
blocks+Merkle+verification → 4 CLI → 5 integrations), each ending at a STOP
gate. Tests follow repo convention: proptest for canonicalization/hash/chain
determinism and WAL roundtrips; insta snapshots for verification reports and
all human output; `assert_cmd` integration tests for the CLI scenarios
(tamper-one-byte, kill-mid-ingestion recovery, disk-full via small
`queue_max_disk_bytes` fixture, duplicate/out-of-order, key rotation
mid-run, offline proof-bundle verify in clean env); zero network in any test
(wiremock only if a cloud-stub diagnostic needs exercising). No criterion
(§3.4); latency targets documented, asserted loosely in integration tests,
dropped-events==0 asserted strictly under load.

Small sequential commits, one concern per commit; `docs/atep-ledger.md`
single-page (repo docs are flat single-pagers); examples `basic-run/`,
`tamper-detection/`, `queue-recovery/` with genuinely generated outputs only.

---

## 10. Sign-off checklist (human)

- [ ] Q0 open-core cut as proposed (format open, custody/hosting/probative packs paid)
- [ ] Q1 crate name `agenomic-ledger-local`
- [ ] Q2 BLAKE3 (confirmation)
- [ ] Q3 canonical JSON (JCS port) — or direct to CBOR instead
- [ ] Q4 default `hash_only`; `redacted_preview` opt-in; crypto-shredding deferred
- [ ] Q5 per-turn chain deferred (fields reserved)
- [ ] Q6 `strict_cloud` fail-closed stub + BACKEND_GAPS
- [ ] Q7 KMS follow-up; file keystore v1
- [ ] Q8 `.agenomic/ledger` data / `~/.config/agenomic/keys` keys
- [ ] Exit code **19 = LedgerIntegrityFailed** reservation
- [ ] `keys revoke` verb addition (§5.5)
- [ ] §3 contradictions acknowledged (co-signature reference, python ATEP divergence ownership, event-name reconciliation approach)
- [ ] Explicit **"go" for Phase 1**
