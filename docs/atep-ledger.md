# Cryptographic event ledger

The ledger is a **private, append-only, tamper-evident hash chain** for
Agenomic runtime and governance events — a blockchain-style structure, not a
blockchain: no consensus, no distribution, no tokens. It *extends* the
existing event types (tracking, governance, ATEP, replay); it never mutates
or re-encodes them.

Two non-negotiable guarantees:

1. **No event loss.** Every accepted event reaches a durable state or an
   explicit, visible failure state (dead-letter). Silent drops are forbidden
   and disproved by tests (`received == sum of explicit outcomes`).
2. **Agents are never blocked by default.** The hot path returns after a
   local fsync'd WAL append; blocking exists only in the explicitly
   configured strict mode.

Design contract: [`docs/plans/atep-ledger-plan.md`](plans/atep-ledger-plan.md)
(Phase 0, signed off). Crate: `crates/agenomic-ledger-local`.

## Architecture

```
producer (track / governance / replay / CLI)
   │  draft (payload → blake3 hash; raw content never travels further)
   ▼
hot path: validate → assign event_id → dedup/conflict → WAL append (fsync)
   │                                        │ queue full → WAL backlog
   ▼                                        ▼ (order preserved)
bounded queue ──► sealer worker: canonicalize → hash → sign → append
                                        │
                                        ├── ledger.jsonl   (signed entries)
                                        ├── blocks.jsonl   (signed Merkle blocks)
                                        └── dead-letter/   (explicit failures)
```

On-disk layout (defaults; see `agenomic ledger --help` for overrides):
`.agenomic/ledger/{store,wal,dead-letter,blocks.jsonl}` for data,
`~/.config/agenomic/keys/` for Ed25519 keys (PKCS#8 PEM, mode 0600).

## Cryptography

- **Canonicalization**: RFC 8785-flavoured canonical JSON (UTF-16 key sort,
  ECMAScript number rendering) — a byte-compatible port of the platform's
  canonical run-trace reference (RFC 0010). Never hash non-canonical JSON.
- **Hashing**: BLAKE3 everywhere (`blake3:<hex>`), domain-separated:
  `AGENOMIC-LEDGER-ENTRY-v1\0` (entries), `AGENOMIC-LEDGER-BLOCK-v1\0`
  (blocks), `AGENOMIC-LEDGER-PROOF-v1\0` (proof manifests). Block Merkle
  roots use the RFC 0002/0010 `blake3-merkle-v1` construction.
- **Signatures**: detached Ed25519 over the 32-byte digest ("sign the hash,
  not the body" — the ATEP rule). The signed surface excludes only the
  volatile fields (`entry_hash`, `signature`, durability/verification
  status) and *includes* `signing_key_id`, so key substitution breaks the
  hash.
- **Chains**: every entry links `previous_entry_hash` (global) and
  `previous_run_entry_hash` (per run). Blocks chain via
  `previous_block_hash`. Per-turn chains are deferred (fields reserved).
- **Payloads are hash-committed** (`hash_only`, the GDPR-safe default): the
  ledger stores `event_payload_hash`, never content. Signatures stay
  verifiable when the payload is absent — proof of existence without
  disclosure.
- **Keys**: generate / rotate / revoke via `agenomic ledger keys`. Rotated
  keys verify history forever; revoked keys *flag* (never silently fail)
  verification; the active key cannot be revoked. Private keys never appear
  in logs, reports, or errors.

## Queue, durability, and recovery

Durability states: `received → queued → wal_persisted → … → ledger_appended`
(terminal failures: `failed`, `dead_lettered`; cloud states are reserved —
see `docs/BACKEND_GAPS.md`). The WAL is the spool: CRC-framed segments,
size rotation, checkpointed applied-watermark. On startup, records above
the checkpoint replay idempotently (dedup by `event_id` + payload hash), a
torn tail is truncated and reported, and corrupt segments are quarantined
as `.corrupt` — preserved, never deleted. The disk budget refuses
explicitly (`agenomic::ledger::busy`), it never loses data.

Idempotency: same `event_id` + same payload hash → idempotent success; same
`event_id` + different hash → conflict, dead-lettered with a tampering
warning, the original never overwritten.

## Latency modes

| Mode | `append` returns after | Notes |
|---|---|---|
| `best_effort_low_latency` | in-memory enqueue | dev only; full queue = explicit refusal |
| `durable_low_latency` (default) | fsync'd WAL append | production default |
| `strict_verified` | signed ledger append | synchronous, high assurance |
| `strict_cloud` | — | **fails closed** (`agenomic::ledger::cloud_unavailable`); no silent downgrade |

## Verification

`agenomic ledger verify` runs the full engine offline: entry hashes and
signatures, chain wiring, sequence gaps (missing events), duplicates,
conflicting event ids, block hash/signature/Merkle/coverage, key status,
and WAL health — with a structured report, the first invalid sequence, and
recommendations. Exit 19 (`LedgerIntegrityFailed`) on failure. Gaps are
*reported*, never papered over: the ledger never rewrites history.

## Integrations

- `agenomic track start --ledger` binds a tracking session: the session
  lifecycle and every ingested event are appended (committed by the
  tracking chain's own `event_hash`). `agenomic track report
  --include-ledger-proof` attaches the proof block (root hash, run chain
  head, block ids, key ids, verification/gap/queue-loss status) and the
  report hash covers it.
- `agenomic governance … --ledger` dual-emits engine results to the ledger
  alongside the signed ATEP `governance` stream — never instead of it. The
  ledger *records* proposals and critiques; approval remains a human act.
- `agenomic replay … --from-ledger <run>` verifies the run's chain **before**
  replaying (exit 19 on failure) and attaches the ledger proof to the
  replay report. The ledger proves *provenance and integrity* of the
  recorded events; replay itself remains statistical — the ledger does not
  and cannot make replay deterministic.
- `agenomic evidence export --include-ledger` assembles the offline
  proof bundle (signed manifest, chain, blocks, Merkle data, signatures,
  public keys, verification report); `agenomic evidence verify` re-checks
  it on a clean machine with nothing but the bundle directory.

## Security limitations (read before relying on this)

- **Local keys sign locally.** Whoever controls the machine controls the
  active key: the ledger detects *tampering after the fact*, it cannot stop
  an attacker with the private key from writing a consistent forged chain
  going forward. Rotation limits the blast radius; hosted/KMS custody is
  the trust upgrade (see `docs/BACKEND_GAPS.md`).
- **Locally-assembled evidence bundles are non-probative** and carry the
  platform legal notice. Org-attested probative packs are a hosted-service
  concern.
- **Hash-only payloads prove existence, not content.** Auditors verify that
  a specific payload existed; recovering the content requires the producer
  side to retain it.
- `redacted_payload_preview` is opt-in and puts (potentially personal) data
  into an append-only structure — read the GDPR caveat in the plan before
  enabling it. `encrypted_full_payload` (crypto-shredding) is a tracked
  follow-up.

Examples with genuinely generated outputs: [`examples/ledger/`](../examples/ledger/).
