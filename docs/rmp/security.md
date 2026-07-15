# RMP · Security and privacy

## Deterministic by default, LLM strictly opt-in

No code path in `agenomic-rmp` calls a model. The
`SuggestionProvider` trait exists so hosts can attach LLM assistance
(intent explanation, scenario drafting, risk summaries, audit narratives,
root-cause explanation). Rules, enforced by construction:

* the default provider is a no-op; offline mode never calls out;
* providers receive **redacted** context (summaries + hashes), never raw
  production payloads or secrets;
* suggestions are advisory: they attach alongside deterministic
  rationales and evidence references, never replace them;
* high-impact changes require human approval regardless of origin.

## Secrets

* `agenomic_rmp::redact` runs on the **ledger write path** (every RMP
  event body is passed through `redact_json` in `RmpLedgerEvent::to_draft`
  before it is hash-committed) as defense in depth: sensitive key names
  (`api_key`, `token`, `password`, …) and well-known credential prefixes
  (`sk-`, `ghp_`, `xoxb-`, `agm_`, PEM headers, `Bearer `) are replaced
  with `[REDACTED]`. It over-redacts by design. `redact_json` /
  `redact_text` are also exported for callers that build report or alert
  payloads from untrusted data, but reports and alerts are **not** scanned
  automatically — they carry hash references and finding metadata rather
  than raw payloads by construction, so the redaction line is the ledger,
  not the report writer.
* Ledger payloads are committed by hash; raw payloads never travel past
  the hot path (the WAL stores hash commitments, not bodies).
* Scenario inputs may be stored as hashes (`input_hash`) instead of
  content for sensitive fixtures.

## Human approval

* High-impact recommendation kinds (policy, contract, tool permissions,
  rollback, workflow guardrails) always require approval.
* High/critical scenario enrichment proposals require a recorded reviewer
  identity; the state machine rejects skipped transitions.
* Critical action-plan containment steps require approval.
* Approvals are recorded (reviewer, timestamp) and, when the ledger is
  enabled, written as `rmp.scenario_enrichment.approved` events.

## No silent weakening, no silent mutation

* RMP never edits bundles, prompts, policies, contracts, thresholds, or
  harness rules — it proposes.
* Historical records are append-only: findings and proposals are JSONL
  appends; proposal status changes append a superseding record; ledger
  entries are immutable and hash-chained.
* Detection/queue failures are explicit (`LedgerBusy`, dead-letter
  records) — nothing is dropped silently.

## Tenancy and permissions

The OSS CLI is single-operator and local: approval is enforced in-process
(`agenomic rmp proposals approve` requires a reviewer identity for
high/critical proposals) and there is no per-user RBAC.

Cloud status (as of this release): the **Monitor** phase is served by
Agenomic Cloud's live-tracking endpoints (`/v1/tracking/*`, plus
`/v1/agents/:id/drift`), which sit behind the platform auth stack —
org-scoped rows with row-level security, RBAC, idempotency keys, and audit
logs. Dedicated `/v1/rmp`, `/v1/review`, and `/v1/protect` endpoints
(session CRUD, scenario/proposal approval, alert routing, evidence export)
are **not yet implemented**; those flows run through the CLI today. See the
follow-up TODOs in `docs/review-monitor-protect.md`.

## Known limitations

* Local evidence proves integrity (nothing changed after recording), not
  provenance (who recorded it) — org-attested packs are a hosted feature.
* Secret detection is heuristic; use redaction hooks upstream for
  domain-specific secrets.
* Notification transports are not part of the OSS CLI; routing is
  recorded and left to integrations.
