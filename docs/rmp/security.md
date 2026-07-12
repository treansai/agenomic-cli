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

* `agenomic_rmp::redact` scans every payload headed for the ledger, a
  report, or an alert: sensitive key names (`api_key`, `token`,
  `password`, …) and well-known credential prefixes (`sk-`, `ghp_`,
  `xoxb-`, `agm_`, PEM headers, `Bearer `) are replaced with
  `[REDACTED]`. It over-redacts by design.
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

The OSS CLI is single-operator and local. In Agenomic Cloud, RMP
endpoints sit behind the platform auth stack: org-scoped rows with
row-level security, RBAC (`Viewer` read, `Maintainer` write, `Owner`
admin — approvals and evidence export require write), idempotency keys,
and audit-log entries for approvals and exports.

## Known limitations

* Local evidence proves integrity (nothing changed after recording), not
  provenance (who recorded it) — org-attested packs are a hosted feature.
* Secret detection is heuristic; use redaction hooks upstream for
  domain-specific secrets.
* Notification transports are not part of the OSS CLI; routing is
  recorded and left to integrations.
