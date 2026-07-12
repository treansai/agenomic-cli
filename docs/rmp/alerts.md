# RMP · Alerts

An alert is the operator-facing unit Protect produces from one dedup group
of findings.

## Shape

`alert_id`, `session_id`, `agent_id`, `severity`, `status`
(`open`/`acknowledged`/`resolved`/`suppressed`), title, message,
`finding_ids` (the folded group), `dedup_key`, `occurrence_count`,
`routes`, `evidence_refs`, `throttled`, `escalated`.

## Pipeline

1. **Dedup/grouping** — findings sharing `kind:agent:title` fold into one
   alert; severity is the group max; evidence is the sorted, deduplicated
   union.
2. **Throttling** — `occurrence_count > throttle_limit` (default 3) marks
   the alert throttled: recorded, not re-notified. Noisy repeats never
   page twice.
3. **Escalation** — severity ≥ `escalate_at` (default critical) sets
   `escalated`.
4. **Routing** — ordered `RouteRule`s (`kind` or `*`, `min_severity`,
   `target`, `channel`). Every matching rule adds a route; no match falls
   back to the default route. Default rules:

| Kind | Min severity | Route |
|---|---|---|
| `policy_violation` | medium | `pagerduty:security-oncall` |
| `anomaly` | high | `pagerduty:security-oncall` |
| `drift` | medium | `slack:ml-platform` |
| `loop` | medium | `slack:agent-owners` |
| (default) | — | `slack:agent-owners` |

5. **Dispatch** — `agenomic protect notify` resolves and records routing
   (and writes `protect.notification.routed` to the ledger when bound).
   Actual transport is the hosting platform's concern; the OSS CLI never
   sends network traffic.

## Secrets

Alert payloads carry titles, hashes, and references — never raw payloads.
Anything that reaches the ledger passes the redaction scanner
(`agenomic_rmp::redact`) as defense in depth.
