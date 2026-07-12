# RMP · Protect

Protect consumes findings (from Monitor, Review, and governance agents)
and produces operator-facing artifacts: alerts, recommendations, action
plans, and audit evidence. It is fully deterministic — the same findings
always produce the same outputs — and it never mutates a bundle, policy,
or contract.

## Anomaly detection

On top of the per-event detectors, Protect derives session-level anomalies:

| Pattern | Finding |
|---|---|
| ≥ N failure/harness findings in one session | `repeated_failure` (high) |
| critical finding awaiting human review | `missing_human_approval` (critical) |
| intent/policy findings on a high-autonomy agent with no human in the loop | `dangerous_autonomy` (critical) |

The risk matrix's agent-type assessment feeds the autonomy check.

## Alerts

Findings are grouped by a stable dedup key (`kind:agent:title`):

* **Deduplication** — N identical findings become one alert with
  `occurrence_count = N`.
* **Grouping** — the alert carries all folded finding ids and the union of
  their evidence references.
* **Throttling** — occurrences beyond the limit (default 3) mark the alert
  `throttled`; it is recorded but not re-notified.
* **Escalation** — alerts at/above the escalation severity (default
  critical) are flagged `escalated`.
* **Routing** — ordered rules match finding kind + minimum severity to a
  team/channel; unmatched alerts go to the default route. See
  `docs/rmp/alerts.md`.

## Recommendations

Deterministic templates map finding kinds to typed recommendations
(prompt improvement, policy change, contract change, workflow guardrail,
tool permission change, human approval gate, replay scenario, risk matrix
update, release rollback, monitoring threshold update, harness rule
update). **High-impact kinds always require human approval** — see
`docs/rmp/recommendations.md`.

## Action plans

Every high-severity alert gets an ordered plan:
`investigate → (mitigate) → remediate → verify → document`. Critical plans
include a containment step that itself requires human approval. Steps
reference the recommendations they apply, and plans carry the scenario
enrichment proposals derived from the same findings.

## Ledger events

When ledger-bound: `protect.anomaly.detected`, `protect.alert.created`,
`protect.notification.routed`, `protect.recommendation.created`,
`protect.action_plan.created`, `protect.evidence.exported`.

## CLI

```bash
agenomic protect alerts --session <rmp-session>
agenomic protect action-plan --alert <alert-id> --session <rmp-session>
agenomic protect recommendations --session <rmp-session>
agenomic protect notify --alert <alert-id> --session <rmp-session>
agenomic rmp protect --session <rmp-session>     # (re)run the stage
```

`protect notify` resolves and records the routing; actual transport
(Slack/e-mail/PagerDuty) is an integration concern of the hosting
platform, not the offline CLI.
