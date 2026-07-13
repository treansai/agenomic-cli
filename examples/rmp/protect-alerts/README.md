# Protect: findings → alerts → recommendations → action plan

`findings.json` holds three monitor findings (a repeated drift and a
loop). Run them through Protect via an RMP session, or inspect the
pre-rendered sample outputs:

* `sample-alert.json` — the deduplicated, routed alert (3 occurrences of
  the same drift fold into one alert routed to `slack:ml-platform`).
* `sample-recommendation.json` — the deterministic recommendation derived
  from the loop finding (a workflow guardrail; requires human approval).
* `sample-action-plan.json` — the ordered plan generated for the alert.

```bash
agenomic rmp enrich-scenarios --from-findings findings.json   # feedback edge
agenomic protect alerts --session <rmp-session>               # live pipeline
agenomic protect action-plan --alert <alert-id> --session <rmp-session>
agenomic protect notify --alert <alert-id> --session <rmp-session>
```
