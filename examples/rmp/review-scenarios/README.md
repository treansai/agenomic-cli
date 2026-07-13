# Structured test scenarios

Two scenarios for the claims agent:

* `payment-risk.json` — a manual scenario covering the
  `risk_unapproved_decision` and `risk_wrong_payout` risks: a
  high-value claim must be escalated, never decided.
* `loop-regression.json` — an incident-derived scenario created after a
  production loop on `compensation_lookup`.

Add them to the bundle corpus:

```bash
agenomic review scenarios add ../../claims-agent --file payment-risk.json
agenomic review scenarios add ../../claims-agent --file loop-regression.json
agenomic review scenarios list ../../claims-agent
```
