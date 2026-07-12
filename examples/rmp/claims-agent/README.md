# RMP context for the claims agent

RMP-side context cards for the `examples/claims-agent` bundle: who the
agent is, what it is deployed for, and its typed risk register.

* `agent-id-card.json` — identity, allowed tools, forbidden actions,
  autonomy, approval requirements.
* `use-case-card.json` — the deployed use case, expected/forbidden
  intents, success criteria, failure modes.
* `risk-matrix.json` — typed risks with likelihood/impact, impact
  drivers, and associated risks.

Seed a bundle's corpus with the matrix:

```bash
agenomic review run ../../claims-agent --risk-matrix risk-matrix.json
```
