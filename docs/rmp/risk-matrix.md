# RMP · Risk matrix

The risk matrix is the typed risk register of one agent
(`agenomic.rmp.risk-matrix/v0.1`).

## Structure

* `RiskItem` — `risk_id`, title, category, `likelihood` (0..1), `impact`
  (0..1), `impact_drivers` (weighted business/regulatory/safety drivers),
  `associated_risks` (typed relations to other risks),
  `covered_by_scenarios`, `observed_findings`, `status`
  (`open`/`mitigated`/`accepted`).
* `AgentTypeAssessment` — agent type, autonomy level, external side
  effects, human-in-the-loop. Derived deterministically from the agent ID
  card; scales the aggregate score (multiplier 1.0–2.0).

## Scoring

* Item score = `likelihood × impact`, boosted by impact-driver weights,
  clamped to 0..1. Severity bands: ≥0.7 critical, ≥0.5 high, ≥0.3 medium,
  ≥0.1 low.
* Release risk score = `0.7 × max + 0.3 × mean` over non-mitigated items,
  scaled by the assessment multiplier.
* Coverage ratio = fraction of open risks covered by ≥1 scenario.

## Lifecycle

* Review marks scenario coverage (`covered_by_scenarios`) and flags
  uncovered open risks as coverage-gap findings.
* Monitor/Protect findings mapped to `risk_ids` are recorded as
  `observed_findings` — production evidence against the risk.
* `review.risk_matrix.updated` is written to the ledger when enabled.
* Historical entries are never silently mutated: updates stamp
  `updated_at` and evidence lists only grow.

## CLI

```bash
agenomic review risk-matrix ./my-agent      # show (or initialize) the bundle's matrix
agenomic review run ./my-agent --risk-matrix risk-matrix.json
```

The bundle-scoped matrix lives at
`<bundle>/.agenomic/rmp/corpus/risk-matrix.json`; session-scoped copies are
persisted with each review outcome.
