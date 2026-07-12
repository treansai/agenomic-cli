# RMP · Review

Review evaluates an agent **before release, after changes, or after
incidents**. It is deterministic and offline: replay uses
`agenomic-replay-local`, contract checks use `agenomic-contract`, policy
checks use `agenomic-policy`, and no model is ever called.

## Inputs

| Input | Source |
|---|---|
| Agent genome + lockfile | the bundle (`genome.yaml`, `agent.lock.yaml`) |
| Behavior contract | `<bundle>/behavior.contract.yaml` (via replay) |
| Agent ID card / use case card | `agenomic_rmp::cards` (optional JSON) |
| Risk matrix | `--risk-matrix` file or the bundle corpus |
| Test scenarios | the bundle corpus + `--scenario` files |
| Evaluation history | prior review/monitor history entries |
| Trace fixtures | `--traces` JSONL or `<bundle>/traces/*.jsonl` |
| Carried findings | Monitor/Protect findings of the same RMP session |
| Approved enrichment proposals | the session's proposal log |

## What a pass does

1. Folds **approved** scenario enrichment proposals into the corpus.
2. Classifies the agent type (autonomy, side effects, human-in-the-loop)
   and stamps the assessment onto the risk matrix.
3. Validates and selects scenarios; marks risk coverage.
4. Flags use-case failure modes missing from the risk matrix (risk gaps).
5. Reports uncovered open risks (coverage gaps).
6. Runs deterministic replay: behavior-contract checks over trace fixtures;
   violations become findings.
7. Records carried production findings as risk observations.
8. Computes metrics (`release_risk_score`, `risk_coverage_ratio`,
   `review_score`, replay counters).
9. Detects regressions against the best recent review score in the
   evaluation history.
10. Lands on a release recommendation:

| Condition | Recommendation |
|---|---|
| any blocking finding or `fail_on` severity reached | `block` |
| risk score ≥ threshold or human-review finding | `human_review_required` |
| non-empty findings | `approve_with_conditions` |
| clean | `approve` |

## Outputs

`ReviewOutcome`: result (`pass`/`warn`/`fail`), score, release risk score,
recommendation, findings, coverage report, updated risk matrix, replay
report, metrics, required changes, and the evaluation-history entry for
this pass.

## CLI

```bash
agenomic review run ./my-agent
agenomic review run ./my-agent --scenario scenarios/payment-risk.json --traces traces/fixtures.jsonl
agenomic review scenarios list ./my-agent
agenomic review scenarios add ./my-agent --file scenario.json
agenomic review risk-matrix ./my-agent
agenomic review report --session <rmp-session>
# inside an RMP session (carries findings + proposals):
agenomic rmp review ./my-agent --session <rmp-session>
```

Exit codes: `0` pass/warn, `1` fail.

## Test scenarios

See the schema in `schemas/rmp-test-scenario.schema.json`. A scenario binds
input fixtures to expected outputs, expected tool calls, expected memory
behavior, expected intent, forbidden behaviors, policy expectations, and
metrics, and records its provenance (`manual`, `generated`,
`incident_derived`, `monitor_derived`, `protect_derived`,
`user_provided`) plus the evidence and dataset references
(`evidence_source_refs`, `dataset_refs`) that motivated it. Data-engine
generated datasets are referenced by `dataset_refs`; generation itself is
a cloud capability.
