# RMP · Scenario enrichment

Scenario enrichment is the edge that closes the loop: a production finding
becomes a Review artifact.

## The proposal

A `ScenarioEnrichmentProposal` carries:

* `proposal_id`, `source_finding_id`, `source_event_ids`
* `proposed_scenario` — a full `TestScenario` (source
  `monitor_derived` / `protect_derived` / `incident_derived`)
* `risk_ids`, `reason`, `expected_coverage_improvement`, `severity`
* `human_approval_required` — always true at `high`/`critical` severity
* `status` — `draft → pending_review → approved → applied` (or `rejected`)
* `created_at`, `reviewed_by`, `reviewed_at`

## Deterministic mapping

| Finding kind | Derived scenario |
|---|---|
| `loop` | loop regression scenario (bounds repeated tool calls) |
| `drift` | baseline regression check |
| `policy_violation`, `harness_violation` | policy test |
| `intent_shift`, `forbidden_intent` | intent boundary scenario |
| `failure`, `repeated_failure` | tool-failure replay fixture |
| `replay_divergence`, `low_replay_fidelity` | release validation gate |
| `missing_human_approval`, `dangerous_autonomy` | human-approval gate scenario |
| `tool_misuse`, `memory_misuse`, `suspicious_output`, `anomaly`, `unexpected_workflow_transition` | forbidden-behavior scenario |

Review-side kinds (`risk_gap`, `coverage_gap`, `regression`, …) do not
loop back — they are already Review artifacts.

## Approval workflow

Transitions are validated; skipping states is an error. Approving a
proposal that requires human approval demands a non-empty reviewer
identity, which is recorded (`reviewed_by`, `reviewed_at`) for the audit
trail. When Protect creates a proposal it writes
`rmp.scenario_enrichment.proposed`; approval and application write
`rmp.scenario_enrichment.approved` / `...applied`, and a successful
apply also writes `review.test_scenario.created` — all to the session
ledger when it was started with `--ledger`.

`apply` folds the proposal's scenario into the Review corpus
(`<store>/corpus/scenarios/<scenario_id>.json`) so the next
`agenomic rmp review` of the same bundle covers the incident. The derived
scenario's `evidence_source_refs` keep pointing at the original
production events.

## CLI

Derive proposals:

```bash
# from a live monitor session
agenomic monitor enrich-review --session <tracking-session> --output proposals.json
# from an exported findings file
agenomic rmp enrich-scenarios --from-findings findings.json --output proposals.json
```

Review and act on a bound session's proposals (the human-approval loop):

```bash
agenomic rmp proposals list    --session <rmp-session>
agenomic rmp proposals approve <proposal_id> --session <rmp-session> --reviewer <name>
agenomic rmp proposals reject  <proposal_id> --session <rmp-session> --reviewer <name>
agenomic rmp proposals apply   <proposal_id> --session <rmp-session>
```

`--reviewer` is mandatory on `approve` when the proposal is flagged
`human_approval_required` (high/critical severity). `apply` only accepts a
proposal already in `approved` state. All four commands take the standard
`--store` / `--tracking-store` flags.
