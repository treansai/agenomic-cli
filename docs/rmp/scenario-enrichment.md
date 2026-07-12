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
trail, and `rmp.scenario_enrichment.approved` / `...applied` events are
written to the ledger when enabled.

Approved proposals are folded into the scenario corpus on the next
`agenomic rmp review` pass of the same session, and the derived scenario's
`evidence_source_refs` keep pointing at the original production events.

## CLI

```bash
# derive proposals from a live session
agenomic monitor enrich-review --session <tracking-session> --output proposals.json
# derive proposals from an exported findings file
agenomic rmp enrich-scenarios --from-findings findings.json --output proposals.json
```
