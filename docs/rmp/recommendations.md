# RMP · Recommendations

A recommendation is a typed, deterministic change proposal derived from a
finding. It is **never applied automatically**.

## Kinds

`prompt_improvement`, `policy_change`, `contract_change`,
`workflow_guardrail`, `tool_permission_change`, `human_approval_gate`,
`replay_scenario`, `risk_matrix_update`, `release_rollback`,
`monitoring_threshold_update`, `harness_rule_update`.

## Human approval

`requires_human_approval` is set when either:

* the kind is high-impact — `policy_change`, `contract_change`,
  `tool_permission_change`, `release_rollback`, `workflow_guardrail` —
  regardless of severity, or
* the source finding is `high`/`critical`.

The status field tracks `proposed → approved/rejected → applied`;
approvals are audit-logged (ledger `protect.recommendation.created` plus
the platform's approval trail where available). There is no code path in
this crate that mutates a bundle, prompt, policy, or contract.

## Determinism

Templates map finding kinds to recommendations (see
`docs/rmp/protect.md`); identical findings produce identical
recommendations, deduplicated by `(kind, title)`. Each recommendation
carries its `source_finding_ids` and `evidence_refs`, and a plain-language
`rationale` that is always present — an optional LLM provider may add an
explanatory narrative, but never replaces the deterministic rationale.
