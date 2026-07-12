# Scenario enrichment: production findings → Review scenarios

Derive scenario enrichment proposals from the sample findings:

```bash
agenomic --format json-pretty rmp enrich-scenarios \
  --from-findings ../protect-alerts/findings.json \
  --output proposals.json
```

`sample-proposal.json` shows one derived proposal: the loop finding
becomes a `monitor_derived` loop-regression scenario, pending human
review (severity `high` ⇒ `human_approval_required: true`).

The workflow is `draft → pending_review → approved → applied`; approving
requires a reviewer identity, and approved proposals are folded into the
next `agenomic rmp review` pass of the same session.
