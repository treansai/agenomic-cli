# Review · Monitor · Protect — examples

End-to-end examples of the RMP loop over the `examples/claims-agent`
bundle. Each subdirectory is self-contained; the walkthrough below runs
the whole loop offline.

| Directory | Shows |
|---|---|
| `claims-agent/` | agent ID card, use case card, risk matrix for the sample agent |
| `review-scenarios/` | structured test scenarios (manual + incident-derived) |
| `live-monitoring/` | sample live events streamed into a monitor session |
| `protect-alerts/` | sample findings → alert → recommendation → action plan |
| `scenario-enrichment/` | production findings becoming Review scenarios |
| `evidence-export/` | what an exported evidence bundle contains |

## Full walkthrough

```bash
cd examples/rmp
BUNDLE=../claims-agent

# 0. (once) initialize the local ledger
agenomic ledger init

# 1. Seed the review corpus with scenarios + risk matrix
agenomic review scenarios add "$BUNDLE" --file review-scenarios/payment-risk.json
agenomic review risk-matrix "$BUNDLE"

# 2. Start the RMP session (ledger-bound)
agenomic --format json rmp start "$BUNDLE" --release release_123 --env production --ledger
# note the printed session ids:
RMP=rmp_...        # session.session_id
TRACK=01J...       # session.monitor_session_id

# 3. Review before release (replays the bundle's traces against its contract)
agenomic rmp review "$BUNDLE" --session "$RMP"

# 4. Stream production events (the third one loops, the fourth drifts)
for e in live-monitoring/events/*.json; do
  agenomic monitor event --session "$TRACK" --file "$e" || true
done
agenomic monitor findings --session "$TRACK"

# 5. Protect: alerts, recommendations, action plan
agenomic protect alerts --session "$RMP"
agenomic --format json protect alerts --session "$RMP" | jq -r '.alerts[0].alert_id'
agenomic protect action-plan --alert alr_... --session "$RMP"

# 6. Close the loop: findings become new review scenarios
agenomic monitor enrich-review --session "$TRACK" --output proposals.json

# 7. Unified report + audit evidence
agenomic rmp report --session "$RMP" --include-ledger-proof --output rmp-report.json
agenomic rmp export-evidence --session "$RMP" --output ./evidence --include-ledger

# 8. Verify the ledger chain offline
agenomic ledger verify
```
