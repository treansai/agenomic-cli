# Live monitoring events

Sample production events for a monitor session over the claims agent.
Events 01–02 are normal; 03a–03c repeat the same tool call (loop
pressure); 04 calls a tool outside the release baseline (critical drift).

```bash
BUNDLE=../../claims-agent
agenomic --format json monitor start "$BUNDLE" --env production --ledger
# use the printed session_id:
for e in events/*.json; do
  agenomic monitor event --session <session-id> --file "$e" || true
done
agenomic monitor findings --session <session-id>
agenomic monitor stop --session <session-id>
```

The drift event exits with code 7 (release-blocking alert) — the `|| true`
keeps the loop going for the demo.
