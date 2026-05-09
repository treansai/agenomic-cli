# Examples

Three synthetic Agenomic agents used by the CLI's CI to ensure the full
pipeline keeps working:

- [`claims-agent`](./claims-agent) — insurance claims triage
- [`support-agent`](./support-agent) — customer support
- [`trading-risk-agent`](./trading-risk-agent) — trading-risk evaluator

## Full pipeline

```bash
cd examples/claims-agent
agenomic validate . --level strict
agenomic build . --output /tmp/claims.bundle.tar.zst
agenomic hash /tmp/claims.bundle.tar.zst
agenomic replay /tmp/claims.bundle.tar.zst ./traces/synthetic_claim_traces.jsonl --output /tmp/replay.json
agenomic attest /tmp/claims.bundle.tar.zst --replay-report /tmp/replay.json --output /tmp/attestation.json
agenomic verify /tmp/attestation.json
```
