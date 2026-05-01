# Examples

Three synthetic AgentLock agents used by the CLI's CI to ensure the full
pipeline keeps working:

- [`claims-agent`](./claims-agent) — insurance claims triage
- [`support-agent`](./support-agent) — customer support
- [`trading-risk-agent`](./trading-risk-agent) — trading-risk evaluator

## Full pipeline

```bash
cd examples/claims-agent
agentlock validate . --level strict
agentlock build . --output /tmp/claims.bundle.tar.zst
agentlock hash /tmp/claims.bundle.tar.zst
agentlock replay /tmp/claims.bundle.tar.zst ./traces/synthetic_claim_traces.jsonl --output /tmp/replay.json
agentlock attest /tmp/claims.bundle.tar.zst --replay-report /tmp/replay.json --output /tmp/attestation.json
agentlock verify /tmp/attestation.json
```
