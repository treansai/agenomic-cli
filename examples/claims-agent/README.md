# claims-agent

Synthetic example agent for an insurance-claims triage workflow. Used by
the CLI's smoke tests and acceptance gate.

```bash
agentlock validate ./examples/claims-agent --level strict
agentlock build ./examples/claims-agent --output dist/claims.bundle.tar.zst
agentlock hash dist/claims.bundle.tar.zst
agentlock replay dist/claims.bundle.tar.zst \
    ./examples/claims-agent/traces/synthetic_claim_traces.jsonl \
    --output /tmp/replay.json
agentlock attest dist/claims.bundle.tar.zst \
    --replay-report /tmp/replay.json \
    --output /tmp/attestation.json
agentlock verify /tmp/attestation.json
```
