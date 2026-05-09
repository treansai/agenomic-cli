# claims-agent

Synthetic example agent for an insurance-claims triage workflow. Used by
the CLI's smoke tests and acceptance gate.

```bash
agenomic validate ./examples/claims-agent --level strict
agenomic build ./examples/claims-agent --output dist/claims.bundle.tar.zst
agenomic hash dist/claims.bundle.tar.zst
agenomic replay dist/claims.bundle.tar.zst \
    ./examples/claims-agent/traces/synthetic_claim_traces.jsonl \
    --output /tmp/replay.json
agenomic attest dist/claims.bundle.tar.zst \
    --replay-report /tmp/replay.json \
    --output /tmp/attestation.json
agenomic verify /tmp/attestation.json
```
