# CI/CD integration

The CLI is designed to be a deterministic gate in your CI.

## GitHub Actions

```yaml
- uses: actions/checkout@v4
- run: curl -fsSL https://agentlock.dev/install.sh | sh
- run: agentlock validate ./agent --level ci
- run: agentlock build ./agent --output dist/agent.bundle.tar.zst --strict
- run: agentlock replay dist/agent.bundle.tar.zst ./agent/traces.jsonl --output dist/replay.json --fail-on high
- run: agentlock attest dist/agent.bundle.tar.zst --replay-report dist/replay.json --output dist/att.json --sign-with ${{ secrets.AGENTLOCK_KEY }}
```

## GitLab CI

```yaml
agentlock:
  image: rust:1.85
  script:
    - curl -fsSL https://agentlock.dev/install.sh | sh
    - agentlock validate ./agent --level ci
    - agentlock build ./agent --output dist/agent.bundle.tar.zst --strict
```

## Exit codes for gating

| Exit | Meaning | Common gate |
| --- | --- | --- |
| 1 | ValidationFailed | Block PR |
| 4 | SecurityViolation | Block PR & alert |
| 7 | ContractFailed | Block release, allow PR comments |
| 8 | DiffRiskExceeded | Require review approval |
| 9 | AttestationVerificationFailed | Block deploy |

`agentlock <cmd> --format json` emits machine-readable output if you want
to attach the report as an artifact.
