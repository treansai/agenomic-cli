# CI/CD integration

The CLI is designed to be a deterministic gate in your CI.

## GitHub Actions

```yaml
- uses: actions/checkout@v4
- run: curl -fsSL https://agenomic.io/install.sh | sh
- run: agenomic validate ./agent --level ci
- run: agenomic build ./agent --output dist/agent.bundle.tar.zst --strict
- run: agenomic replay dist/agent.bundle.tar.zst ./agent/traces.jsonl --output dist/replay.json --fail-on high
- run: agenomic attest dist/agent.bundle.tar.zst --replay-report dist/replay.json --output dist/att.json --sign-with ${{ secrets.AGENOMIC_KEY }}
```

## GitLab CI

```yaml
agenomic:
  image: rust:1.85
  script:
    - curl -fsSL https://agenomic.io/install.sh | sh
    - agenomic validate ./agent --level ci
    - agenomic build ./agent --output dist/agent.bundle.tar.zst --strict
```

## Exit codes for gating

| Exit | Meaning | Common gate |
| --- | --- | --- |
| 1 | ValidationFailed | Block PR |
| 4 | SecurityViolation | Block PR & alert |
| 7 | ContractFailed | Block release, allow PR comments |
| 8 | DiffRiskExceeded | Require review approval |
| 9 | AttestationVerificationFailed | Block deploy |

`agenomic <cmd> --format json` emits machine-readable output if you want
to attach the report as an artifact.

## Stale-bundle check (`agm update`)

Fail the build when the committed bundle no longer matches the repository,
without ever auto-committing on the server (see
[`init-and-update.md`](init-and-update.md) §3.8):

```yaml
- name: Bundle is up to date
  run: |
    agm update --no-commit --format json > /tmp/agenomic-update.json
    test "$(jq '.changed | length' /tmp/agenomic-update.json)" = "0" \
      || { echo "::error::genome.yaml is stale, run 'agm update' locally"; exit 1; }
```
