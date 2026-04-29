# agentlock-cli

`agentlock` is a local-first Rust CLI for creating, validating, packaging,
inspecting, hashing, diffing, replaying, and attesting AgentLock agent-bundles.

It does not require API keys and does not call external services.

## Quickstart

```bash
cargo run -p agentlock-cli --bin agentlock -- init ./examples/demo-agent
cargo run -p agentlock-cli --bin agentlock -- validate ./examples/demo-agent
cargo run -p agentlock-cli --bin agentlock -- build ./examples/demo-agent --output ./dist/demo-agent.tar.zst
cargo run -p agentlock-cli --bin agentlock -- inspect ./dist/demo-agent.tar.zst
cargo run -p agentlock-cli --bin agentlock -- hash ./examples/demo-agent
cargo run -p agentlock-cli --bin agentlock -- replay ./examples/claims-agent ./examples/claims-agent/traces/sample_traces.jsonl --runs 2 > /tmp/replay-report.json
cargo run -p agentlock-cli --bin agentlock -- attest ./examples/claims-agent --replay-report /tmp/replay-report.json
```

## Workspace Layout

```text
.
├── crates/
│   ├── agentlock-core/
│   ├── agentlock-bundle/
│   ├── agentlock-diff/
│   ├── agentlock-replay-local/
│   └── agentlock-cli/
├── schemas/
├── examples/claims-agent/
└── tests/cli_smoke_tests.rs
```

## Commands

### `agentlock init <path>`

Creates a minimal bundle folder with:

- `genome.yaml`
- `agent.lock.yaml`
- `behavior.contract.yaml`
- `prompts/system.md`

Example output:

```text
$ agentlock init ./tmp/my-agent
Initialized bundle at ./tmp/my-agent
```

### `agentlock validate <path>`

Checks required files, YAML syntax, schema conformance, and internal references.

```text
$ agentlock validate ./examples/claims-agent
Bundle is valid: ./examples/claims-agent
```

### `agentlock build <path> --output <bundle.tar.zst>`

Validates and writes a deterministic `tar.zst` bundle, then prints the bundle hash.

```text
$ agentlock build ./examples/claims-agent --output ./dist/claims-agent.tar.zst
Built bundle: ./dist/claims-agent.tar.zst
Bundle hash: <blake3-hash>
```

### `agentlock inspect <bundle-or-folder>`

Prints a human-readable summary of the bundle metadata.

```text
$ agentlock inspect ./examples/claims-agent
agent_id: claims-agent
name: Claims Agent
version: 0.1.0
model_provider: local-stub
model: deterministic-replay
tools: claims.lookup, policy.lookup
knowledge_snapshots: claims-handbook-2026-04
behavior_contract_id: claims-agent-contract-v1
```

### `agentlock hash <bundle-or-folder>`

Prints a deterministic content hash that ignores OS metadata.

```text
$ agentlock hash ./examples/claims-agent
<blake3-hash>
```

### `agentlock diff <old> <new>`

Shows static changes for prompts, tools, model config, policies, and knowledge snapshots.

```text
$ agentlock diff ./old-bundle ./new-bundle
Changed prompts:
  - prompts/system.md
Changed tools:
  - added: policy.lookup
Changed model config:
  - model: deterministic-replay -> deterministic-replay-v2
```

### `agentlock replay <bundle-or-folder> <traces.jsonl> --runs <n>`

Runs local deterministic checks from `behavior.contract.yaml` against JSONL traces and prints a JSON report.

```text
$ agentlock replay ./examples/claims-agent ./examples/claims-agent/traces/sample_traces.jsonl --runs 1
{
  "report_version": 1,
  "provider": "local-deterministic",
  "bundle_hash": "<blake3-hash>",
  "contract_id": "claims-agent-contract-v1",
  "generated_at": "2026-04-29T12:00:00Z",
  "summary": {
    "runs_requested": 1,
    "traces": 1,
    "total_checks": 7,
    "passed_checks": 7,
    "failed_checks": 0,
    "contract_passed": true
  },
  "runs": [
    {
      "run_index": 1,
      "trace_id": "claim-approved-001",
      "passed": true,
      "checks": [
        {
          "id": "final-answer-present",
          "passed": true,
          "message": "found at least one assistant output event"
        }
      ]
    }
  ]
}
```

### `agentlock attest <bundle-or-folder> --replay-report <report.json>`

Writes an unsigned `release_attestation.json` next to the folder or bundle archive.

```text
$ agentlock attest ./examples/claims-agent --replay-report /tmp/replay-report.json
Wrote ./examples/claims-agent/release_attestation.json
```

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The included [examples/claims-agent](/Users/gabinmberikongo/code/treansai/agentlock/agentlock-cli/examples/claims-agent)
bundle is used by the smoke tests and can be validated, built, inspected, hashed,
replayed, and attested locally.
