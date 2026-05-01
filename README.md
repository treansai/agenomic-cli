# agentlock-cli

`agentlock` is the public, open-source Rust CLI for the AgentLock platform. It validates, hashes, bundles, replays, and signs agent definitions fully offline; produces and verifies signed ATEP (Agentic Trajectory Event Protocol) event histories; and optionally connects to AgentLock Cloud for managed releases.

## Quickstart

```bash
agentlock validate ./my-agent --level strict
agentlock build ./my-agent --output dist/my-agent.bundle.tar.zst
agentlock attest dist/my-agent.bundle.tar.zst --output attestation.json
```

## Status

Pre-release (v0.1.0). Apache-2.0 licensed.
