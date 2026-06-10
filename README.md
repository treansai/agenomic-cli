# agenomic-cli

[![ci](https://github.com/treansai/agenomic-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/treansai/agenomic-cli/actions/workflows/ci.yml)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/agenomic-cli.svg)](https://crates.io/crates/agenomic-cli)

`agenomic` is the public, open-source Rust CLI for the Agenomic platform.
It validates, hashes, bundles, replays, and signs agent definitions fully
offline; produces and verifies signed ATEP (Agentic Trajectory Event
Protocol) event histories; and optionally connects to Agenomic Cloud for
managed releases..

## Install

```bash
# Pre-built binary (Linux/macOS):
curl -fsSL https://agenomic.io/install.sh | sh

# Or from source:
cargo install --path crates/agenomic-cli
```

## Quickstart

```bash
agenomic init .                  # detect everything: genome + workflows + system + env vars
agenomic init . --agent          # …then fill the semantic fields with the agent's own LLM
agenomic enrich .                # run the LLM pass alone (ANTHROPIC_API_KEY / OPENAI_API_KEY)
agenomic validate ./my-agent --level strict
agenomic bundle compile-runtime ./my-agent
agenomic build ./my-agent --output dist/my-agent.bundle.tar.zst
agenomic cloud login --endpoint https://api.agenomic.io --api-key <KEY>
agenomic bucket use --name default
agenomic cloud push-agent dist/my-agent.bundle.tar.zst --name "My Agent"
agenomic attest dist/my-agent.bundle.tar.zst --output attestation.json
```

`agenomic bundle compile-runtime` materializes deterministic
`runtime/*.compiled` launch plans from `genome.yaml`. The MVP emits
metadata + execution plans for `plain`, `langgraph`, and `crewai`
adapters so a bundle can carry portable runtime targets before build /
registry upload.

`agenomic init` / `update` go beyond the genome (spec 0.2, RFC 0009):
they recover **workflow topology** from LangGraph builders (`add_node`,
`add_edge`, `add_conditional_edges`) and Temporal workflows/signals,
synthesize a **`system.yaml`** when several graphs hand off to each
other (member roles, conditional edges, signals, engine hint), and
detect **environment variables** (required vs optional) across
Python/Node/Rust sources and `.env.example`. Everything is offline,
deterministic, and never overwrites a hand-edited manifest. The fields
static analysis cannot know — domain, criticality, description, skills,
behavior-contract rules — are filled by `agenomic enrich` (or
`init|update --agent`), which calls the agent's own declared model
provider and only ever replaces placeholders, schema-validating every
write.

## Documentation

- [Command reference](docs/command-reference.md)
- [Bundle format](docs/bundle-format.md)
- [Deterministic hashing](docs/deterministic-hashing.md)
- [ATEP format](docs/atep-format.md)
- [Local replay](docs/replay-local.md)
- [CI/CD integration](docs/ci-cd.md)
- [Cloud integration](docs/cloud-integration.md)
- [Security](docs/security.md)

## Examples

Three synthetic example agents live under [`examples/`](examples/) and are
exercised by the smoke test (`scripts/smoke.sh`).

## License

Apache-2.0. See [LICENSE](LICENSE).
