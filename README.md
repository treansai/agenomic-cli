# agenomic-cli

[![ci](https://github.com/agenomic/agenomic-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/agenomic/agenomic-cli/actions/workflows/ci.yml)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/agenomic-cli.svg)](https://crates.io/crates/agenomic-cli)

`agenomic` is the public, open-source Rust CLI for the Agenomic platform.
It validates, hashes, bundles, replays, and signs agent definitions fully
offline; produces and verifies signed ATEP (Agentic Trajectory Event
Protocol) event histories; and optionally connects to Agenomic Cloud for
managed releases.

## Install

```bash
# Pre-built binary (Linux/macOS):
curl -fsSL https://agenomic.dev/install.sh | sh

# Or from source:
cargo install --path crates/agenomic-cli
```

## Quickstart

```bash
agenomic validate ./my-agent --level strict
agenomic build ./my-agent --output dist/my-agent.bundle.tar.zst
agenomic attest dist/my-agent.bundle.tar.zst --output attestation.json
```

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
