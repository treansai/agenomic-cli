# basic-run

A run's lifecycle on the ledger: three events, one sealed block, offline
verification, and a JSONL export.

```bash
agenomic ledger init --store led --keys keys
agenomic ledger append --event events/01-agent-started.json   --store led --keys keys
agenomic ledger append --event events/02-tool-call.json       --store led --keys keys
agenomic ledger append --event events/03-agent-completed.json --store led --keys keys
agenomic ledger seal   --store led --keys keys
agenomic ledger verify --store led --keys keys      # exit 0
agenomic ledger export --run run-1 --output export.jsonl --store led --keys keys
```

Real outputs from this repo's binary:
- [`generated-ledger.jsonl`](generated-ledger.jsonl) — the three sealed,
  signed, chain-linked entries (note `previous_entry_hash` wiring and the
  `blake3:` payload commitments; payloads themselves are never stored).
- [`generated-blocks.jsonl`](generated-blocks.jsonl) — the signed Merkle
  block covering sequences 0..=2.
- [`expected-seal-output.txt`](expected-seal-output.txt),
  [`expected-verify-output.txt`](expected-verify-output.txt) — command output.
- [`generated-export.jsonl`](generated-export.jsonl) — the exported chain
  (re-verifiable anywhere, offline).
