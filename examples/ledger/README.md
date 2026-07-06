# Ledger examples

Hands-on walkthroughs of the cryptographic event ledger
(`docs/atep-ledger.md`). Every `expected-*.txt` / `generated-*.jsonl` file
here was genuinely produced by running the commands in each README against
this repository's `agenomic` binary — nothing is hand-written. Hashes and
ids differ on your machine (fresh keys, fresh ULIDs); the shapes and
verdicts will not.

- [`basic-run/`](basic-run/) — init → append → seal → verify → export.
- [`tamper-detection/`](tamper-detection/) — flip one byte, watch verify
  fail with the exact entry named (exit 19).
- [`queue-recovery/`](queue-recovery/) — crash between seal and checkpoint;
  recovery deduplicates instead of double-appending.
