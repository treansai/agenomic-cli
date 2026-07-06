# tamper-detection

Start from `basic-run`'s ledger, flip ONE hex character inside entry 1's
`event_payload_hash` (the JSON stays parseable), and verify again:

```bash
agenomic ledger verify --store led-tampered --keys keys   # exit 19
```

Real output ([`expected-verify-output.txt`](expected-verify-output.txt)):
verification FAILS, names `first invalid sequence: 1`, reports both the
hash failure and the signature failure at that entry (the signature covers
the same digest), and recommends the tampering playbook. The tampered
store is committed as [`tampered-ledger.jsonl`](tampered-ledger.jsonl) so
you can diff it against `../basic-run/generated-ledger.jsonl` — the entire
difference is one character.
