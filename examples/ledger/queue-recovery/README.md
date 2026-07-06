# queue-recovery

The crash artifact the WAL checkpoint protects against: the process dies
after sealing an event into the ledger but before the checkpoint advances,
so on restart the WAL record looks pending again.

```bash
agenomic ledger init --store led --keys keys
agenomic ledger append --event e1.json --store led --keys keys
agenomic ledger append --event e2.json --store led --keys keys
rm led/wal/checkpoint.json          # simulate the crash window
agenomic ledger queue status --store led --keys keys
agenomic ledger queue flush  --store led --keys keys
agenomic ledger verify       --store led --keys keys   # exit 0
```

Real outputs: [`expected-status-before-recovery.txt`](expected-status-before-recovery.txt)
shows the pending WAL record; [`expected-flush-output.txt`](expected-flush-output.txt)
shows recovery **deduplicating** it (`0 replayed, 1 deduplicated`) instead
of double-appending; [`expected-verify-output.txt`](expected-verify-output.txt)
shows the chain intact with exactly the two original entries. No loss, no
duplicates — the idempotency layer, not luck.
