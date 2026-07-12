# Evidence export

Export the audit bundle for an RMP session:

```bash
agenomic rmp export-evidence --session <rmp-session> --output ./evidence --include-ledger
```

Produces (see `docs/rmp/evidence.md` for details):

```text
evidence/
  rmp_report.json        unified report, blake3 hash-stamped
  rmp_report.md          human-readable summary
  review_report.json     review outcome + risk matrix + replay report
  monitor_report.json    monitor outcome (tracking report inside)
  tracking_report.json
  protect_report.json    alerts, recommendations, action plans
  action_plan.md
  recommendations.md
  proposals.json         scenario enrichment proposals
  test_scenarios.json
  ledger_proof.json      chain head, block ids, verification status
  manifest.json          file list + hashes, anchored to the report hash
```

`sample-rmp-report.json` is a trimmed example of the unified report.
For the full offline-verifiable ledger bundle (chain, Merkle data,
signatures, embedded public keys):

```bash
agenomic evidence export --run <tracking-session> --output ./evidence/ledger --include-ledger
agenomic evidence verify ./evidence/ledger
```
