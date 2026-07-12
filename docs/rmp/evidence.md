# RMP · Evidence export

`agenomic rmp export-evidence` produces an audit-ready file set for one
session:

```text
<out>/
  rmp_report.json          the unified report (hash-stamped)
  rmp_report.md            human-readable summary
  review_report.json       when Review ran
  risk_matrix.json         when present
  replay_reports/          replay report(s) from Review
  monitor_report.json      when Monitor ran
  tracking_report.json     the underlying tracking report
  protect_report.json      when Protect ran
  action_plan.md           rendered action plans
  recommendations.md       rendered recommendations
  proposals.json           scenario enrichment proposals
  test_scenarios.json      scenario ids executed by Review
  ledger_proof.json        with --include-ledger
  manifest.json            file list + blake3 hashes
```

Every file is hashed (`blake3:`) into `manifest.json`, which also records
the RMP report hash the bundle is anchored to.

## Offline verification

With `--include-ledger` the report carries the ledger proof block
(`agenomic.ledger.proof/v0.1`): root hash, run chain head, block ids,
verification status, signing key ids. For the full offline-verifiable
proof bundle (chain, blocks, Merkle data, signatures, public keys), export
the ledger evidence next to the RMP bundle:

```bash
agenomic evidence export --run <tracking-session> --output ./evidence/ledger --include-ledger
agenomic evidence verify ./evidence/ledger      # fully offline, exit 19 on failure
```

## What evidence is (and is not)

Locally signed bundles are **technical integrity evidence**: they prove
the recorded events were not altered after recording. They do not prove
who recorded them — org-attested probative packs are a hosted (cloud)
capability. Reports state this honestly rather than overclaiming.
