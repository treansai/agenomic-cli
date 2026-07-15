# RMP · CLI reference

All commands accept the global `--format human|json|json-pretty|yaml`.
Shared flags: `--store` (RMP store root, default `<cwd>/.agenomic/rmp`),
`--tracking-store` (live path, default `<cwd>/.agenomic/tracking`),
`--ledger --ledger-store --ledger-keys` (where applicable).

## `agenomic rmp`

```bash
agenomic rmp start ./my-agent --release <id> --env production [--ledger]
agenomic rmp status --session <rmp-session>
agenomic rmp report --session <rmp-session> [--output rmp-report.json] [--include-ledger-proof]
agenomic rmp review ./my-agent [--session <rmp-session>] [--scenario file]...
agenomic rmp monitor --session <rmp-session>
agenomic rmp protect --session <rmp-session>
agenomic rmp enrich-scenarios --from-findings findings.json [--output proposals.json]
agenomic rmp proposals list --session <rmp-session>
agenomic rmp proposals approve <proposal_id> --session <rmp-session> --reviewer <name>
agenomic rmp proposals reject <proposal_id> --session <rmp-session> [--reviewer <name>]
agenomic rmp proposals apply <proposal_id> --session <rmp-session>
agenomic rmp action-plan --alert <alert-id> --session <rmp-session>
agenomic rmp export-evidence --session <rmp-session> --output <dir> [--include-ledger]
```

`rmp start` creates the umbrella session **and** the underlying live
tracking session (its id is `monitor_session_id` in the output).

## `agenomic review`

```bash
agenomic review run ./my-agent [--scenario f]... [--risk-matrix f] [--traces f] [--output f]
agenomic review scenarios list ./my-agent
agenomic review scenarios add ./my-agent --file scenario.json
agenomic review risk-matrix ./my-agent
agenomic review report --session <rmp-session>
```

## `agenomic monitor`

```bash
agenomic monitor start ./my-agent [--release <id>] [--env production] [--ledger]
agenomic monitor event --session <tracking-session> --file event.json
agenomic monitor tail --session <tracking-session> [--limit 20]
agenomic monitor findings --session <tracking-session>
agenomic monitor enrich-review --session <tracking-session> [--output proposals.json]
agenomic monitor stop --session <tracking-session> [--status completed|cancelled|failed]
```

## `agenomic protect`

```bash
agenomic protect alerts --session <rmp-session>
agenomic protect action-plan --alert <alert-id> --session <rmp-session>
agenomic protect recommendations --session <rmp-session>
agenomic protect notify --alert <alert-id> --session <rmp-session>
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (review pass/warn, report not blocked) |
| 1 | review failed, or the unified report recommends `block` |
| 7 | a monitor event raised a release-blocking alert, or monitor stop landed on `fail` |
| 19 | ledger integrity failure (from the shared ledger machinery) |
