# RMP · Monitor

Monitor continuously observes AI agents during execution. It composes the
existing building blocks — it does **not** re-implement them:

* **Detection** is `agenomic-track` (`TrackingEngine`): deterministic
  drift, loop, intent-shift, and failure detection plus the runtime
  harness (behavior contract + Rego policies).
* **Durability** is `agenomic-ledger-local`'s WAL pipeline: idempotent
  ingestion, crash recovery, dead-letter queue, explicit backpressure.

## The hot path

`MonitorEngine::ingest` is latency-critical:

1. The raw event is committed to the ledger by hash (never re-encoded)
   through the pipeline. In the default `durable_low_latency` mode this is
   one fsync'd WAL append; sealing/signing happens on the background
   worker.
2. In-memory detectors run; any alerts become monitor findings.

Heavy work — harness evaluation, report building, enrichment proposals —
happens at `stop`.

## Modes

The RMP mode vocabulary mirrors the ledger's:

| Mode | Ingest returns after |
|---|---|
| `best_effort_low_latency` | the in-memory enqueue (crash loses queued events) |
| `durable_low_latency` (default) | the fsync'd WAL append |
| `strict_verified` | seal + sign + persist (synchronous) |
| `strict_cloud` | reserved; fails closed |

A full queue or exhausted disk budget is an explicit `LedgerBusy` error —
nothing is silently dropped. Crash recovery replays the WAL idempotently;
poison events land in the dead-letter store
(`agenomic ledger queue dead-letter list`).

## Findings

Tracking alerts map onto typed findings: `drift`, `loop`, `intent_shift`,
`harness_violation`, `policy_violation`, `anomaly` (security). Failure
events map to `failure`/`repeated_failure`. Findings carry severity,
evidence event ids, observed/expected values, and gating flags
(`blocks_release`, `requires_human_review`).

## Ledger events

When the session is ledger-bound, Monitor records (on the tracking
session's run chain, so one `ledger verify --run` covers everything):

* every raw tracking event (committed by its own event hash)
* `monitor.session.started`
* `monitor.finding.created`, `monitor.drift.detected`,
  `monitor.loop.detected`, `monitor.intent.shifted`,
  `monitor.failure.detected`
* `rmp.scenario_enrichment.proposed` at stop

## Feedback into Review

`agenomic monitor enrich-review --session <id>` derives scenario
enrichment proposals from the session's findings (see
`docs/rmp/scenario-enrichment.md`). Protect is triggered when any finding
reaches the configured severity (default `high`).

## CLI

```bash
agenomic monitor start ./my-agent --env production --ledger
agenomic monitor event --session <id> --file event.json     # exit 7 when a blocking alert fires
agenomic monitor tail --session <id>
agenomic monitor findings --session <id>
agenomic monitor enrich-review --session <id> --output proposals.json
agenomic monitor stop --session <id>
```

`agenomic monitor` shares its session store with `agenomic track` — the
same session can be driven by either command family; `monitor` adds the
RMP finding/enrichment layer.
