# Review · Monitor · Protect (RMP)

RMP is Agenomic's continuous safety loop for production AI agents:

```text
        ┌────────────────────────────────────────────────┐
        ▼                                                │
   ┌─────────┐        ┌─────────┐        ┌─────────┐     │
   │ Review  │──────▶ │ Monitor │──────▶ │ Protect │─────┘
   └─────────┘        └─────────┘        └─────────┘
   scenarios,         live events,       anomalies,
   risk matrix,       drift/loop/        alerts, action
   replay, release    intent/failure     plans, evidence
   recommendation     detection          export
```

* **Review** evaluates an agent before release, after changes, or after
  incidents: structured test scenarios, a typed risk matrix, deterministic
  replay against the behavior contract, regression detection against
  evaluation history, and a release recommendation
  (`approve` / `approve_with_conditions` / `human_review_required` / `block`).
* **Monitor** observes live execution. It reuses the online-tracking engine
  (drift, loops, intent shifts, failures, runtime harness) and appends every
  event to the cryptographic ledger through the durable WAL pipeline — the
  hot path is one fsync'd WAL write, sealing/signing happens on a background
  worker.
* **Protect** turns findings into action: anomaly detection over patterns
  the per-event detectors cannot see, deduplicated/routed/throttled alerts,
  deterministic recommendations, ordered action plans, and audit-ready
  evidence export.

## The loop closes

Every real production issue detected by Monitor or Protect can enrich
Review through a **scenario enrichment proposal**
(`docs/rmp/scenario-enrichment.md`):

| Production finding | New Review artifact |
|---|---|
| Loop detected | loop regression scenario |
| Prompt/config drift | baseline regression check |
| Policy violation | policy test |
| Forbidden intent shift | intent boundary scenario |
| Tool failure | failure replay fixture |
| Replay divergence | release validation gate |
| Missing human approval | human-approval gate scenario |

Proposals move through an explicit approval workflow
(`draft → pending_review → approved → applied`); high-severity proposals
always require a recorded human reviewer.

## Where things live

| Piece | Location |
|---|---|
| Engine crate | `crates/agenomic-rmp` |
| CLI commands | `agenomic rmp` / `review` / `monitor` / `protect` |
| Session state | `<cwd>/.agenomic/rmp/<session_id>/` |
| Live events | `<cwd>/.agenomic/tracking/<session_id>/` (shared with `agenomic track`) |
| Ledger | `<cwd>/.agenomic/ledger` (shared with `agenomic ledger`) |
| Scenario corpus | `<bundle>/.agenomic/rmp/corpus/scenarios/` |

## Design guarantees

* **Deterministic by default.** No LLM is called anywhere in the loop. The
  optional `SuggestionProvider` interface exists for hosts that want
  LLM-assisted narratives; suggestions are advisory and never replace
  deterministic evidence (see `docs/rmp/security.md`).
* **Nothing is mutated automatically.** Recommendations and enrichment
  proposals are typed suggestions. High-impact kinds (policy, contract,
  tool permissions, rollback, workflow guardrails) always require human
  approval.
* **Everything is evidence.** Findings, alerts, and reports carry
  deterministic evidence references (event ids, ledger entry ids, report
  hashes). With `--ledger`, every lifecycle event is hash-committed and
  signed into the append-only ledger and the unified report carries an
  offline-verifiable proof block.
* **The live path stays fast.** Monitor ingestion uses the ledger's
  `durable_low_latency` mode: WAL append + in-memory detectors, with
  crash recovery, idempotent replay, and a dead-letter queue.

## Quick start

```bash
# 1. Boot the loop for a bundle (ledger-bound).
agenomic ledger init
agenomic rmp start ./my-agent --release release_123 --env production --ledger

# 2. Stream production events into the monitor session.
agenomic monitor event --session <tracking-session> --file event.json

# 3. Inspect findings, run Protect, get an action plan.
agenomic monitor findings --session <tracking-session>
agenomic protect alerts --session <rmp-session>
agenomic protect action-plan --alert <alert-id> --session <rmp-session>

# 4. Close the loop: derive scenarios from findings and re-review.
agenomic monitor enrich-review --session <tracking-session> --output proposals.json
agenomic rmp review ./my-agent --session <rmp-session>

# 5. Unified report + audit evidence.
agenomic rmp report --session <rmp-session> --include-ledger-proof
agenomic rmp export-evidence --session <rmp-session> --output ./evidence --include-ledger
```

Detailed docs: `docs/rmp/review.md`, `docs/rmp/monitor.md`,
`docs/rmp/protect.md`, `docs/rmp/scenario-enrichment.md`,
`docs/rmp/risk-matrix.md`, `docs/rmp/alerts.md`,
`docs/rmp/recommendations.md`, `docs/rmp/evidence.md`, `docs/rmp/cli.md`,
`docs/rmp/sdk.md`, `docs/rmp/security.md`.
