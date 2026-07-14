# RMP · SDKs and cloud

> **Status.** The RMP surface is CLI-first today. The example client APIs
> below are the **target** shape for the SDKs and the matching cloud
> endpoints; they are not all wired up yet. What ships now: the CLI
> (`agenomic rmp|review|monitor|protect`, documented in `cli.md`) and the
> Monitor phase against Agenomic Cloud's live-tracking endpoints
> (`/v1/tracking/*`). The `/v1/rmp`, `/v1/review`, and `/v1/protect`
> endpoints these snippets imply are not implemented yet — treat this page
> as the intended SDK contract, and drive RMP from the CLI in the meantime.

The Python and TypeScript SDKs are intended to expose the RMP surface
following their existing local-first conventions: without a
`base_url`/`baseUrl` the client runs in local mode (sessions buffer events
in memory / to JSONL); with one it targets Agenomic Cloud.

## Python

```python
from agenomic import Client

client = Client(api_key="...", base_url="https://api.agenomic.dev")

session = client.rmp.start(
    agent="agent://acme/claims",
    release_id="release_123",
    environment="production",
    ledger=True,
)

review = client.review.run(agent="agent://acme/claims")

monitor = client.monitor.start(agent="agent://acme/claims", release_id="release_123")
client.monitor.event(
    session_id=monitor.session_id,
    event={
        "type": "tool.call.completed",
        "tool": {"name": "claims_db.lookup"},
        "input_hash": "blake3:...",
        "output_hash": "blake3:...",
    },
)

alerts = client.protect.alerts(session_id=session.session_id)
plan = client.protect.action_plan(alert_id=alerts[0]["alert_id"], session_id=session.session_id)
client.review.approve_scenario_enrichment(
    proposal_id=plan["scenario_proposal_ids"][0],
    session_id=session.session_id,
    reviewer="alice@example.com",
)
```

## TypeScript

```typescript
const client = new AgenomicClient({ apiKey: process.env.AGENOMIC_API_KEY, baseUrl: "..." });

const session = await client.rmp.start({
  agent: "agent://acme/claims",
  releaseId: "release_123",
  environment: "production",
  ledger: true,
});

await client.monitor.event({
  sessionId: session.session_id,
  event: { type: "tool.call.completed", tool: { name: "claims_db.lookup" } },
});

const alerts = await client.protect.alerts({ sessionId: session.session_id });
const plan = await client.protect.actionPlan({
  alertId: alerts[0].alert_id,
  sessionId: session.session_id,
});
```

Wire shapes are snake_case and match `schemas/rmp-*.schema.json` in this
repo and the spec repo's `schemas/v0.3/rmp-*.schema.json`.

## Cloud endpoints

| Method + path | Purpose |
|---|---|
| `POST /v1/rmp/sessions` | create RMP session |
| `GET /v1/rmp/sessions` / `GET /v1/rmp/sessions/:id` | list / get |
| `POST /v1/rmp/sessions/:id/report` | generate the unified report |
| `POST /v1/review/runs` | run review |
| `GET /v1/review/scenarios` / `POST /v1/review/scenarios` | scenario corpus |
| `POST /v1/review/proposals/:id/approve` | approve scenario enrichment |
| `PUT /v1/review/risk-matrix` | update risk matrix |
| `POST /v1/monitor/sessions` | start monitor session |
| `POST /v1/monitor/sessions/:id/events` | ingest event (idempotent) |
| `GET /v1/monitor/sessions/:id/findings` | list findings |
| `GET /v1/protect/alerts?session_id=` | list alerts |
| `POST /v1/protect/alerts/:id/route` | route alert |
| `POST /v1/protect/alerts/:id/action-plan` | create action plan |
| `GET /v1/protect/recommendations?session_id=` | list recommendations |
| `POST /v1/protect/recommendations/:id/approve` | approve recommendation |
| `POST /v1/rmp/sessions/:id/evidence` | export evidence |

All under the standard auth (session cookie or `x-api-key`), tenant
isolation, idempotency (`Idempotency-Key`), and audit-log middleware.
