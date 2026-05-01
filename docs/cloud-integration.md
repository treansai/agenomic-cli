# Cloud integration

The CLI works fully offline. Cloud integration is opt-in.

## When to use

Use AgentLock Cloud when you need:

- Hosted multi-tenant replay across LLM providers
- Statistical replay (`runs_per_trace > 1` with a real model)
- Org-wide release management (promote, rollback)
- Tamper-evident long-term storage of ATEP segments

## Login

```bash
agentlock cloud login --endpoint https://api.agentlock.dev --api-key <KEY>
agentlock cloud whoami
```

Credentials are stored at `~/.config/agentlock/credentials.toml` with mode
0600 on Unix.

## Idempotency

Every POST sent by the cloud client carries an `Idempotency-Key: <ULID>`
header. The CLI retries on 429 / 502 / 503 / 504 with exponential backoff
(200ms / 800ms / 3200ms). 401 fails fast (no retry).

## Proxies

Standard `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` env vars are honored via
reqwest's defaults.
