# Cloud integration

The CLI works fully offline. Cloud integration is opt-in.

## When to use

Use Agenomic Cloud when you need:

- Hosted multi-tenant replay across LLM providers
- Statistical replay (`runs_per_trace > 1` with a real model)
- Org-wide release management (promote, rollback)
- Tamper-evident long-term storage of ATEP segments

## Login

```bash
agenomic cloud login --endpoint https://api.agenomic.io --api-key <KEY>
agenomic bucket use --name default
agenomic cloud whoami
```

Credentials are stored at `~/.config/agenomic/credentials.toml` with mode
0600 on Unix.

## Buckets

`agenomic cloud push-agent` always targets a bucket. The CLI resolves the
destination in this order:

1. The active bucket selected with `agenomic bucket use --name <bucket>`
2. The implicit `default` bucket

If the target bucket does not exist yet, the CLI creates it and moves the
agent into that bucket before uploading the bundle.

## Idempotency

Every POST sent by the cloud client carries an `Idempotency-Key: <ULID>`
header. The CLI retries on 429 / 502 / 503 / 504 with exponential backoff
(200ms / 800ms / 3200ms). 401 fails fast (no retry).

## Proxies

Standard `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` env vars are honored via
reqwest's defaults.
