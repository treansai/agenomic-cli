# `agent://` URI Scheme

Status: **provisional, internal to Agenomic**. Not registered with IANA.

The `agent://` URI scheme identifies an Agenomic-compliant agent bundle
independently of where it is stored. It is consumed by `agenomic-os` (the
Agent Genome Orchestration Substrate) to resolve, materialize, and launch
agents from a stable reference.

## Grammar

```
agent://<org>/<slug>[@<version-or-channel-or-digest>][?<query>]
```

- `<org>` — publisher organization slug. Lowercase ASCII letters, digits, `-`.
- `<slug>` — agent slug under that org. Lowercase ASCII letters, digits, `-`.
- `<version-or-channel-or-digest>` — optional, one of:
  - a semver string (`1.2.0`, `1.2.0-rc.1`)
  - a channel name (`prod`, `staging`, `dev`)
  - a content digest (`sha256:<hex>`)
- `<query>` — optional `&`-separated `key=value` pairs. Recognized keys:
  - `profile` — runtime profile name (matches `agenomic-config` profiles)
  - `runtime` — runtime adapter id override

When no version qualifier is given, the resolver applies its default
channel policy (typically `prod` for trusted publishers, refusal otherwise).

## Examples

```
agent://treansai/agenomic-codedrift
agent://treansai/agenomic-codedrift@1.2.0
agent://treansai/agenomic-codedrift@prod
agent://treansai/agenomic-codedrift@sha256:abc123…
agent://treansai/agenomic-codedrift?profile=local
agent://treansai/agenomic-codedrift@1.2.0?profile=local&runtime=python
```

## Rejection rules

The parser must reject:

- empty `<org>` or `<slug>`
- uppercase characters in `<org>` or `<slug>`
- `..`, `.`, leading/trailing `-` in either segment
- multiple `@` in the path component
- duplicate query keys
- unknown query keys (parser logs; resolver decides)
- references that resolve to a bundle without a signed `agent.lock` when
  the source is remote and unsigned bundles are not explicitly allowed

## Relationship to `genome.yaml`

A genome MAY declare its own canonical reference under `agent.id` using
the `agent://` scheme. When present, `agenomic-os inspect` and
`agenomic-os run` verify that the resolved reference matches `agent.id`
before launching.

## Stability

This scheme is provisional. It MUST NOT be presented as an IANA-registered
URI scheme in user-facing documentation or third-party integrations until
a formal registration process is completed. See the
[IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes/).

## See also

- `docs/BACKEND_GAPS.md` for resolver/registry surfaces not yet implemented.
- `schemas/genome.schema.json` for the optional `execution:` block consumed
  by `agenomic-os`.
- `schemas/agent-lock.schema.json` for the `execution_hash` drift signal.
