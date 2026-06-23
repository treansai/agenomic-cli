# Tool Boundary Gate

The Tool Boundary Gate is a **deterministic, at-the-effect** enforcement point
for agent tool calls, in the spirit of ClawGuard. Its guiding insight:

> Reliable defenses do not depend on the LLM. Filtering at the prompt is the
> wrong layer — enforce at the **effect**.

A prompt-injection payload that reaches a tool argument cannot talk its way past
the gate, because the gate never asks a model anything: it decides in pure Rust,
and the same `(rule set, tool call)` always yields the same verdict.

It lives in the `agenomic-gate` crate and is exposed as `agenomic gate check`.

## What it checks

Two layers run on every tool call, neither of which calls a model:

1. **Non-negotiable invariants** (built-in, deterministic):
   - **Tool allowlist & scopes** — when an allowlist is configured it is
     fail-closed; a requested scope outside a tool's permitted set is a block.
   - **Self-modification** — blocks tools that rewrite the agent's own
     instructions/policy (by name, e.g. `set_system_prompt`) or that write a
     protected target (`genome.yaml`, `system_prompt`, `policies/*.rego`,
     `.agenomic/`, `.env`, `*.pem`, `*.key`, `id_rsa`, …).
   - **Path traversal / sensitive files** — blocks `..` escapes and writes to
     secret files.
   - **PII / exfiltration** — blocks PII (email, card numbers via Luhn, SSN,
     credential prefixes) or untrusted-provenance data heading to an
     **unapproved external recipient**.
   - **Irreversible effects** — `delete_*`, `deploy`, `transfer_funds`, … require
     human approval; from untrusted provenance they are blocked outright.
2. **The existing Rego gate** (`agenomic-policy`) — reused, never bypassed. A
   Rego `deny`, or an unsatisfied `allow`, is a hard block. The gate hands Rego
   an enriched context (`is_irreversible`, `has_pii`, `is_external_sink`, …) so
   policies can reason without re-deriving.

## Provenance: the gate does not trust the model

Every tool call carries the **provenance** of its arguments. Anything derived
from model output, tool output, an MCP server response, or a skill file is
`untrusted` — and `untrusted` is the **default**, so a call with no stated
provenance is assumed attacker-influenced. Untrusted calls are held to stricter
rules: untrusted egress to an unapproved recipient is exfiltration (block), and
an untrusted irreversible effect is blocked rather than queued for review.

## Verdicts and exit codes

| Verdict                 | Meaning                                  | Exit |
|-------------------------|------------------------------------------|------|
| `Allow`                 | May proceed                              | 0    |
| `Block`                 | Denied (hard)                            | 16   |
| `RequireHumanApproval`  | Paused pending a signed human decision   | 18   |

Exit 16 reuses the governance `block` code (`OsPolicyViolation`); 18
(`ToolBoundaryReviewRequired`) is distinct so scripts can tell a denial from a
pause.

## Signed audit trail

Every passage through the gate seals signed ATEP events, chained onto each
stream's head and verifiable with `agenomic atep verify`:

- **`policy` stream**: `tool.call.proposed` → `policy.check.performed` →
  `tool.call.approved | tool.call.blocked | tool.call.executed`.
- **`governance` stream**: `human.review.requested`, and on resume
  `human.review.approved | rejected | modified` — each carrying the reviewer's
  **role, justification and timestamp**.

Raw arguments never appear in a payload; only their content-addressed BLAKE3
hash does, so a sensitive tool argument never leaks into the audit trail.

## Usage

```sh
# One-shot check (exit code is the verdict). --policy points at a dir holding a
# `policies/` folder (Rego) and an optional `gate.json` rule override.
agenomic gate check tool-call.json --policy ./bundle

# Seal the passage as signed ATEP events.
agenomic gate check tool-call.json --policy ./bundle \
  --atep ./store --signing-key key.pem

# Resume a held (RequireHumanApproval) call with a signed human decision.
agenomic gate check tool-call.json --policy ./bundle \
  --approval approval.json --executed \
  --atep ./store --signing-key key.pem
```

A tool call:

```json
{
  "tool": "send_email",
  "provenance": "untrusted",
  "scopes": ["email.send"],
  "arguments": { "to": "x@example.com", "body": "…" }
}
```

A signed human approval (`role` / `justification` / `timestamp` are mandatory):

```json
{
  "disposition": "approved",
  "role": "oncall-sre",
  "justification": "ticket OPS-1234 verified",
  "timestamp": "2026-06-23T10:00:00Z"
}
```

## Customising the rule set

Drop a `gate.json` next to the Rego `policies/` directory (or pass `--rules`).
It is merged over the safe built-in defaults — a partial file only overrides
the fields it names:

```json
{
  "allowed_tools": ["read_file", "send_email", "get_weather"],
  "approved_recipients": ["@corp.com"],
  "irreversible_tools": ["delete_record", "deploy", "send_payment"]
}
```

## Scope note

The gate ships as a library (`agenomic-gate`) plus the standalone `gate check`
command. Intercepting *individual* tool calls inside a running agent belongs in
the runtime adapter: the subprocess launcher in `agenomic-os` does not surface
per-call effects to the CLI. The library is pure (no IO, crypto or clock), so an
adapter can embed it directly at the effect boundary.
