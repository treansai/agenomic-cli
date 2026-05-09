# Local replay

`agenomic replay` evaluates a corpus of stored traces against a behavior
contract's deterministic checks. **It does not call any LLM.**

## What it does

- Loads the bundle's manifest (or the supplied bundle dir/archive).
- Loads the contract from the bundle (or `--contract FILE`).
- Loads traces from a JSONL file (or from an ATEP store via `--from-atep DIR`).
- Runs each rule's deterministic check across every trace.
- Emits a `replay-report` JSON document and a tabular human summary.

## What it does NOT do

- It does **not** call your LLM provider.
- `--runs-per-trace > 1` is **a no-op** in v0.1 and emits a warning. That
  mode requires a runtime adapter (provider plugin), which is part of
  Agenomic Cloud or a custom integration.

## Exit codes

- `0` — all checks pass at the configured `--fail-on` threshold.
- `7` — at least one violation at or above `--fail-on`.

## Honest disclaimer

The intent of local replay is to give a fully offline, deterministic
**lower-bound** proof: "given exactly these traces, this contract holds".
It does not prove anything about new traces or about model stochasticity.
For statistical replay across LLM variation, use Agenomic Cloud.
