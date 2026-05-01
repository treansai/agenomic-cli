# Command reference

Every `agentlock` command, their flags, and exit codes.

## Global flags

| Flag | Env | Description |
| --- | --- | --- |
| `--profile <NAME>` | `AGENTLOCK_PROFILE` | Override the active profile |
| `--no-color` | `AGENTLOCK_NO_COLOR` | Disable ANSI color in human output |
| `--format <FORMAT>` | `AGENTLOCK_FORMAT` | `human` (default), `json`, `json-pretty`, `yaml` |

## Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | All good |
| 1 | ValidationFailed | A schema or required-file check failed |
| 2 | InvalidUsage | clap rejected the command-line args |
| 3 | InternalError | Unexpected I/O / serialization failure |
| 4 | SecurityViolation | Path traversal, symlink, or credential file detected |
| 5 | CloudAuthFailed | 401 from the cloud, or no credentials configured |
| 6 | NetworkError | Cloud HTTP failure after retries |
| 7 | ContractFailed | `agentlock replay` saw violations at or above `--fail-on` |
| 8 | DiffRiskExceeded | `agentlock diff` found a change at or above `--fail-on` |
| 9 | AttestationVerificationFailed | `agentlock verify` failed a check |
| 10 | AtepIntegrityFailed | ATEP signature, merkle root, or CRC failed |

## Commands

### `agentlock init [PATH]`

Scaffold an empty bundle directory with `genome.yaml`, `agent.lock.yaml`,
`behavior.contract.yaml`, and `prompts/system.md`.

### `agentlock validate <PATH> [--level basic|strict|ci]`

Validate a bundle directory or `.tar.zst` archive.

### `agentlock build <DIR> --output <FILE> [--compression-level N] [--strict] [--allow-symlinks]`

Build a `.bundle.tar.zst`.

### `agentlock inspect <PATH>`

Print a high-level bundle summary.

### `agentlock hash <PATH> [--prefix]`

Print the canonical `logical_bundle_hash`.

### `agentlock diff <BASELINE> <CANDIDATE> [--fail-on critical] [--ignore-prompts-whitespace]`

Diff two bundles. Exits 8 if any change ≥ `--fail-on`.

### `agentlock replay <BUNDLE> [TRACES] [--from-atep DIR] [--contract FILE] [--runs-per-trace N] [--fail-on SEV] [--output FILE]`

Run a deterministic local replay.

### `agentlock attest <BUNDLE> [--replay-report FILE] [--atep DIR] [--sign-with KEY] [--generate-key PATH] --output FILE`

Create a release attestation. With `--generate-key PATH` only generates a
fresh ed25519 key.

### `agentlock verify <ATTESTATION> [--atep DIR]`

Verify an attestation. With `--atep DIR`, additionally re-checks that the
ATEP store's merkle root matches the embedded `atep_root_hash`.

### `agentlock atep init <PATH> --agent-id <ID> --signing-key <FILE>`

Initialize a new ATEP store.

### `agentlock atep append <PATH> --stream <S> --type <T> [--payload-file FILE] --signing-key <FILE>`

Append a single signed event to a stream.

### `agentlock atep verify <PATH> --public-key <FILE>`

Verify all segment merkle roots and event signatures.

### `agentlock atep inspect <PATH>`

Print the manifest.

### `agentlock atep replay-state <PATH> [--at RFC3339] [--output FILE]`

Reconstruct an `AgentState` projection.

### `agentlock cloud login --endpoint URL --api-key KEY`

Persist a Cloud profile (mode 0600 credentials file).

### `agentlock cloud whoami`

Call `/v1/whoami` against the configured profile.

### `agentlock cloud logout`

Delete credentials for the active profile.

### `agentlock bundle extract <ARCHIVE> <DIR>`

Extract a `.bundle.tar.zst`.

### `agentlock bundle manifest <PATH>`

Print the canonical Merkle manifest as JSON.

### `agentlock trace validate <PATH>` and `agentlock trace summarize <PATH>`

Validate / summarize a JSONL trace file.

### `agentlock doctor`

Run system diagnostics; emits JSON.

### `agentlock completions <SHELL>`

Print a shell completion script (bash, zsh, fish, powershell, elvish).
