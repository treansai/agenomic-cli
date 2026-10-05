# agenomic-cli: agent instructions

This is the public open-source CLI for the Agenomic platform. AGPL-3.0-only.

## Product invariants

1. Works fully offline. No command requires network.
2. Deterministic hashing. Same input → same hash, always.
3. ATEP-native. Reads/writes/signs binary event streams matching the
   agenomic-cloud format.
4. Cloud is optional. Local commands stand alone.

## Engineering rules

- Every public function has a doc comment with at least one example.
- No `unwrap()` or `expect()` in non-test code.
- All errors use `miette::Diagnostic` for human output and have a stable code.
- Exit codes follow the catalog in `crates/agenomic-core/src/exit.rs`.
- Snapshot tests (`insta`) for any human-formatted output.
- Property tests (`proptest`) for hashing determinism and ATEP roundtrips.

## Naming

- Binary: `agenomic`
- Bundle file extension: `.bundle.tar.zst`
- ATEP segment file extension: `.atep`
- Default config: `~/.config/agenomic/config.toml`
- Project config: `agenomic.toml`

## Security defaults

- Symlinks rejected during bundle build unless `--allow-symlinks`.
- `.env`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519` always excluded.
- Bundle path traversal (`..`) rejected.
- Config files written with mode 0600.

## Managed prompts

New code for managed prompts carries no comments; the reasons live here.

- `crates/agenomic-prompt` is an independent implementation of RFC 0012
  (references, canonical JSON and digests, the `agenomic-fstring/v1`
  renderer, the `agenomic-secrets/1` patterns, bundle loading). There is
  no shared crate with the server or the SDKs on purpose: the vendored
  conformance vectors are the only parity mechanism, so a behaviour change
  starts with a vector in the specification repository, then the vendored
  copy and `SPEC_VECTORS.lock`.
- `canonical::canonical_json` writes the normative canonical form by hand
  (UTF-16 key order, the serde_json escape table, integral numbers below
  2^53 printed as integers). Every value is checked against the Agenomic
  JSON Subset first, so floats never reach a digest.
- Offsets in syntax errors and secret findings count Unicode code points,
  because the vectors pin code points for every language.
- `PromptBundle::load` has no escape hatch: a bundle loads only when it is
  pinned by `expected_bundle_digest` or signed by a trusted key. A digest
  pin skips the governance check because the pin is the operator's
  approval. `verify_exported` serves `agenomic prompts export`, which
  receives the document over the authenticated API: it always checks
  digests, closure and scope, and the signature only when `--trust-key`
  is given, before anything is written.
- `verifying_key_from_pem` also reads the raw `BEGIN ED25519 PUBLIC KEY`
  form because organization signing keys are published in that form.
- `agenomic prompts push` tolerates `fragment_not_found` in its offline
  check: fragments are server-side versions, and the server validates
  them at publish time.
- `agenomic prompts get` also reads the prompt metadata route, because the
  version document carries no prompt-level kind (`fragment` and `text`
  share text content) and the prompt file needs it.
- `agenomic channels promote` and `rollback` are hand-off commands
  (amendment AM4): channel moves are session only and the CLI holds an API
  key, so they call only the read-only move preview and print where a
  person completes the move. The preview returns a web path; `--web-url`
  or `AGENOMIC_WEB_URL` turns it into a full address.
- `CliError::CloudRefused` maps a coded cloud refusal by status (409 to the
  new exit code 21, 401 and 403 to 5, 400, 404 and 422 to 1, the rest to
  6). Its body excerpt is cut on characters, not bytes, so a non-ASCII
  error body cannot panic.
- Help text of the new clap commands uses `about` and `help` attributes
  rather than doc comments, so that no new comments are added.
- The prompt schemas under `schemas/` are verbatim copies of the
  specification `v0.4` files with their `$id`s; `agenomic_spec::validator`
  registers them as documents so their relative `$ref`s resolve offline.
- `crates/agenomic-cli/tests/prompts_cli.rs` removes every `AGENOMIC_*`
  variable from the child environment so a developer profile cannot leak
  into the snapshots.
