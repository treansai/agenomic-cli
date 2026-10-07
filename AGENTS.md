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
- `agenomic prompts push` tolerates unresolved fragment pins in its offline
  check: fragments are server-side versions, and the server validates
  them at publish time.
- `agenomic prompts get` also reads the prompt metadata route, because the
  version document carries no prompt-level kind (`fragment` and `text`
  share text content) and the prompt file needs it.
- `agenomic prompts pull --all` verifies the digest of every version on
  every page before it writes the first file, so a bad version never
  leaves a partial directory behind
  (`pull_all_writes_nothing_when_any_version_fails_its_digest`).
- `agenomic channels promote` and `rollback` are hand-off commands
  (amendment AM4): channel moves are session only and the CLI holds an API
  key, so they call only the read-only move preview and print where a
  person completes the move. The preview returns a web path; `--web-url`
  or `AGENOMIC_WEB_URL` turns it into a full address.
- In a move preview, `candidate` is the release the move would point the
  channel to, also for a rollback (the `--to-release` value or the
  cloud's default target). `agenomic channels rollback` therefore prints
  `candidate` as its `target` and adds `rollback.default_target` only
  when the two differ: printing the default target alone showed another
  release than the one the gates evaluated, which a run against a real
  gateway revealed
  (`channels_rollback_to_release_prints_the_evaluated_target`).
- `CliError::CloudRefused` maps a coded cloud refusal by status (409 to the
  new exit code 21, 401 and 403 to 5, 400, 404 and 422 to 1, the rest to
  6). Its body excerpt is cut on characters, not bytes, so a non-ASCII
  error body cannot panic.
- `truncate_for_error` cuts on a character boundary too: `prompts export`
  and URI references call `whoami`, and a whoami body over 240 bytes with
  a multibyte character across byte 240 (a localized web page behind a
  wrong endpoint) made the command panic
  (`export_reports_a_non_ascii_whoami_body_without_panicking`). The two
  whoami messages these commands print use a colon and a semicolon
  instead of em dashes, like the `HashMismatch` text.
- Help text of the new clap commands uses `about` and `help` attributes
  rather than doc comments, so that no new comments are added.
- The prompt schemas under `schemas/` are verbatim copies of the
  specification `v0.4` files with their `$id`s; `agenomic_spec::validator`
  registers them as documents so their relative `$ref`s resolve offline.
- `crates/agenomic-cli/tests/prompts_cli.rs` removes every `AGENOMIC_*`
  variable from the child environment so a developer profile cannot leak
  into the snapshots.
- `crates/agenomic-prompt/.gitattributes` turns off line-ending conversion
  for the vendored vectors: the harness hashes their raw bytes against
  `MANIFEST.json` and the lock, so a CRLF checkout on Windows would fail.
  The CLI tests also normalize `\` to `/` before snapshotting paths.
- `secrets::scan` counts code points incrementally from the previous hit
  of each pattern instead of recounting the prefix for every hit, which
  was quadratic in the number of findings
  (`many_findings_keep_exact_offsets_in_linear_time`).

## Coding connector (`connector/`, TypeScript)

- The machine connector is a Node package, not a Rust crate: the Claude Agent SDK is the supported way to drive Claude Code programmatically and ships for TypeScript; `codex app-server` is spoken over stdio from the same process. It is optional and network bound by nature, so it lives outside the offline `agenomic` binary and does not change its invariants.
- Sources ship as `.ts` and run with Node's type stripping (Node >= 22.18): no parameter properties, enums or namespaces (`erasableSyntaxOnly`). `npm run typecheck` is `tsc --noEmit`.
- Never forces an allow: a PreToolUse answer is either an explicit deny or no output, so native permission rules still apply. Fail-closed hooks answer an explicit deny within a deadline below the native timeout.
- The launcher (`bin/agenomic-connector.mjs`) exits only after stdout and stderr are flushed, never with a bare `process.exit()`: a write to a pipe the runtime is not draining yet completes asynchronously, and a dropped denial would leave the runtime its native fallback.
- A launched Codex session in shadow or enforce starts only once Codex, asked again after the installer recorded the trust, lists the exact PreToolUse command the managed block declares, from the session's own `config.toml`, enabled and `trusted` (`installCodex(...).preToolUse`); other trusted Agenomic hooks only observe and do not count. `hooks install` exits 1 and `doctor --probe` does not run the Codex terminal session without it.
- Every stdio pipe of a spawned runtime (Codex App Server, Claude Code, the `hooks/list` App Server) has an `error` listener: an EPIPE once the process closed its input would otherwise crash the daemon. The Codex adapter then fails its pending calls at once (and refuses writes to a closed input), and both adapters stop the process so the session ends through its normal exit path.
- Every admitted action is settled when its runtime ends, however it ends (stop, session end, crash or kill): the daemon runs `SessionContext.settleFinal` when an adapter's `done` resolves, so retained outcomes are delivered and unreported actions settle as `unknown` instead of staying open. A settlement still retrying when a resumed runtime ends again is shared, and the actions opened since get a settlement of their own.
- Logs never carry a credential: the daemon registers the runner's tokens and both runtimes' credential values with `redactLogsWith`, and `log()` redacts every line with them and the known patterns. Runtime, SDK and provider errors are still logged bounded through `ctx.cleanText`, and command refusals and hook error replies are redacted with the same values before they leave the daemon.
- A launch records the real path of its workspace checkout (`workspace_root`) with the session. A workspace id can be declared again for another checkout (`workspace add`), so a resume is refused (`workspaceMoved`) unless the declared workspace's real path is that root and the session directory lies in that checkout or is a worktree of its repository (same git common directory); a record without the root is checked on the directory alone.
- Capabilities are announced in `src/capabilities.ts` and validated per machine and runtime version by `doctor --probe`; `unknown` is never usable.
- A local (terminal) session's capabilities are computed for the version of the CLI that runs it, never the configured executable's: the hook sends `invoker`, the runtime process's executable (`invokingExecutable` walks `/proc` past shells, and to the script of a Node or Bun process, which `scriptOf` reads past options given as two arguments such as `-r x.js` and after `bun run`), and the daemon reads its `--version` with the cached reader. Without an invoker (non-Linux, a command line whose script is not known for certain, a binary deleted or a binary or script changed after the process start time of `/proc/<pid>/stat`, as an npm update of a running CLI does) the version is unknown, so an enforce session is blocked.
- `Daemon.connect` waits up to `versionWaitMs` (3 s) for the session's runtime `--version`; the background read never blocks heartbeats, and a hook waits only on the first session of a binary revision (the answer is cached). A session connected while it is still unknown is reported unknown (enforce blocked), then `refreshMode` reports its mode, protection and capabilities again once the version answers, only when they changed and only while the session is still connected.
- Unit tests: `npm test`. End to end against a real gateway: `test/e2e.test.ts` (see its header).
