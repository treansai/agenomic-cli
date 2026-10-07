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
- Never forces an allow: a PreToolUse answer is either an explicit deny or no output, so native permission rules still apply. Fail-closed hooks answer an explicit deny within a deadline below the native timeout. A daemon connection that ends or closes before a complete reply line fails at once (`ask`), so the fail mode applies without waiting for that deadline.
- The launcher (`bin/agenomic-connector.mjs`) exits only after stdout and stderr are flushed, never with a bare `process.exit()`: a write to a pipe the runtime is not draining yet completes asynchronously, and a dropped denial would leave the runtime its native fallback.
- A launched Codex session in shadow or enforce starts only once Codex, asked again after the installer recorded the trust, lists the exact PreToolUse command the managed block declares, from the session's own `config.toml`, enabled and `trusted` (`installCodex(...).preToolUse`); other trusted Agenomic hooks only observe and do not count. `hooks install` exits 1 and `doctor --probe` does not run the Codex terminal session without it.
- A launched Claude Code session's sandbox denies reading the connector's home (`credentials.json`, `connector.json`, and under `state/` the other sessions' worktrees, the runtime homes, the spool) and re-allows only the session's own worktree, which lives below it in `state/worktrees/<id>`, with `allowRead` (`claudeSandboxFilesystem`): `allowRead` takes precedence over `denyRead` for the paths it names, so the session reads its checkout whichever way the platform's sandbox applies a denial to descendants (Seatbelt on macOS applies it to every descendant). Both rules name every spelling of their path (`spellings`, the real path when a symlink is on the way).
- A launched Codex session runs under the `agenomic-session` permissions profile that its own `config.toml` makes the default (`codexSessionConfig`): Codex's `:workspace` profile (read everywhere, write the worktree, `.git` and `.codex` read-only) without write access to /tmp and $TMPDIR, without network, and with the connector's home denied, so its shell commands cannot read `credentials.json`, `connector.json` or, under `state/`, the other sessions' worktrees and runtime homes; the worktree below that home stays readable and writable because Codex applies the most specific entry. The thread is started without a `sandbox` override (it would replace the profile with the legacy `workspace-write` mode, which reads the whole disk), and a thread whose `activePermissionProfile` is not `agenomic-session` (an older Codex, an `extra_config_toml` that sets `default_permissions`) is refused before its first turn. Codex hooks run outside that sandbox, so the PreToolUse hook still reaches the daemon socket.
- Every stdio pipe of a spawned runtime (Codex App Server, Claude Code, the `hooks/list` App Server) has an `error` listener: an EPIPE once the process closed its input would otherwise crash the daemon. The Codex adapter then fails its pending calls at once (and refuses writes to a closed input), and both adapters stop the process so the session ends through its normal exit path.
- No process the connector starts for a runtime inherits the daemon's environment: the managed runtimes and the auxiliary `hooks/list` App Server get `runtimeEnv` (PATH, their HOME and runtime variables, the configured `env_passthrough` and `extra_env`, nothing else; `hooks install` uses the developer's HOME and the configured Codex runtime's variables), and a runtime asked its `--version` gets only PATH and HOME. Only `git`, run by the daemon on the developer's checkout, keeps the daemon's environment.
- Every admitted action is settled when its runtime ends, however it ends (stop, session end, crash or kill): the daemon runs `SessionContext.settleFinal` when an adapter's `done` resolves, so retained outcomes are delivered and unreported actions settle as `unknown` instead of staying open. A settlement still retrying when a resumed runtime ends again is shared, and the actions opened since get a settlement of their own. A daemon stop (SIGINT/SIGTERM) also starts a final settlement for every session still connected, a local terminal session included: a tool still running when the daemon stops reports to a daemon that no longer knows its action, so its action settles as `unknown`. A hook request being answered when the daemon stops (an authorization, an approval being waited for) is cut by the stop's abort signal and waited for, so that an action the gateway admitted meanwhile is in its context before the handover, and a hook request reaching a stopping daemon is refused (the hook's fail mode applies); a closed `SessionContext` cuts its authorizations too. The stop waits for those hook requests and the final settlements in flight, bounded together by `shutdownSettleMs` (10 s), then `SessionContext.close` cuts the reports still in flight and hands over every retained outcome and an `unknown` for every other admitted action whose tool never reported, in every mode; a settlement that ran out of its 10-minute budget (`finalSettleMs`) keeps its context (and its retained outcomes) in the daemon even after a local session is forgotten, so the stop hands those over too. They are saved to `state/outcomes.json` and delivered by the next start (`deliverSaved`), which rewrites the file as each is acknowledged so none is delivered twice.
- No git output that grows with a checkout's change set is buffered whole (`src/workspace.ts`): diffs, `diff --numstat`/`--name-status`, the untracked listings and `git status` are read with `gitBounded`, which stops git past its limit and reports `more` instead of failing. The untracked listing of a captured diff (`withUntracked`) is read up to the diff's window, its cut entry dropped, and a listing read in part marks the diff `truncated`, so a huge untracked tree never turns a snapshot into `diff: null`; `inspect` reads `git status` up to 1 MiB for its first 500 preexisting changes. `git()` (whole output) is kept for commands whose output stays small (`rev-parse`, `worktree`, `update-ref`, `add`).
- The event spool never grows past `maxSpoolBytes` (64 MiB): `EventSink.spill` counts the bytes it is about to write, keeps only the lines that fit (evidence events first, in order) and counts the others in `events_dropped`.
- Logs never carry a credential: the daemon registers the runner's tokens and both runtimes' credential values with `redactLogsWith`, and `log()` redacts every line with them and the known patterns. A configured value is redacted whatever its length: one of eight characters or more wherever it occurs, a shorter one as a whole token (not inside a longer run of letters and digits; a terminal escape sequence just before it is a boundary, so coloured output does not hide it); only empty or blank values, and values that cannot be a credential (one character, or a boolean or toggle word such as `true` or `off`, as in `CLAUDE_CODE_USE_BEDROCK=1`), are skipped, so that every `1` of every event is not rewritten. Any other short value of a passed-through or secret-named variable (a two-digit setting included) is still redacted as a whole token. `clean()` redacts both before and after it strips control sequences. Runtime, SDK and provider errors are still logged bounded through `ctx.cleanText`, and command refusals and hook error replies are redacted with the same values before they leave the daemon.
- A launched Claude Code session registers the session id the runtime actually uses: the connector chooses one, and when Claude Code reports another (`system/init`) that one is registered instead, after start() initialized and never overwritten by the chosen id (`ClaudeSession.register` runs registrations in order and skips an unchanged id). `Daemon.registerNative` updates the route, the persisted `native_id` a resume uses and the gateway's session, and drops the route to the replaced id.
- A local (terminal) session belongs to the most specific declared workspace containing its directory (`workspaceOf`): real paths on both sides, compared on path-component boundaries (`/repo` does not contain `/repo2`), the longest match wins whatever the declaration order.
- A launch records the real path of its workspace checkout (`workspace_root`) with the session. A workspace id can be declared again for another checkout (`workspace add`), so a resume is refused (`workspaceMoved`) unless the declared workspace's real path is that root and the session directory lies in that checkout or is a worktree of its repository (same git common directory); a record without the root is checked on the directory alone.
- Capabilities are announced in `src/capabilities.ts` and validated per machine and runtime version by `doctor --probe`; `unknown` is never usable.
- A configured runtime executable (`runtimes.<runtime>.executable`) is an absolute path or a bare command name, never a relative path: `validateConfig` refuses `./bin/codex` or `bin/codex` with a configuration error (it would name a file in the daemon's directory for `--version` and the probe, and a repository-controlled one in the session's worktree at spawn). `loadConfig` looks a command name up once on the absolute directories of the daemon's PATH (`resolveExecutable` skips relative entries such as `.`) and keeps the absolute path, so version detection, the probe, `hooks install` and every spawn (`codexExecutable`, Claude Code's `pathToClaudeCodeExecutable`, through `runtimeExecutable`) use the same file; `saveConfig` writes the name back as configured. Every runtime process the connector starts (a session, `hooks/list`, the probe, a `--version` read) gets only the absolute directories of PATH (`absolutePath`, applied by `runtimeEnv` whichever of the daemon or `extra_env` set it): `.` or an empty entry (`:/usr/bin`, a trailing colon) would let the interpreter of a script runtime (`#!/usr/bin/env node`) come from the daemon's directory for `--version` and from the session's worktree at spawn. A runtime whose command is not found on PATH is unavailable, not a configuration error (`runtimeUnavailable`): the configuration still loads, so `run`, `status`, `doctor --probe` and the other runtime keep working; the daemon logs it and does not offer it, the probe skips it (`doctor` and `status` print why), and using it (a launch, `hooks install`) is refused with that reason. It is never looked up again until the configuration is loaded again. A missing absolute path loads too and fails when spawned.
- A local (terminal) session's capabilities are computed for the version of the CLI that runs it, never the configured executable's: the hook sends `invoker`, the runtime process's executable (`invokingExecutable` walks `/proc` past shells, and to the script of a Node or Bun process, which `scriptOf` reads past options given as two arguments such as `-r x.js` and after `bun run`), and the daemon reads its `--version` with the cached reader. Without an invoker (non-Linux, a command line whose script is not known for certain, a binary deleted or a binary or script changed after the process start time of `/proc/<pid>/stat`, as an npm update of a running CLI does) the version is unknown, so an enforce session is blocked.
- `Daemon.connect` waits up to `versionWaitMs` (3 s) for the session's runtime `--version`; the background read never blocks heartbeats, and a hook waits only on the first session of a binary revision (the answer is cached per path, device, inode, size, mtime and ctime, so a binary replaced with the same size and a restored mtime is asked again). A session connected while it is still unknown is reported unknown (enforce blocked), then `refreshMode` reports its mode, protection and capabilities again once the version answers, only when they changed and only while the session is still connected.
- Unit tests: `npm test`. End to end against a real gateway: `test/e2e.test.ts` (see its header).
