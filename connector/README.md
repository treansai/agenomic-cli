# @agenomic/coding-connector

The Agenomic machine connector. It connects Claude Code and Codex sessions
on a machine to Agenomic: sessions you launch from agenomic.io run here,
in a dedicated git worktree, under the runtime's own sandbox; sessions you
start yourself in a terminal are reported through hooks you install
explicitly. AGPL-3.0-only.

It runs the real runtimes through their supported interfaces (Claude Agent
SDK, `codex app-server`, command hooks). It does not replace them, does not
proxy their model calls and does not attach to processes it did not start.

## Install and connect

```sh
npm install -g @agenomic/coding-connector      # Node >= 22.18, git; Linux: bubblewrap
agenomic-connector enroll --token agmcen_… --endpoint https://api.agenomic.io
agenomic-connector workspace add --id my-repo --path ~/src/my-repo
agenomic-connector doctor --probe              # validates capabilities on this machine
agenomic-connector run
```

- Only declared workspaces are reported. Nothing is scanned.
- Credentials are short lived, rotated, stored in
  `~/.config/agenomic/connector/credentials.json` (0600). They never reach
  the runtimes, which get a fresh environment with the provider variables
  you list (`runtimes.*.env_passthrough`, default `ANTHROPIC_API_KEY` /
  `OPENAI_API_KEY`).
- One outbound HTTPS connection; nothing listens on the network. Hooks talk
  to the daemon over a 0600 unix socket.

## Your own terminal sessions

```sh
agenomic-connector local-sessions --mode observe        # or shadow / enforce with --policy-ref
agenomic-connector hooks install --runtime claude-code --scope project --dir ~/src/my-repo [--dry-run]
agenomic-connector hooks install --runtime codex [--dry-run]
agenomic-connector hooks uninstall --runtime claude-code --scope project --dir ~/src/my-repo
```

Install keeps your existing hooks, is idempotent and backs the file up;
uninstall removes exactly what install added. Codex runs only trusted
hooks: the installer records trust for its own entries, by hash, because
you ran the command. Restart sessions that were open before the install.
When the daemon does not answer, a hook follows the current
`local-sessions` mode: enforce refuses the tool call, observe and shadow
let the runtime decide. Changing the mode needs no reinstall (hooks
installed by an earlier version keep a fixed mode until you run
`hooks install` again).
Local hooks are cooperative, not a security boundary (see
`agenomic-cloud/docs/coding/threat-model.md`).

## What is validated

`doctor --probe` runs the runtimes this machine is configured with (the
enabled ones, with their configured `executable`) against local scripted
model endpoints (no provider, no network) through the same adapters the
daemon uses, and checks effects on disk: a denied write is absent, a
write outside the worktree is blocked by the sandbox even when allowed,
an approved action runs only after its approval, a second message runs,
an interrupt cuts a 60 s command short, a stop is verified, a resume
continues in the same worktree, and the developer's uncommitted files
are untouched. For Codex it also runs a terminal `codex exec` session
with the connector's hooks installed, as for your own sessions: the
session is reported, a refused shell call does not run and a held one
runs only after its approval (Claude Code terminal sessions are not
probed yet, so their capabilities stay unvalidated). Results are stored
under the version the probed binary reports (`--version` for a
configured executable); the daemon reports the same version, so a probe
of one binary never validates another. A terminal session is validated
for the CLI that runs it, not for the configured one: its hook names the
runtime process that ran it (read from `/proc` on Linux), and the daemon
reads that binary's `--version`. When the hook cannot name it (other
systems, or a binary replaced since it started), nothing is validated
for the session and an enforce session is blocked. The daemon reads it in the
background: until the binary has answered, it reports `unknown` and
nothing is validated. Connecting a session waits up to 3 s for that
answer; a session connected before it is reported again (its
capabilities, and enforce instead of blocked when the version is
validated) as soon as the binary has answered. The cockpit only offers an
operation validated on the machine.

## Tests

```sh
npm test                 # unit tests (hooks install, fail-closed hook, spool, worktrees, redaction)
AGENOMIC_E2E_ENDPOINT=http://127.0.0.1:18080 \
AGENOMIC_E2E_SEED_DATABASE_URL=postgres://… node --test test/e2e.test.ts
```

The end to end test needs a running Agenomic API gateway with the coding
sessions migration (see `agenomic-cloud/docs/coding/implementation-report.md`).

## Licenses

The connector depends on `@anthropic-ai/claude-agent-sdk` (Anthropic
commercial terms; installed from npm, not redistributed here) and, as an
optional dependency, `@openai/codex` (Apache-2.0). Use a provider
authentication method allowed for your deployment; the connector never
reads claude.ai or ChatGPT session credentials.
