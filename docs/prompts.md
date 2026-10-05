# Managed prompts in the CLI

The CLI covers the minimal managed prompts surface: read and publish
prompt versions, render them offline, export signed prompt bundles,
and inspect release channels. The Python SDK has the full surface
(scanner, importer, LangGraph adapter, experiments).

Everything that renders or verifies runs locally in the
`agenomic-prompt` crate, with no network access. Parity with the
Python and TypeScript SDKs and with the server comes from the shared
conformance vectors of RFC 0012 (see "Conformance" below).

## The prompt file

`agenomic prompts get`, `pull` and `push` read and write the
single-prompt file `agenomic.prompt_file/v1`
(`schemas/prompt-file.schema.json`). The CLI reads JSON only.

```json
{
  "schema": "agenomic.prompt_file/v1",
  "prompt_id": "prm_support_planner",
  "name": "Support planner",
  "description": "Plans the next support step.",
  "tags": ["support"],
  "kind": "chat",
  "content": {
    "schema": "agenomic.prompt_content/v1",
    "template_format": "agenomic-fstring/v1",
    "renderer_version": "1",
    "kind": "chat",
    "body": [
      { "role": "system", "content": "You plan support work for locale {locale}." },
      { "placeholder": "history", "optional": true },
      { "role": "user", "content": "{question}" }
    ],
    "variables": {
      "history": { "type": "messages", "required": false },
      "locale": { "type": "string", "required": false },
      "question": { "type": "string", "required": true }
    },
    "partials": { "locale": "en" },
    "output_contract": null,
    "fragments": {}
  },
  "parent_version": 6,
  "change_message": "Ask for the order id first",
  "version": 7,
  "content_digest": "sha256:..."
}
```

- `content` is the hashed document. `content_digest` is
  `sha256:` + hex(sha256(canonical JSON of `content`)).
- `kind` is the prompt-level kind (`text`, `chat` or `fragment`) and
  must agree with `content.kind` (`fragment` prompts have text content).
- `version` and `content_digest` are written by `get` and `pull` and are
  read only. `push` refuses a file whose `content_digest` does not match
  its content, and never uses `version`: the server allocates it.

## Reading prompts

```bash
agenomic prompts list --query planner --tag support
agenomic prompts get prm_support_planner:7 -o planner.json
agenomic prompts get prm_support_planner@staging     # resolved once, to an immutable version
agenomic prompts pull prm_support_planner --all --dir prompts
```

A bare `prm_x` means the latest version. Every download recomputes the
content digest of each version before anything is written; a mismatch
exits 1 and nothing is written. `get` and a single-version `pull` also
download and verify the fragments the version includes. `pull --all`
verifies every version of every page first and writes the files only
then; it does not download fragments (each content digest already
covers its fragment pins).

## Publishing a version

```bash
agenomic prompts push planner.json --dry-run      # local checks only, nothing sent
agenomic prompts push planner.json --message "Shorter plan steps"
```

`push` checks the file against its schema, checks `content_digest` when
present, validates the template and computes the digest locally, then
publishes with `parent_version` from the file. The server allocates the
next version; pushing the same file twice returns the same version
(`already published`). When the prompt does not exist yet, it is created
first from `prompt_id`, `kind`, `name` (defaults to the prompt id),
`description` and `tags`.

To publish an edit of a pulled version, set `parent_version` to the
pulled `version` and remove `version` and `content_digest`. When another
version was published in the meantime the cloud answers
`prompt_version_conflict` and the command exits 21: pull again and
re-apply the edit.

Fragments (`{>name}` includes) are resolved and checked by the server at
publish time; the local check of `push` validates everything it can
without them.

## Rendering

```bash
agenomic prompts render planner.json --var question="Where is my parcel?"
agenomic prompts render prm_support_planner:7 --vars vars.json --format json
agenomic prompts render planner.json --var question=hi --server
```

- `--var NAME=VALUE` passes a string; `--vars FILE` passes a JSON object
  for typed variables (integers, booleans, `json`, `messages`).
- A text prompt prints its text. A chat prompt prints its messages as
  JSON. `--format json` prints `{kind, text, messages, content_digest,
  rendered_hash, warnings}`.
- Missing, unknown or mistyped variables fail before anything is
  printed, with exit 1.
- `--server` also renders with `POST /v1/prompts/render` and exits 1 when
  the two `rendered_hash` values differ.
- Execution contexts need a version or an alias: `render prm_x` is
  refused with `prompt_ref_unversioned`.

## Offline prompt bundles

```bash
agenomic prompts export --agent <AGENT_ID> --channel production -o bundle.json \
  --trust-key orgkey.pem --expires-in-days 30
```

`export` downloads the signed `agenomic.prompt_bundle/v1` document,
verifies every content digest, every manifest digest, the artifact set
digest, the exact closure and the workspace and agent scope, verifies the
signature when `--trust-key` is given, and only then writes the file. It
prints `prompt_bundle_digest`: pin it in the runtime as
`expected_bundle_digest` (Python) or `expectedBundleDigest`
(TypeScript).

The trust key is the organization signing key in PEM form (SPKI
`BEGIN PUBLIC KEY` or raw `BEGIN ED25519 PUBLIC KEY`). The key embedded in
the bundle is never trusted.

Render a slot from a bundle without any network access:

```bash
agenomic prompts render --bundle bundle.json --slot planner.instructions \
  --workspace <WORKSPACE_ID> --agent <AGENT_ID> \
  --expect-bundle-digest sha256:... --var question=hi
```

A bundle loads only when it is pinned by `--expect-bundle-digest` or
signed by the `--trust-key` key (`bundle_untrusted_key` otherwise), when
it has not expired, and when it belongs to the expected workspace and
agent. A signed bundle loaded through its signature must also be
governed (`approved`); a digest pin is the operator's approval. Digest
failures exit 1, signature and trust failures exit 9.

## Channels and the promotion hand-off

```bash
agenomic channels list --agent <AGENT_ID>
agenomic channels history --agent <AGENT_ID> production
agenomic channels promote --agent <AGENT_ID> production --release <RELEASE_ID>
agenomic channels rollback --agent <AGENT_ID> production [--to-release <RELEASE_ID>]
```

Channel moves are session only, and the CLI authenticates with an API
key, so `promote` and `rollback` are hand-off commands. They call only
the read-only move preview, print the current and candidate releases
with their digests, the gates, the approvals and the actions available
to this credential, and print where an authorized person completes the
move in the web app. They exit 0 when the preview succeeded and never
move a channel.

The preview returns a web path. Pass `--web-url https://<your web app>`
or set `AGENOMIC_WEB_URL` to print the full address.

## Exit codes

| Code | When |
| --- | --- |
| 0 | Success |
| 1 | Local validation or render error, digest mismatch, a 400, 404 or 422 from the cloud |
| 5 | Missing credentials, a 401 or 403 from the cloud |
| 6 | Network error or a 5xx from the cloud |
| 9 | Bundle signature, trust, expiry or governance failure |
| 21 | A 409 from the cloud, for example a stale `parent_version` |

## Conformance

The `agenomic-prompt` crate implements the reference grammar, the
canonical JSON and digests, the `agenomic-fstring/v1` renderer, the
`agenomic-secrets/1` patterns and the bundle load procedure of RFC 0012.
It vendors the conformance vectors of the specification repository under
`crates/agenomic-prompt/tests/vectors/`, pinned by `SPEC_VECTORS.lock`
(the specification commit and the sha256 of `MANIFEST.json`):

```bash
cargo test -p agenomic-prompt --test conformance
```

The harness checks the lock and every file hash, then runs every vector
whose `consumers` list names `rust-cli`. To update the vectors, copy
`conformance/vectors/prompts/` from the specification repository at the
new commit and rewrite the lock with that commit and the new manifest
digest.

## Limits of this version

- JSON only: YAML prompt files and prompts files are read by the Python
  SDK.
- No draft editing, alias moves, imports or experiments: use the web app
  or the Python SDK.
- Bundle signatures are verified against one trusted key per command.
