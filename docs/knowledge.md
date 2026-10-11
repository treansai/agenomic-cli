# Knowledge bases in the CLI

`agenomic knowledge` manages the knowledge bases of a workspace over the
Agenomic Cloud API: list and create knowledge bases, upload documents,
search, query and answer, create, compare, verify, publish and roll back
versions, follow jobs, and export or import a knowledge base. The
documents, identifiers and digests behind these commands are defined by
RFC 0014 of the Agenomic specification.

Unlike the offline commands, every `knowledge` command needs a cloud
profile (`agenomic cloud login`, or `AGENOMIC_ENDPOINT` and
`AGENOMIC_API_KEY`) and sends the API key in `x-api-key`. Nothing is
cached locally.

## Identifiers and versions

A knowledge base id is chosen by its creator and matches
`^kb_[a-z0-9]+(?:[_-][a-z0-9]+)*$` (64 characters at most), for example
`kb_customer_support`. The CLI refuses another id before sending
anything (exit 1, `agenomic::knowledge::invalid_kb_id`).

Every option that takes a version accepts:

| Value | Meaning |
| --- | --- |
| `3`, `v3` | the immutable version 3 |
| `published` | the version the knowledge base currently publishes |
| `draft` | the working set (editor access only) |

Numbers are sent as numbers. Leaving `--version` out lets the server use
the published version. Commands whose route names one version (`version
diff`, `version verify`, `publish`, `rollback --to`) take a number only
and refuse `published` and `draft` with
`agenomic::knowledge::version_number_required`.

## Reading and creating

```bash
agenomic knowledge list [--query Q] [--status S] [--tag T] [--limit N] [--cursor C]
agenomic knowledge get kb_customer_support
agenomic knowledge create kb_returns --name "Returns" --description "Return policies" --tag support
```

```text
KB ID                STATUS  HEALTH   PUBLISHED  LATEST  DOCUMENTS  NAME
kb_customer_support  active  healthy  v3         v4      7          Customer Support
kb_compliance        active  healthy  -          -       7          Compliance Policies
next page: --cursor WyJrYl9jb21wbGlhbmNlIl0
```

`get` prints the reference, the status and health, the published version
with its manifest digest, the latest version, the draft revision, the
publication generation (the value that `publish` and `rollback` send in
`If-Match`), and document and job counts.

## Uploading documents

```bash
agenomic knowledge upload kb_customer_support ./docs --glob '*.md' --prefix docs \
  --collection faq --tag refunds --classification public \
  --message "Révision des remboursements" --wait
```

- Each path is a file or a directory. A directory is walked recursively
  in file name order. Entries whose name starts with `.` (and everything
  below them) are skipped, symbolic links are skipped and never
  followed, and credential files (`*.pem`, `*.key`, `id_rsa`,
  `id_ed25519`, `.env*`) are skipped with a note on stderr. A credential
  file named on the command line is refused.
- `--glob PATTERN` keeps only the directory entries whose path relative to
  the directory matches; `*` also matches `/`, so `*.md` keeps every
  Markdown file at any depth. Repeat it to keep several patterns. Files
  named on the command line are not filtered.
- The document path is the relative path of the file (its file name for a
  file named on the command line), below `--prefix` when given, with `/`
  separators. Paths must be normalized: no empty, `.` or `..` segment, no
  `\`, no control character, 512 characters at most. Two files that map
  to the same document path are refused before the first upload.
- Documents are uploaded one by one with
  `POST /v1/knowledge-bases/{kb_id}/documents/upload`. The request body
  is the file itself, streamed as raw bytes (no multipart), with
  `content-type` (`application/octet-stream` unless `--content-type` is
  given: the server then infers the format from the path extension) and
  the headers `x-agenomic-document-path`, `x-agenomic-collection`,
  `x-agenomic-tags` (a comma separated list), `x-agenomic-classification`
  and `x-agenomic-change-message`. Every header value is percent-encoded
  UTF-8; `/` stays as is in the document path. Tags may not hold a comma.
- Uploading the same bytes to the same path again answers
  `created: false`, and the command reports the document as `unchanged`.
- The first refused upload stops the command; the documents uploaded
  before it stay in the working set.

```text
unchanged docs/faq.md (kdoc_01jb3m5q7s9v1x3z5b7d9f0001, revision 3)
uploaded  docs/guides/setup.md (kdoc_01jb3m5q7s9v1x3z5b7d9f0003, revision 2, job kjob_01jb3m5q7s9v1x3z5b7d9f0042)
uploaded  docs/guides/sécurité.md (kdoc_01jb3m5q7s9v1x3z5b7d9f0002, revision 1, job kjob_01jb3m5q7s9v1x3z5b7d9f0041)
job kjob_01jb3m5q7s9v1x3z5b7d9f0042 failed: knowledge_parse_failed: the document has no text
job kjob_01jb3m5q7s9v1x3z5b7d9f0041 succeeded
2 uploaded, 1 unchanged
```

With `--wait`, the command polls every returned ingestion job until it
succeeds, fails or is cancelled (at most `--timeout` seconds, 600 by
default) and exits 1 when one of them failed or was cancelled.

## Search, query and answer

```bash
agenomic knowledge search kb_customer_support "refund window" --version v3 --top-k 5 --mode hybrid --context
agenomic knowledge query kb_customer_support 'get "Refund Policy" from "faq/refunds-and-returns.md"'
agenomic knowledge answer kb_customer_support "How long is the refund window?"
```

- `search` (`POST .../search`) prints rank, score, injection risk,
  evidence id, path and heading path of each result, then the retrieval
  event. `--mode` is `keyword`, `semantic`, `hybrid` (the server
  default), `section` or `exact`. `--context` also prints the evidence
  rendered for a model, inside its `<knowledge_evidence>` delimiters.
- `query` (`POST .../query`) runs the text form of a structured query and
  prints the matches, the matched documents and the content of each
  returned section.
- `answer` (`POST .../answer`) prints the grounded answer, or
  `abstained: <reason>`, then the evidence with the cited items, the
  conflicts the server detected and the invalid citations. Each answer
  runs and bills a model call, so the client sends it once: a network
  error or a 5xx is reported (exit 6) and never retried.

Scores are rank derived, not probabilities. Retrieved text is untrusted
data: in human output every control character and invisible formatting
character is replaced by a space, so a document cannot move the cursor,
change colors or reorder the text in your terminal. `--json` prints the
response unchanged.

```text
RANK  SCORE  RISK    EVIDENCE  PATH                           HEADING
1     0.94   low     e1        faq/refunds-and-returns.md     Refunds and Returns / Refund Policy
2     0.61   medium  e2        faq/legacy-loyalty-program.md  Legacy Loyalty Program / Points Refunds
retrieval kret_01jb3m5q7s9v1x3z5b7d9f0001: kb_customer_support v3, hybrid
```

## Versions

```bash
agenomic knowledge versions kb_customer_support
agenomic knowledge version create kb_customer_support --message "Extend the refund window" --wait
agenomic knowledge version diff kb_customer_support 4 --against 3
agenomic knowledge version verify kb_customer_support 4
```

- `version create` snapshots the working set into a new immutable
  version (`POST .../versions`). It reads the knowledge base first and
  sends its `draft_revision` as `expected_draft_revision`, so the server
  can refuse the snapshot when the working set changed after the command
  read it. `--expected-draft-revision N` pins another revision. The
  request carries an idempotency key, so the automatic retries of the
  client after a network error or a 5xx are safe. `--wait` follows the
  build job like `upload --wait`.
- `version diff` (`GET .../versions/{n}/diff?against={m}`) prints the
  added, modified, deleted and moved documents with their revisions, the
  changed sections, metadata and index configuration, and the agents the
  change affects. Without `--against`, the server compares with the
  parent version.
- `version verify` (`GET .../versions/{n}/verify`) prints the server's
  recomputation of the manifest and document digests and the signature
  check, and exits 1 when any of them fails.

## Publication

```bash
agenomic knowledge publish kb_customer_support 4 --reason "Refund window extended"
agenomic knowledge rollback kb_customer_support --to 3 --reason "Wrong refund window"
```

Publishing and rolling back move the published pointer with a
compare-and-set: both commands read the knowledge base first and send its
`publication_generation` in `If-Match` (`POST .../publish` with
`{version, reason}`, `POST .../rollback` with `{reason, to_version}`).
When the pointer moved in between, the server answers 409, nothing is
published or rolled back, and the command exits 21 with the error code
and a hint to read the knowledge base again:

```text
hint: the publication of kb_customer_support moved after generation 4 was read, so nothing was rolled back; check `agenomic knowledge get kb_customer_support` and run the command again
error: cloud refused the request: knowledge_publication_conflict (HTTP 409): the publication generation moved [details: {"current_generation":5}]
```

Publishing and rolling back change what agents read, so the server may
reserve them to signed-in people: an API key then gets
`session_required` (exit 5) unless the knowledge base lets API keys
publish.

## Jobs

```bash
agenomic knowledge job kjob_01jb3m5q7s9v1x3z5b7d9f0047 [--wait] [--timeout SECONDS]
```

`job` reads `GET /v1/knowledge-jobs/{job_id}`. With `--wait` it polls
until the job is `succeeded`, `failed` or `cancelled` (the delay starts
at 250 ms and doubles up to 2 s) and exits 1 unless it succeeded; a job
still running after `--timeout` seconds exits 6 with
`knowledge_job_timeout`.

## Export and import

```bash
agenomic knowledge export kb_customer_support --version 3 -o kb.json
agenomic knowledge import kb.json --kb-id kb_customer_support_copy --name "Customer Support (copy)"
```

`export` reads `GET /v1/knowledge-bases/{kb_id}/export`. `--version 3`
(or `v3`) sends `?version=3` and `--version published` sends
`?version=published`; without `--version`, or with `--version draft`,
the command sends no `version` and the server exports the working set.
The server answers the
`agenomic.knowledge_export/v1` JSON document as an attachment; the
command checks that it is a JSON object and writes the response body to
the file byte for byte.

`import` reads the file and sends its bytes unchanged, with
`content-type: application/json`, as the body of
`POST /v1/knowledge-bases/import?kb_id=<id>&name=<name>`. Both query
parameters are optional and are left out when `--kb-id` and `--name` are
not given. The server accepts at most 17 MiB (16 MiB of documents plus
1 MiB of envelope), so the command refuses a larger file before sending
anything (`agenomic::knowledge::import_too_large`, exit 1), as well as a
file that is not a JSON object. The server answers 201 with the new
knowledge base, the number of imported documents and the number of jobs
it enqueued to index them:

```text
imported kb_customer_support_copy (Customer Support (copy))
uri:       kb://0b6c2f1e-7a44-4c8e-9f1d-2a3b4c5d6e7f/kb_customer_support_copy
documents: 1
jobs:      1 enqueued; `agenomic knowledge get kb_customer_support_copy` shows the pending ones
```

## JSON output

`--json` (anywhere after `knowledge`) is the same as `--format json`:
every command prints the response of the Agenomic Cloud API unchanged on
one line. `--format json-pretty` and `--format yaml` also work. Three
commands print another document:

- `upload` prints `{"kb_id", "documents": [...]}` with one upload
  response per document; with `--wait`, each `job` is the finished job.
- `version create --wait` prints the creation response with the finished
  job in `job`.
- `export` prints `{"path", "kb_id", "version", "schema", "bytes"}`; the
  exported document is in the file.

A failing `--wait` or `version verify` still prints its JSON before
exiting 1.

## Errors and exit codes

A refusal of the Agenomic Cloud API is reported with its error code,
message and details, for example
`cloud refused the request: knowledge_access_denied (HTTP 403): ... [reason: classification_exceeds_ceiling]`.

| Code | When |
| --- | --- |
| 0 | Success |
| 1 | Invalid argument (an import file above 17 MiB included), a failed or cancelled job with `--wait`, a failed `version verify`; a 400, 404 or 422 from the cloud |
| 3 | A local file could not be read or written |
| 5 | Missing credentials, a 401 or 403 from the cloud (for example `session_required`) |
| 6 | Network error, a 5xx from the cloud after retries (at once for `answer`), a `--wait` timeout |
| 21 | A 409 from the cloud, for example `knowledge_publication_conflict` |

## Limits of this version

- No document edits, deletions or collections, no agent bindings, no
  sources and sync, no version approval: use the web app, the Python
  SDK or the HTTP API.
- The CLI does not recompute knowledge digests itself; `version verify`
  asks the server to recompute them.
