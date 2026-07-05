# Hugging Face provider

Agenomic supports [Hugging Face](https://huggingface.co) as a first-class model
provider. You can reference Hugging Face models in an agent genome, validate and
build the bundle, pin a reproducible lockfile, diff model/revision/parameter
changes, and run text generation or embeddings through the public Inference API
or a dedicated Inference Endpoint.

The provider is **opt-in**: agents that use OpenAI, Anthropic, local, or other
providers are unaffected, and no Hugging Face credentials are required unless you
use the provider.

## Provider name and aliases

The canonical provider name is `huggingface`. These aliases are accepted
everywhere a provider is named (case-insensitive, `-`/`_` interchangeable):

| Alias          | Normalises to |
| -------------- | ------------- |
| `huggingface`  | `huggingface` |
| `hf`           | `huggingface` |
| `hugging_face` | `huggingface` |

## Setup

Set an access token. Both names are supported; `HUGGINGFACE_API_TOKEN` takes
precedence over `HF_TOKEN`:

```bash
export HUGGINGFACE_API_TOKEN=hf_xxx     # preferred
export HF_TOKEN=hf_xxx                  # fallback
```

### Environment variables

| Variable                    | Required | Purpose |
| --------------------------- | -------- | ------- |
| `HUGGINGFACE_API_TOKEN`     | one of   | Access token (preferred). |
| `HF_TOKEN`                  | one of   | Access token (fallback). |
| `HUGGINGFACE_ENDPOINT_URL`  | no       | Dedicated Inference Endpoint URL. Overrides the serverless Inference API. |
| `HUGGINGFACE_ORG`           | no       | Organization / user namespace. |
| `HUGGINGFACE_DEFAULT_MODEL` | no       | Model id used when a command omits one. |
| `HUGGINGFACE_TIMEOUT_SECONDS` | no     | Per-request timeout (default 30). |

Secrets are **never** hardcoded, printed, or written to logs, traces, reports,
lockfiles, or error messages. See [Security](#security) below.

## Genome configuration

Declare the model in the genome `runtime` block:

```yaml
runtime:
  model_provider: 'huggingface'
  model_id: 'mistralai/Mistral-7B-Instruct-v0.3'
  task: 'text-generation'        # optional: text-generation, embeddings, classification, …
  revision: 'main'               # optional: branch, tag, or commit SHA
  endpoint_url: 'https://my-endpoint.endpoints.huggingface.cloud'  # optional
  organization: 'my-org'         # optional
  temperature: 0.2
  parameters:                    # optional provider generation parameters
    temperature: 0.2
    max_tokens: 1024
```

Only `model_provider` and `model_id` are required. The Hugging Face declaration
participates in canonical hashing, lockfile generation, diffing, replay baseline
comparison, release attestation, and drift detection like any other model.

## Lockfile

When the model is resolved (e.g. via `agm provider test`), the lockfile `model:`
block pins enough to make the release reproducible:

```yaml
model:
  provider: 'huggingface'
  model_id: 'mistralai/Mistral-7B-Instruct-v0.3'
  revision: 'main'
  resolved_commit: 'e0bc86c23ce5aae1db576c8cca6f06f1f73af2db'
  task: 'text-generation'
  endpoint_ref: 'https://my-endpoint.endpoints.huggingface.cloud'  # redacted reference, if set
  endpoint_hash: '…'        # BLAKE3 of the endpoint URL
  metadata_hash: '…'        # BLAKE3 of resolved metadata
  parameter_hash: '…'       # BLAKE3 of canonical parameters
```

If exact remote metadata is unavailable (no network or no token for a gated
model), resolution fails with a clear, secret-free warning and the build still
succeeds with whatever is declared in the genome.

## CLI

```bash
# List providers and configured state.
agm providers list

# Validate token + connectivity; resolve model metadata (token optional for
# public models). Output is redacted — the token is never shown.
agm provider test huggingface --model mistralai/Mistral-7B-Instruct-v0.3 --revision main

# Validate a genome/bundle, including Hugging Face semantic checks.
agm validate ./my-agent --level strict

# Build a reproducible bundle (HF metadata in the lockfile, no secrets).
agm build ./my-agent -o my-agent.bundle.tar.zst

# Diff two bundles — model/revision/task/endpoint/parameter changes are shown.
agm diff old.bundle.tar.zst new.bundle.tar.zst

# Enrichment can route to Hugging Face when the genome (or --provider) selects it.
agm enrich ./my-agent --provider huggingface
```

`agm diff` emits these Hugging Face-aware change types:

| change_type               | Severity | Replay required |
| ------------------------- | -------- | --------------- |
| `model_provider_changed`  | High     | no              |
| `model_id_changed`        | High     | no              |
| `model_revision_changed`  | High     | **yes**         |
| `model_task_changed`      | Medium   | no              |
| `model_endpoint_changed`  | Medium   | no              |
| `model_parameters_changed`| Medium   | no              |

## SDKs

Python:

```python
from agenomic import Client

client = Client()
agent = client.agent.load("./my-agent")
agent.configure_model(
    provider="huggingface",
    model="mistralai/Mistral-7B-Instruct-v0.3",
    task="text-generation",
)
```

TypeScript:

```ts
const client = new AgenomicClient();
await client.models.configure({
  provider: "huggingface",
  model: "mistralai/Mistral-7B-Instruct-v0.3",
  task: "text-generation",
});
```

## Cloud

Agenomic Cloud can store a Hugging Face connection per organization with the
token encrypted at rest (KMS envelope encryption, tenant-isolated). See the
cloud connection guide for `POST /v1/providers/huggingface/connect`,
`POST /v1/providers/huggingface/test`, `GET /v1/providers`, and
`DELETE /v1/providers/huggingface`.

## Security

- The token is held in a `SecretString`, read only from the environment.
- No token appears in trace events, replay reports, release attestations,
  evidence packages, lockfiles, error messages, or frontend state beyond the
  initial submission.
- Every error path scrubs the configured token and any `hf_…`-shaped string.
- `endpoint_url` must not contain inline credentials (`user:pass@host`);
  `agm validate` rejects it if it does, and warns on `http://` endpoints.
- There is no silent fallback to another provider; selecting Hugging Face
  without a token fails with a clear, actionable error.

## Limitations

- `agm provider test` performs a live connectivity probe; CI/offline flows
  should run `agm validate`/`agm build`, which require no network.
- Embeddings and text generation are routed through the serverless Inference API
  unless `HUGGINGFACE_ENDPOINT_URL` is set; serverless availability depends on
  the model.
- `resolved_commit` is captured only when the Hub reports a `sha` for the
  requested revision.
