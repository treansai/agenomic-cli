# Hugging Face Agent (example)

A minimal Agenomic agent that declares a [Hugging Face](https://huggingface.co)
model as its runtime provider. It demonstrates how the Hugging Face provider
participates in validation, building, diffing, lockfile pinning, and replay.

## Layout

```
huggingface-agent/
├── genome.yaml             # declares provider: huggingface
├── agent.lock.yaml         # pins revision + resolved commit + content hashes
├── behavior.contract.yaml
└── prompts/system.md
```

## Genome

```yaml
runtime:
  model_provider: 'huggingface'           # also accepts 'hf' / 'hugging_face'
  model_id: 'mistralai/Mistral-7B-Instruct-v0.3'
  task: 'text-generation'
  revision: 'main'
  temperature: 0.2
  parameters:
    temperature: 0.2
    max_tokens: 1024
```

## Configuration

Set a token (either name works; `HUGGINGFACE_API_TOKEN` wins if both are set):

```bash
export HUGGINGFACE_API_TOKEN=hf_xxx        # or: export HF_TOKEN=hf_xxx
# optional:
export HUGGINGFACE_ENDPOINT_URL=https://my-endpoint.endpoints.huggingface.cloud
export HUGGINGFACE_DEFAULT_MODEL=mistralai/Mistral-7B-Instruct-v0.3
export HUGGINGFACE_TIMEOUT_SECONDS=30
```

Tokens are never written to logs, traces, lockfiles, reports, or error
messages.

## Sample CLI commands

```bash
# List providers and whether each is configured in this environment.
agm providers list

# Validate token + connectivity, and resolve model metadata (no token needed
# for public models). Prints a redacted summary — never the token.
agm provider test huggingface --model mistralai/Mistral-7B-Instruct-v0.3

# Validate this bundle (schema + Hugging Face semantic checks).
agm validate examples/huggingface-agent --level strict

# Build a reproducible bundle (HF metadata travels in the lockfile; no secrets).
agm build examples/huggingface-agent -o /tmp/hf-agent.bundle.tar.zst

# Diff against a modified copy to see model/revision/parameter changes.
agm diff /tmp/hf-agent-v1.bundle.tar.zst /tmp/hf-agent-v2.bundle.tar.zst
```

## Expected behavior

- `agm validate` **accepts** this genome. It rejects a Hugging Face genome whose
  `endpoint_url` carries inline credentials, and warns on `http://` endpoints.
- `agm build` includes the `model:` block (provider, model_id, revision,
  resolved_commit, task, and the `*_hash` reproducibility fields) without
  leaking any token.
- `agm diff` reports `model_revision_changed` (replay required),
  `model_parameters_changed`, `model_task_changed`, `model_endpoint_changed`,
  and `model_provider_changed` clearly.
- `agm replay` runs offline against the recorded trace; live Hugging Face calls
  require `HUGGINGFACE_API_TOKEN` / `HF_TOKEN`.
