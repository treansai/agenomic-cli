# Changelog

All notable changes to `agenomic-cli` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Repo-aware `agm init`.** When run in a project with a recognised manifest
  (`pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, `agenomic.yaml`),
  `init` now detects agent id (git remote), name/description/authors,
  framework, model provider + default model id, entrypoint, tools, and memory
  backend, and writes them into the generated bundle. New flags: `--from`,
  `--no-detect`, `--force`, `--dry-run`. See `docs/init-and-update.md`.
- **`agm update`.** Re-detects, merges into the existing bundle while preserving
  hand-edits (via a `.agenomic/provenance.yaml` sidecar), re-emits the canonical
  files, and auto-commits via `gix` (offline, pure-Rust). Flags `--message`,
  `--commit`/`--no-commit`, `--sign`, `--allow-dirty`, `--prune`, `--step`,
  `--dry-run`, `--from`. Refuses (exit 2) on protected branches / unrelated dirty
  trees; exits 1 when there are no changes.
- New `agenomic-detect` crate (detection, inference, merge, emission, provenance,
  git) and `[init]`/`[update]` tables in `agenomic.toml`.

### Changed

- `agm init` in a populated directory that already has a `genome.yaml` now
  refuses with exit 2 and points at `agm update` (use `--force` to overwrite).
  Empty/no-manifest directories are unchanged (byte-identical legacy scaffold).

### Fixed

- `agm cloud whoami` now surfaces the "wrong endpoint?" hint on HTTP status
  errors too (previously only on parse errors), and its HTML detector
  recognises Next.js error pages by their `_next/static` marker. Pointing
  `--endpoint` at the web origin now yields an actionable message instead of
  a raw 404 body.
- `agenomic completions` / full `--help` no longer panic under clap 4.6
  (the `cloud push-agent`/`push-release` `--version` args clashed with the
  auto version flag).
