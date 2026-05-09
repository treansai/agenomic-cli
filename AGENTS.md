# agenomic-cli — agent instructions

This is the public open-source CLI for the Agenomic platform. Apache-2.0.

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
