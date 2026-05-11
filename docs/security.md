# Security

## Threat model

The CLI defends against three primary threats:

1. **Tampering with bundles** — caught by deterministic Merkle hashing
   (`agenomic-hash`).
2. **Tampering with agent history** — caught by ATEP signed events, the
   per-segment Merkle root, and the optional `atep_root_hash` anchor in
   release attestations.
3. **Accidental credential leak via bundle build** — caught by the always-on
   security excludes (see `agenomic-fs::SECURITY_EXCLUDES`) and the
   `agenomic validate --level ci` security scan.

## Defaults

- Symlinks are rejected during `build` and `validate` unless you pass
  `--allow-symlinks` (not recommended).
- `.env`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, `*.p12`, `*.pfx` are
  excluded from every walk, regardless of `.agenomicignore`.
- Path traversal (`..`) is rejected, both in directory walks and in archive
  extraction.
- `~/.config/agenomic/credentials.toml` is created with mode 0600 on Unix.

## Key handling

- `agenomic attest --generate-key /path/to/key.pem` writes a fresh ed25519
  PKCS#8 PEM at mode 0600 and a `.pem.pub` PEM next to it.
- The CLI never transmits private keys.
- Public-key PEM and short key-id are embedded in attestation signatures so
  they can be verified offline.

## Reporting issues

Please email security@agenomic.dev with details and a minimal reproducer.
