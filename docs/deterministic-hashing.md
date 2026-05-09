# Deterministic hashing

The bundle hash is the trust anchor for everything else: attestations,
release IDs, replay anchoring. It is reproducible bit-for-bit across
operating systems, file-creation orders, and zstd implementations.

## Algorithm

`agenomic-hash` produces a [`BundleManifest`](../crates/agenomic-hash/src/manifest.rs)
using BLAKE3.

1. **Walk** the bundle directory deterministically (POSIX path order, byte
   comparison) using `agenomic-fs::walk_bundle` with default options
   (security excludes, no symlinks).
2. **Leaf hash** for each file:
   ```
   leaf = BLAKE3("AGENTLOCK-LEAF-v1\0" || path_bytes || 0x00 || file_bytes)
   ```
3. **Merkle tree**: pair-wise BLAKE3 with the `AGENTLOCK-NODE-v1\0` domain
   separator. An odd trailing node at any layer is duplicated (paired with
   itself).
4. **Root**: the single remaining node hex-encoded as 64 chars.

The manifest also records `manifest_version` (`agenomic.manifest/v0.1`) and
`algorithm` (`blake3-merkle-v1`). These two strings are how we detect
breaking changes — any tweak to the algorithm requires a version bump.

## Two hashes

`agenomic build` emits **two** hashes:

- `logical_bundle_hash` — the Merkle root above. Reproducible regardless of
  zstd level or tar implementation. **Sign this**.
- `archive_hash` — BLAKE3 of the final `.tar.zst` bytes. Useful as a
  download-fingerprint. Different compression levels produce different
  archive hashes.

## Golden test

A known fixture lives in
[`crates/agenomic-hash/tests/golden.rs`](../crates/agenomic-hash/tests/golden.rs).
If that test ever fails, the algorithm has changed — bump
`MANIFEST_VERSION` and update the golden.
