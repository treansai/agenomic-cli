//! Build a `.bundle.tar.zst` archive from a directory.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use agentlock_core::{io_at, CliError, CliResult};
use agentlock_fs::{walk_bundle, WalkOptions};
use agentlock_hash::{compute_manifest_from_pairs, BundleManifest};

/// Options for [`build_bundle`].
#[derive(Debug, Clone)]
pub struct BuildBundleOptions {
    pub input_dir: PathBuf,
    pub output_file: PathBuf,
    /// zstd compression level (1..=22). Default 3.
    pub compression_level: i32,
    /// If true, fail on validation errors (delegated to `agentlock-validate`
    /// in higher layers).
    pub strict: bool,
    /// If false, secret/credential files are still excluded by the walker.
    pub include_attestations: bool,
    pub ignore_file: Option<PathBuf>,
    pub allow_symlinks: bool,
}

impl Default for BuildBundleOptions {
    fn default() -> Self {
        Self {
            input_dir: PathBuf::new(),
            output_file: PathBuf::new(),
            compression_level: 3,
            strict: false,
            include_attestations: false,
            ignore_file: None,
            allow_symlinks: false,
        }
    }
}

/// Result of [`build_bundle`].
#[derive(Debug, Clone)]
pub struct BundleBuildResult {
    pub output_file: PathBuf,
    /// Hex BLAKE3 root from the bundle manifest. Reproducible across machines.
    pub logical_bundle_hash: String,
    /// Hex BLAKE3 of the final `.tar.zst` bytes.
    pub archive_hash: String,
    pub manifest: BundleManifest,
    pub size_bytes: u64,
}

/// Build a bundle.
///
/// 1. Walk `input_dir` deterministically (security excludes always honored).
/// 2. Compute the canonical manifest.
/// 3. Pack files in manifest order into a tar archive with mtime=0.
/// 4. zstd-compress the tar archive into `output_file`.
/// 5. Compute archive hash over the final `.tar.zst` bytes.
///
/// ```no_run
/// use agentlock_bundle::{build_bundle, BuildBundleOptions};
/// let opts = BuildBundleOptions {
///     input_dir: "./examples/claims-agent".into(),
///     output_file: "/tmp/claims.bundle.tar.zst".into(),
///     ..Default::default()
/// };
/// let _r = build_bundle(opts).unwrap();
/// ```
pub fn build_bundle(options: BuildBundleOptions) -> CliResult<BundleBuildResult> {
    let mut walk_opts = WalkOptions::default();
    walk_opts.allow_symlinks = options.allow_symlinks;
    let entries = walk_bundle(&options.input_dir, &walk_opts)?;

    // Read each file once, build pairs in manifest order, and reuse the bytes
    // for tar packing.
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());
    for e in &entries {
        let mut f =
            std::fs::File::open(&e.absolute_path).map_err(|err| io_at(&e.absolute_path, err))?;
        let mut buf = Vec::with_capacity(e.size as usize);
        f.read_to_end(&mut buf)
            .map_err(|err| io_at(&e.absolute_path, err))?;
        pairs.push((e.relative_path.clone(), buf));
    }

    let manifest = compute_manifest_from_pairs(pairs.iter().map(|(p, c)| (p.clone(), c.clone())))?;

    // Build a deterministic tar archive (mtime=0, mode=0644 for files).
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut tar_buf);
        tar.mode(tar::HeaderMode::Deterministic);
        for (path, content) in &pairs {
            let mut header = tar::Header::new_gnu();
            header
                .set_path(path)
                .map_err(|e| CliError::Internal(format!("tar set_path {path}: {e}")))?;
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append(&header, content.as_slice())
                .map_err(|e| CliError::Internal(format!("tar append {path}: {e}")))?;
        }
        tar.into_inner()
            .map_err(|e| CliError::Internal(format!("tar finalize: {e}")))?;
    }

    // zstd-compress
    let mut compressed: Vec<u8> = Vec::new();
    {
        let level = options.compression_level.clamp(1, 22);
        let mut enc = zstd::Encoder::new(&mut compressed, level)
            .map_err(|e| CliError::Internal(format!("zstd encoder: {e}")))?;
        enc.write_all(&tar_buf)
            .map_err(|e| CliError::Internal(format!("zstd write: {e}")))?;
        enc.finish()
            .map_err(|e| CliError::Internal(format!("zstd finish: {e}")))?;
    }

    // Write to output
    if let Some(parent) = options.output_file.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
        }
    }
    agentlock_fs::write_atomic(&options.output_file, &compressed)?;

    // Compute archive hash
    let archive_hash = blake3::hash(&compressed);
    let archive_hex = hex::encode(archive_hash.as_bytes());

    Ok(BundleBuildResult {
        output_file: options.output_file.clone(),
        logical_bundle_hash: manifest.root_hash.clone(),
        archive_hash: archive_hex,
        manifest,
        size_bytes: compressed.len() as u64,
    })
}

/// Decompress and read a `.tar.zst` bundle's tar bytes.
pub fn read_archive_to_pairs(archive: &Path) -> CliResult<Vec<(String, Vec<u8>)>> {
    let f = std::fs::File::open(archive).map_err(|e| io_at(archive, e))?;
    let mut decoder =
        zstd::Decoder::new(f).map_err(|e| CliError::Internal(format!("zstd decoder: {e}")))?;
    let mut tar_bytes: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut tar_bytes)
        .map_err(|e| CliError::Internal(format!("zstd read: {e}")))?;
    let mut archive_reader = tar::Archive::new(tar_bytes.as_slice());
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in archive_reader
        .entries()
        .map_err(|e| CliError::Internal(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| CliError::Internal(format!("tar entry: {e}")))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| CliError::Internal(format!("tar entry path: {e}")))?
            .to_string_lossy()
            .replace('\\', "/")
            .to_string();
        if path.split('/').any(|s| s == "..") {
            return Err(CliError::PathTraversal { path });
        }
        let mut buf: Vec<u8> = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| CliError::Internal(format!("tar entry read: {e}")))?;
        pairs.push((path, buf));
    }
    Ok(pairs)
}
