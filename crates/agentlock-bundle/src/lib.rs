use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use agentlock_core::{
    collect_bundle_file_entries, hash_bundle_dir, hash_bundle_from_entries, validate_bundle_dir,
    AgentlockError, BundleFileEntry, LoadedBundle,
};
use anyhow::{Context, Result};
use tempfile::TempDir;

pub fn build_bundle(source_dir: &Path, output_path: &Path) -> Result<String> {
    let bundle = validate_bundle_dir(source_dir)?;
    let entries = collect_bundle_file_entries(source_dir, &bundle)?;
    let hash = hash_bundle_from_entries(&entries)?;

    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create `{}`", parent.display()))?;
    let temp_file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to stage `{}`", output_path.display()))?;
    write_bundle_archive(&entries, temp_file.path())?;
    temp_file
        .persist(output_path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to persist `{}`", output_path.display()))?;

    Ok(hash)
}

pub fn load_bundle_from_source(source: &Path) -> Result<LoadedBundle> {
    if source.is_dir() {
        return validate_bundle_dir(source);
    }

    if source.is_file() {
        let temp = extract_bundle_to_tempdir(source)?;
        let mut bundle = validate_bundle_dir(temp.path())?;
        bundle.root = source.to_path_buf();
        return Ok(bundle);
    }

    Err(AgentlockError::UnsupportedBundleSource(source.display().to_string()).into())
}

pub fn hash_source(source: &Path) -> Result<String> {
    if source.is_dir() {
        return hash_bundle_dir(source);
    }

    if source.is_file() {
        let temp = extract_bundle_to_tempdir(source)?;
        return hash_bundle_dir(temp.path());
    }

    Err(AgentlockError::UnsupportedBundleSource(source.display().to_string()).into())
}

fn extract_bundle_to_tempdir(source: &Path) -> Result<TempDir> {
    let temp = TempDir::new().context("failed to allocate temporary extraction directory")?;
    let file =
        File::open(source).with_context(|| format!("failed to open `{}`", source.display()))?;
    let decoder =
        zstd::stream::read::Decoder::new(file).context("failed to create zstd decoder")?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().context("failed to read bundle archive")? {
        let mut entry = entry.context("failed to read bundle entry")?;
        let unpacked = entry
            .unpack_in(temp.path())
            .with_context(|| format!("failed to unpack `{}`", source.display()))?;
        if !unpacked {
            anyhow::bail!(
                "bundle `{}` contains a path outside the extraction root",
                source.display()
            );
        }
    }

    Ok(temp)
}

fn write_bundle_archive(entries: &[BundleFileEntry], output_path: &Path) -> Result<()> {
    let file = File::create(output_path)
        .with_context(|| format!("failed to create `{}`", output_path.display()))?;
    let encoder =
        zstd::stream::write::Encoder::new(file, 19).context("failed to create zstd encoder")?;
    let mut builder = tar::Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);

    for entry in entries {
        let mut contents = Vec::new();
        File::open(&entry.absolute_path)
            .with_context(|| format!("failed to open `{}`", entry.absolute_path.display()))?
            .read_to_end(&mut contents)
            .with_context(|| format!("failed to read `{}`", entry.absolute_path.display()))?;

        let mut header = tar::Header::new_gnu();
        header.set_path(&entry.relative_path)?;
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append(&header, contents.as_slice())
            .with_context(|| format!("failed to append `{}`", entry.relative_path))?;
    }

    builder.finish().context("failed to finish tar archive")?;
    let encoder = builder.into_inner().context("failed to flush tar writer")?;
    let mut file = encoder.finish().context("failed to finish zstd stream")?;
    file.flush().context("failed to flush bundle output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use agentlock_core::init_bundle_dir;

    use super::{build_bundle, hash_source, load_bundle_from_source};

    #[test]
    fn build_then_load_bundle_archive() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bundle_dir = temp.path().join("archive-test");
        init_bundle_dir(&bundle_dir)?;
        let output = temp.path().join("archive-test.tar.zst");

        let hash = build_bundle(&bundle_dir, &output)?;
        let extracted = load_bundle_from_source(&output)?;
        assert_eq!(extracted.genome.agent.id, "archive-test");
        assert_eq!(hash, hash_source(&output)?);
        Ok(())
    }
}
