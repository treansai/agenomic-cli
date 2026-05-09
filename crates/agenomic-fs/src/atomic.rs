//! Atomic file write and Unix file-mode helpers.

use std::io::Write;
use std::path::Path;

use agenomic_core::{io_at, CliResult};
use rand::Rng;

/// Write `contents` to `path` atomically.
///
/// The implementation writes to `<path>.tmp.<random>`, fsyncs, then renames.
/// On failure mid-write the temp file is removed best-effort.
///
/// ```no_run
/// use agenomic_fs::write_atomic;
/// use std::path::Path;
/// write_atomic(Path::new("/tmp/example.txt"), b"hello").unwrap();
/// ```
pub fn write_atomic(path: &Path, contents: &[u8]) -> CliResult<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && parent != Path::new("") && !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }

    let suffix: u64 = rand::thread_rng().gen();
    let tmp = path.with_extension(format!(
        "{}tmp.{:016x}",
        path.extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default(),
        suffix
    ));

    let written: CliResult<()> = (|| {
        let mut file = std::fs::File::create(&tmp).map_err(|e| io_at(&tmp, e))?;
        file.write_all(contents).map_err(|e| io_at(&tmp, e))?;
        file.sync_all().map_err(|e| io_at(&tmp, e))?;
        Ok(())
    })();

    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_at(path, e)
    })?;
    Ok(())
}

/// Set file mode to 0600 on Unix; no-op on Windows.
///
/// ```no_run
/// use agenomic_fs::set_secret_mode;
/// use std::path::Path;
/// # std::fs::write("/tmp/credentials.toml", "x").unwrap();
/// set_secret_mode(Path::new("/tmp/credentials.toml")).unwrap();
/// ```
#[cfg(unix)]
pub fn set_secret_mode(path: &Path) -> CliResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| io_at(path, e))?;
    Ok(())
}

/// Set file mode to 0600 on Unix; no-op on Windows.
#[cfg(not(unix))]
pub fn set_secret_mode(_path: &Path) -> CliResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_and_overwrites() {
        let d = tempdir().unwrap();
        let p = d.path().join("a.txt");
        write_atomic(&p, b"first").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        write_atomic(&p, b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
    }

    #[test]
    fn creates_parent_directories() {
        let d = tempdir().unwrap();
        let p = d.path().join("nested/deep/file.txt");
        write_atomic(&p, b"hi").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hi");
    }

    #[cfg(unix)]
    #[test]
    fn secret_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let p = d.path().join("creds.toml");
        write_atomic(&p, b"x").unwrap();
        set_secret_mode(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
