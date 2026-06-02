//! Detection provenance, persisted to a `.agenomic/provenance.yaml` **sidecar**.
//!
//! Provenance is deliberately kept out of `genome.yaml`: `.agenomic/` is in the
//! bundle walk's default excludes, so the sidecar is excluded from the canonical
//! logical hash with no special-casing in `agenomic-hash`. It records what
//! detection produced (so `agm update` can tell hand-edits from stale detection),
//! plus the detector version and timestamp (§2.5/§2.7).

use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult};
use serde::{Deserialize, Serialize};

use crate::model::DetectedGenome;

/// One recorded field origin — the sidecar form of [`crate::model::Evidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub field: String,
    pub value: String,
    /// Source label (e.g. `git`, `pyproject`).
    pub from: String,
    pub evidence: String,
}

/// A single `agm update` summary line, for `provenance.last_update` (§3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastUpdate {
    pub step: Option<String>,
    pub bundle_hash: String,
    pub changes: Vec<String>,
}

/// The provenance sidecar document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub detector_version: String,
    pub detected_at: String,
    pub sources: Vec<SourceRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frozen: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update: Option<LastUpdate>,
}

impl Provenance {
    /// Build provenance from a detection result and a resolved timestamp.
    ///
    /// ```
    /// use agenomic_detect::{DetectedGenome, Provenance};
    /// let g = DetectedGenome::defaults();
    /// let p = Provenance::from_detection(&g, "2026-05-31T00:00:00Z".to_string());
    /// assert_eq!(p.detected_at, "2026-05-31T00:00:00Z");
    /// assert!(p.sources.iter().any(|s| s.field == "agent.id"));
    /// ```
    pub fn from_detection(genome: &DetectedGenome, detected_at: String) -> Provenance {
        let sources = genome
            .sorted_evidence()
            .into_iter()
            .map(|e| SourceRecord {
                field: e.field,
                value: e.value,
                from: e.source.label().to_string(),
                evidence: e.evidence,
            })
            .collect();
        Provenance {
            detector_version: agenomic_spec::DETECTOR_VERSION.to_string(),
            detected_at,
            sources,
            frozen: Vec::new(),
            last_update: None,
        }
    }
}

/// Resolve `detected_at`: `SOURCE_DATE_EPOCH` (unix seconds) as RFC3339-UTC if
/// set and valid, otherwise the current UTC time (§2.7).
///
/// ```no_run
/// let ts = agenomic_detect::resolved_detected_at();
/// assert!(ts.ends_with('Z'));
/// ```
pub fn resolved_detected_at() -> String {
    let from_epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|secs| chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0));
    match from_epoch {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// Path to the provenance sidecar for a bundle directory.
///
/// ```
/// use std::path::Path;
/// let p = agenomic_detect::provenance_path(Path::new("/tmp/bundle"));
/// assert!(p.ends_with(".agenomic/provenance.yaml"));
/// ```
pub fn provenance_path(dir: &Path) -> PathBuf {
    dir.join(".agenomic").join("provenance.yaml")
}

/// Write the provenance sidecar atomically (creating `.agenomic/`).
///
/// ```no_run
/// use agenomic_detect::{DetectedGenome, Provenance, write_provenance};
/// use std::path::Path;
/// let g = DetectedGenome::defaults();
/// let p = Provenance::from_detection(&g, "2026-05-31T00:00:00Z".into());
/// write_provenance(Path::new("/tmp/bundle"), &p).unwrap();
/// ```
pub fn write_provenance(dir: &Path, provenance: &Provenance) -> CliResult<()> {
    let yaml = serde_yaml::to_string(provenance)
        .map_err(|e| CliError::Internal(format!("provenance serialize: {e}")))?;
    agenomic_fs::write_atomic(&provenance_path(dir), yaml.as_bytes())
}

/// Load the provenance sidecar, returning `None` when it is absent.
pub fn load_provenance(dir: &Path) -> CliResult<Option<Provenance>> {
    let path = provenance_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let p: Provenance = serde_yaml::from_str(&text)
                .map_err(|e| CliError::Schema(format!("provenance.yaml: {e}")))?;
            Ok(Some(p))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_at(&path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_sidecar() {
        let d = tempdir().unwrap();
        let g = DetectedGenome::defaults();
        let p = Provenance::from_detection(&g, "2026-05-31T00:00:00Z".into());
        write_provenance(d.path(), &p).unwrap();
        assert!(provenance_path(d.path()).is_file());
        let loaded = load_provenance(d.path()).unwrap().unwrap();
        assert_eq!(loaded, p);
    }

    #[test]
    fn source_date_epoch_is_honoured() {
        // 1700000000 = 2023-11-14T22:13:20Z
        std::env::set_var("SOURCE_DATE_EPOCH", "1700000000");
        let ts = resolved_detected_at();
        std::env::remove_var("SOURCE_DATE_EPOCH");
        assert_eq!(ts, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn missing_sidecar_is_none() {
        let d = tempdir().unwrap();
        assert!(load_provenance(d.path()).unwrap().is_none());
    }
}
