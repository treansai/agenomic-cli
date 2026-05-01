//! On-disk ATEP store layout.
//!
//! ```text
//! .atep/
//! ├── manifest.json
//! └── streams/
//!     ├── identity-00000001.atep
//!     ├── capability-00000001.atep
//!     └── ...
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use agentlock_core::{io_at, CliError, CliResult};
use serde::{Deserialize, Serialize};

use crate::clock::Hlc;
use crate::event::{AtepEvent, StreamId};
use crate::segment::{SegmentReader, SegmentWriter};

/// Manifest version string for an ATEP store.
pub const ATEP_MANIFEST_VERSION: &str = "atep.manifest/v0.1";

/// Per-segment record in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentRecord {
    pub file: String,
    pub events: u32,
    pub merkle_root: String,
}

/// On-disk JSON manifest of the store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtepManifest {
    pub manifest_version: String,
    pub agent_id: String,
    pub streams: BTreeMap<String, Vec<SegmentRecord>>,
    pub total_events: u64,
}

/// Verification report from [`AtepStore::verify_all`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub total_events: u64,
    pub stream_counts: BTreeMap<String, u64>,
    pub verified_signatures: u64,
    pub valid: bool,
}

/// Reconstructed agent state.
///
/// v0.1: just the most recent payload per `(stream, event_type)` pair, plus
/// counts. Richer projections come later.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentState {
    pub agent_id: String,
    pub at: Option<Hlc>,
    pub event_counts: BTreeMap<String, u64>,
    pub last_event_per_type: BTreeMap<String, serde_json::Value>,
}

/// Handle to an on-disk ATEP store.
pub struct AtepStore {
    root: PathBuf,
    manifest: AtepManifest,
}

impl AtepStore {
    /// Open an existing store, or initialize a new empty one.
    ///
    /// ```no_run
    /// use agentlock_atep::AtepStore;
    /// let s = AtepStore::open_or_init(std::path::Path::new("/tmp/atep"),
    ///                                 "agent://acme/foo").unwrap();
    /// drop(s);
    /// ```
    pub fn open_or_init(root: &Path, agent_id: &str) -> CliResult<Self> {
        fs::create_dir_all(root.join("streams")).map_err(|e| io_at(root, e))?;
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let text = fs::read_to_string(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let m: AtepManifest = serde_json::from_str(&text)
                .map_err(|e| CliError::Internal(format!("manifest parse: {e}")))?;
            if m.agent_id != agent_id {
                return Err(CliError::Internal(format!(
                    "agent_id mismatch: store has {} but {agent_id} was requested",
                    m.agent_id
                )));
            }
            m
        } else {
            let m = AtepManifest {
                manifest_version: ATEP_MANIFEST_VERSION.into(),
                agent_id: agent_id.into(),
                streams: BTreeMap::new(),
                total_events: 0,
            };
            agentlock_fs::write_atomic(
                &manifest_path,
                serde_json::to_vec_pretty(&m)
                    .map_err(|e| CliError::Internal(format!("manifest serialize: {e}")))?
                    .as_slice(),
            )?;
            m
        };
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
        })
    }

    /// Append a single event to its stream's latest segment (rotating if
    /// it would exceed the soft cap of 1000 events per segment).
    pub fn append_event(&mut self, event: AtepEvent) -> CliResult<()> {
        if event.header.agent_id != self.manifest.agent_id {
            return Err(CliError::Internal(format!(
                "event agent_id {} does not match store agent_id {}",
                event.header.agent_id, self.manifest.agent_id
            )));
        }
        let stream_label = event.header.stream.label().to_string();

        // Pick or create a segment file. v1 simply uses one segment per call;
        // tooling that wants larger segments can batch via [`append_batch`].
        let (path, seq) = self.next_segment_path(&stream_label);
        {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| io_at(&path, e))?;
            let mut writer = SegmentWriter::new(file)?;
            writer.append(&event)?;
            let summary = writer.finalize()?;

            self.manifest
                .streams
                .entry(stream_label.clone())
                .or_default()
                .push(SegmentRecord {
                    file: path
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    events: summary.event_count,
                    merkle_root: hex::encode(summary.merkle_root),
                });
        }
        self.manifest.total_events += 1;
        let _ = seq;
        self.persist_manifest()
    }

    /// Append several events to the same stream into a single segment.
    pub fn append_batch(&mut self, stream: StreamId, events: &[AtepEvent]) -> CliResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let label = stream.label().to_string();
        let (path, _) = self.next_segment_path(&label);
        let file = std::fs::File::create(&path).map_err(|e| io_at(&path, e))?;
        let mut writer = SegmentWriter::new(file)?;
        for ev in events {
            if ev.header.stream != stream {
                return Err(CliError::Internal("event stream mismatch in batch".into()));
            }
            writer.append(ev)?;
        }
        let summary = writer.finalize()?;
        self.manifest
            .streams
            .entry(label.clone())
            .or_default()
            .push(SegmentRecord {
                file: path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default(),
                events: summary.event_count,
                merkle_root: hex::encode(summary.merkle_root),
            });
        self.manifest.total_events += events.len() as u64;
        self.persist_manifest()
    }

    /// Read all events of a stream across its segments (in segment order).
    pub fn read_stream(&self, stream: StreamId) -> CliResult<Vec<AtepEvent>> {
        let label = stream.label();
        let mut out = Vec::new();
        if let Some(records) = self.manifest.streams.get(label) {
            for rec in records {
                let path = self.root.join("streams").join(&rec.file);
                let file = std::fs::File::open(&path).map_err(|e| io_at(&path, e))?;
                let mut reader = SegmentReader::open(file)?;
                let events = reader.read_all()?;
                out.extend(events);
            }
        }
        Ok(out)
    }

    /// Iterate all events across all streams in canonical order
    /// (stream label asc, then segment order, then frame order).
    pub fn read_all_events(&self) -> CliResult<Vec<AtepEvent>> {
        let mut out = Vec::new();
        for (label, records) in &self.manifest.streams {
            for rec in records {
                let path = self.root.join("streams").join(&rec.file);
                let file = std::fs::File::open(&path).map_err(|e| io_at(&path, e))?;
                let mut reader = SegmentReader::open(file)?;
                let events = reader.read_all()?;
                out.extend(events);
            }
            let _ = label;
        }
        Ok(out)
    }

    /// Verify every event's signature and every segment's merkle root.
    pub fn verify_all(&self, vk: &ed25519_dalek::VerifyingKey) -> CliResult<VerificationReport> {
        let mut rep = VerificationReport {
            valid: true,
            ..Default::default()
        };
        for (label, records) in &self.manifest.streams {
            let mut count = 0u64;
            for rec in records {
                let path = self.root.join("streams").join(&rec.file);
                let file = std::fs::File::open(&path).map_err(|e| io_at(&path, e))?;
                let mut reader = SegmentReader::open(file)?;
                reader.verify_merkle_root()?;
                let events = reader.read_all()?;
                for ev in &events {
                    ev.verify(vk)?;
                    rep.verified_signatures += 1;
                }
                count += events.len() as u64;
            }
            rep.stream_counts.insert(label.clone(), count);
            rep.total_events += count;
        }
        Ok(rep)
    }

    /// Reconstruct an [`AgentState`] up to (and including) the optional
    /// `at` clock. Events with `clock > at` are skipped.
    pub fn replay_to_state(&self, at: Option<Hlc>) -> CliResult<AgentState> {
        let mut events = self.read_all_events()?;
        events.sort_by_key(|e| e.header.clock);
        let mut state = AgentState {
            agent_id: self.manifest.agent_id.clone(),
            at,
            ..Default::default()
        };
        for ev in events {
            if let Some(threshold) = at {
                if ev.header.clock > threshold {
                    continue;
                }
            }
            *state
                .event_counts
                .entry(ev.header.event_type.clone())
                .or_insert(0) += 1;
            // Convert payload to JSON for the projection
            if let Ok(json) = cbor_to_json(&ev.payload.0) {
                state
                    .last_event_per_type
                    .insert(ev.header.event_type.clone(), json);
            }
        }
        Ok(state)
    }

    /// Reference to the parsed manifest.
    pub fn manifest(&self) -> &AtepManifest {
        &self.manifest
    }

    /// Compute a single 32-byte BLAKE3 root over every stored segment's
    /// `merkle_root` (in `manifest.streams` order). Useful as the
    /// `atep_root_hash` field of an attestation.
    pub fn store_merkle_root(&self) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for records in self.manifest.streams.values() {
            for rec in records {
                if let Ok(b) = hex::decode(&rec.merkle_root) {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        leaves.push(arr);
                    }
                }
            }
        }
        crate::segment::compute_merkle_root(&leaves)
    }

    fn persist_manifest(&self) -> CliResult<()> {
        let path = self.root.join("manifest.json");
        let bytes = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| CliError::Internal(format!("manifest serialize: {e}")))?;
        agentlock_fs::write_atomic(&path, &bytes)
    }

    fn next_segment_path(&self, stream_label: &str) -> (PathBuf, u32) {
        let next_seq = self
            .manifest
            .streams
            .get(stream_label)
            .map(|v| v.len() as u32 + 1)
            .unwrap_or(1);
        let name = format!("{stream_label}-{next_seq:08}.atep");
        (self.root.join("streams").join(name), next_seq)
    }
}

fn cbor_to_json(v: &ciborium::value::Value) -> CliResult<serde_json::Value> {
    use ciborium::value::Value as C;
    Ok(match v {
        C::Null => serde_json::Value::Null,
        C::Bool(b) => serde_json::Value::Bool(*b),
        C::Integer(i) => {
            // ciborium Integer can be larger than i64; fall back to string
            let as_i128: i128 = (*i).into();
            if let Ok(n) = i64::try_from(as_i128) {
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::String(as_i128.to_string())
            }
        }
        C::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        C::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        C::Text(s) => serde_json::Value::String(s.clone()),
        C::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for v in a {
                out.push(cbor_to_json(v)?);
            }
            serde_json::Value::Array(out)
        }
        C::Map(m) => {
            let mut out = serde_json::Map::with_capacity(m.len());
            for (k, val) in m {
                let key = match k {
                    C::Text(s) => s.clone(),
                    C::Integer(i) => i128::from(*i).to_string(),
                    _ => continue,
                };
                out.insert(key, cbor_to_json(val)?);
            }
            serde_json::Value::Object(out)
        }
        C::Tag(_, inner) => cbor_to_json(inner)?,
        _ => serde_json::Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Hlc;
    use crate::event::{EventHeader, EventPayload};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tempfile::tempdir;

    fn mk(agent: &str, sk: &SigningKey, stream: StreamId, seq: u64, ms: u64) -> AtepEvent {
        let h = EventHeader {
            schema_version: 1,
            event_id: ulid::Ulid::new().to_bytes(),
            agent_id: agent.into(),
            stream,
            stream_seq: seq,
            clock: Hlc::new(ms, 0, 1),
            parents: vec![],
            event_type: format!("{}.evt_{seq}", stream.label()),
            payload_schema_uri: "atep://schemas/v1/test".into(),
        };
        let p = EventPayload(ciborium::value::Value::Integer(seq.into()));
        AtepEvent::seal(h, p, sk, "k1".into()).unwrap()
    }

    #[test]
    fn init_append_verify() {
        let d = tempdir().unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let agent = "agent://acme/foo";

        let mut store = AtepStore::open_or_init(d.path(), agent).unwrap();
        store
            .append_event(mk(agent, &sk, StreamId::Capability, 1, 100))
            .unwrap();
        store
            .append_event(mk(agent, &sk, StreamId::Capability, 2, 200))
            .unwrap();
        store
            .append_event(mk(agent, &sk, StreamId::Identity, 1, 50))
            .unwrap();

        // Reopen
        let store2 = AtepStore::open_or_init(d.path(), agent).unwrap();
        let rep = store2.verify_all(&sk.verifying_key()).unwrap();
        assert_eq!(rep.total_events, 3);
        assert_eq!(rep.verified_signatures, 3);
        assert_eq!(rep.stream_counts.get("capability"), Some(&2));
        assert_eq!(rep.stream_counts.get("identity"), Some(&1));
    }

    #[test]
    fn replay_with_clock_threshold() {
        let d = tempdir().unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let agent = "agent://acme/foo";
        let mut store = AtepStore::open_or_init(d.path(), agent).unwrap();
        store
            .append_event(mk(agent, &sk, StreamId::Capability, 1, 100))
            .unwrap();
        store
            .append_event(mk(agent, &sk, StreamId::Capability, 2, 300))
            .unwrap();
        let s_full = store.replay_to_state(None).unwrap();
        assert_eq!(s_full.event_counts.values().sum::<u64>(), 2);
        let s_trim = store.replay_to_state(Some(Hlc::new(200, 0, 1))).unwrap();
        assert_eq!(s_trim.event_counts.values().sum::<u64>(), 1);
    }
}
