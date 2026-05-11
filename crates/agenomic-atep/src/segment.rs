//! ATEP segment file (`.atep`) — append-only on-disk container for a stream
//! of [`AtepEvent`]s.
//!
//! ## Layout (little-endian)
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ MAGIC          "ATEP"      4 B          │
//! │ VERSION        u16         2 B          │
//! │ FLAGS          u16         2 B          │
//! │ EVENT_COUNT    u32         4 B          │
//! │ FIRST_HLC                  16 B         │
//! │ LAST_HLC                   16 B         │
//! │ MERKLE_ROOT                32 B         │
//! │ ─────────────── 76-byte header          │
//! │ FRAMES (event_count of):                │
//! │   FRAME_LEN    u32         4 B          │
//! │   EVENT_BYTES  variable (CBOR)          │
//! │ INDEX_OFFSET   u64         8 B          │
//! │ INDEX_LEN      u64         8 B          │
//! │ CRC32                      4 B          │
//! │ MAGIC_TAIL     "PETA"      4 B          │
//! └─────────────────────────────────────────┘
//! ```
//!
//! `MERKLE_ROOT` is BLAKE3 over the ordered list of `causal_hash` values.
//! `INDEX_OFFSET`/`INDEX_LEN` reserved for future use; written as zeros in v1.

use std::io::{Read, Seek, SeekFrom, Write};

use agenomic_core::{CliError, CliResult};
use blake3::Hasher;
use crc32fast::Hasher as Crc32;

use crate::clock::Hlc;
use crate::event::AtepEvent;

pub const SEGMENT_MAGIC_HEAD: &[u8; 4] = b"ATEP";
pub const SEGMENT_MAGIC_TAIL: &[u8; 4] = b"PETA";
pub const SEGMENT_VERSION: u16 = 1;
pub const HEADER_SIZE: u64 = 76;

/// Header values cached after a [`SegmentReader::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub version: u16,
    pub flags: u16,
    pub event_count: u32,
    pub first_hlc: Hlc,
    pub last_hlc: Hlc,
    pub merkle_root: [u8; 32],
}

/// Summary returned by [`SegmentWriter::finalize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSummary {
    pub event_count: u32,
    pub first_hlc: Hlc,
    pub last_hlc: Hlc,
    pub merkle_root: [u8; 32],
    pub bytes_written: u64,
}

/// Writer for a single segment.
pub struct SegmentWriter<W: Write + Seek + Read> {
    writer: W,
    event_count: u32,
    first_hlc: Option<Hlc>,
    last_hlc: Hlc,
    leaf_hashes: Vec<[u8; 32]>,
    bytes: u64,
}

impl<W: Write + Seek + Read> SegmentWriter<W> {
    /// Begin a new segment. Reserves space for the header by writing 76 zero bytes.
    pub fn new(mut writer: W) -> CliResult<Self> {
        writer
            .write_all(&[0u8; HEADER_SIZE as usize])
            .map_err(|e| CliError::Internal(format!("write header reserve: {e}")))?;
        Ok(Self {
            writer,
            event_count: 0,
            first_hlc: None,
            last_hlc: Hlc::new(0, 0, 0),
            leaf_hashes: Vec::new(),
            bytes: HEADER_SIZE,
        })
    }

    /// Append an event frame.
    pub fn append(&mut self, event: &AtepEvent) -> CliResult<()> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(event, &mut buf)
            .map_err(|e| CliError::Internal(format!("cbor encode event: {e}")))?;

        let frame_len = u32::try_from(buf.len())
            .map_err(|_| CliError::Internal("event frame too large (>4GiB)".to_string()))?;
        self.writer
            .write_all(&frame_len.to_le_bytes())
            .map_err(|e| CliError::Internal(format!("write frame_len: {e}")))?;
        self.writer
            .write_all(&buf)
            .map_err(|e| CliError::Internal(format!("write frame: {e}")))?;
        self.bytes += 4 + buf.len() as u64;

        if self.first_hlc.is_none() {
            self.first_hlc = Some(event.header.clock);
        }
        self.last_hlc = event.header.clock;
        self.leaf_hashes.push(event.causal_hash.0);
        self.event_count += 1;
        Ok(())
    }

    /// Write the index trailer + footer, then patch the header.
    pub fn finalize(mut self) -> CliResult<SegmentSummary> {
        let index_offset = self.bytes;
        let index_len = 0u64;
        self.writer
            .write_all(&index_offset.to_le_bytes())
            .map_err(|e| CliError::Internal(format!("write index_offset: {e}")))?;
        self.writer
            .write_all(&index_len.to_le_bytes())
            .map_err(|e| CliError::Internal(format!("write index_len: {e}")))?;

        // Compute CRC32 over the entire stream (excluding the CRC and tail magic).
        // To do so, flush, then read the file from start.
        self.writer
            .flush()
            .map_err(|e| CliError::Internal(format!("flush: {e}")))?;

        // Compute Merkle root over ordered leaf hashes
        let merkle_root = compute_merkle_root(&self.leaf_hashes);

        // Patch header
        let first = self.first_hlc.unwrap_or(Hlc::new(0, 0, 0));
        let last = self.last_hlc;
        let header_bytes = build_header_bytes(self.event_count, first, last, &merkle_root);

        self.writer
            .seek(SeekFrom::Start(0))
            .map_err(|e| CliError::Internal(format!("seek to header: {e}")))?;
        self.writer
            .write_all(&header_bytes)
            .map_err(|e| CliError::Internal(format!("rewrite header: {e}")))?;

        // Now seek to the index trailer end, compute CRC over [0..index_trailer_end], write CRC + tail magic.
        let pre_crc_end = self.bytes + 16;
        self.writer
            .seek(SeekFrom::Start(0))
            .map_err(|e| CliError::Internal(format!("seek to start for crc: {e}")))?;

        let mut crc = Crc32::new();
        let mut buf = vec![0u8; 8192];
        let mut remaining = pre_crc_end as usize;
        while remaining > 0 {
            let n = std::cmp::min(remaining, buf.len());
            self.writer
                .read_exact(&mut buf[..n])
                .map_err(|e| CliError::Internal(format!("read for crc: {e}")))?;
            crc.update(&buf[..n]);
            remaining -= n;
        }
        let crc_val = crc.finalize();

        self.writer
            .seek(SeekFrom::Start(pre_crc_end))
            .map_err(|e| CliError::Internal(format!("seek to crc pos: {e}")))?;
        self.writer
            .write_all(&crc_val.to_le_bytes())
            .map_err(|e| CliError::Internal(format!("write crc: {e}")))?;
        self.writer
            .write_all(SEGMENT_MAGIC_TAIL)
            .map_err(|e| CliError::Internal(format!("write magic tail: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| CliError::Internal(format!("flush footer: {e}")))?;

        Ok(SegmentSummary {
            event_count: self.event_count,
            first_hlc: first,
            last_hlc: last,
            merkle_root,
            bytes_written: pre_crc_end + 8,
        })
    }
}

/// Reader for a finalized segment.
pub struct SegmentReader<R: Read + Seek> {
    reader: R,
    header: SegmentHeader,
    /// Position immediately after the 76-byte header.
    frames_start: u64,
    index_offset: u64,
}

impl<R: Read + Seek> SegmentReader<R> {
    /// Open and validate the header + footer of a segment.
    pub fn open(mut reader: R) -> CliResult<Self> {
        let mut head_buf = [0u8; HEADER_SIZE as usize];
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| CliError::Internal(format!("seek 0: {e}")))?;
        reader
            .read_exact(&mut head_buf)
            .map_err(|e| CliError::AtepIntegrity {
                reason: format!("cannot read header: {e}"),
            })?;

        if &head_buf[0..4] != SEGMENT_MAGIC_HEAD {
            return Err(CliError::AtepIntegrity {
                reason: "bad magic head".into(),
            });
        }
        let version = u16::from_le_bytes(head_buf[4..6].try_into().unwrap());
        if version != SEGMENT_VERSION {
            return Err(CliError::AtepIntegrity {
                reason: format!("unsupported segment version {version}"),
            });
        }
        let flags = u16::from_le_bytes(head_buf[6..8].try_into().unwrap());
        let event_count = u32::from_le_bytes(head_buf[8..12].try_into().unwrap());
        let first_hlc = Hlc::from_le_bytes(head_buf[12..28].try_into().unwrap());
        let last_hlc = Hlc::from_le_bytes(head_buf[28..44].try_into().unwrap());
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&head_buf[44..76]);

        // Validate footer
        let total_len = reader
            .seek(SeekFrom::End(0))
            .map_err(|e| CliError::Internal(format!("seek end: {e}")))?;
        if total_len < HEADER_SIZE + 24 {
            return Err(CliError::AtepIntegrity {
                reason: "segment too short".into(),
            });
        }
        reader
            .seek(SeekFrom::End(-4))
            .map_err(|e| CliError::Internal(format!("seek end-4: {e}")))?;
        let mut tail = [0u8; 4];
        reader
            .read_exact(&mut tail)
            .map_err(|e| CliError::Internal(format!("read tail: {e}")))?;
        if &tail != SEGMENT_MAGIC_TAIL {
            return Err(CliError::AtepIntegrity {
                reason: "bad magic tail".into(),
            });
        }

        // Validate CRC
        let pre_crc_end = total_len - 8;
        reader
            .seek(SeekFrom::Start(pre_crc_end))
            .map_err(|e| CliError::Internal(format!("seek crc: {e}")))?;
        let mut crc_bytes = [0u8; 4];
        reader
            .read_exact(&mut crc_bytes)
            .map_err(|e| CliError::Internal(format!("read crc: {e}")))?;
        let stored_crc = u32::from_le_bytes(crc_bytes);
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| CliError::Internal(format!("seek 0 for crc: {e}")))?;
        let mut crc = Crc32::new();
        let mut remaining = pre_crc_end as usize;
        let mut buf = vec![0u8; 8192];
        while remaining > 0 {
            let n = std::cmp::min(remaining, buf.len());
            reader
                .read_exact(&mut buf[..n])
                .map_err(|e| CliError::Internal(format!("read for crc check: {e}")))?;
            crc.update(&buf[..n]);
            remaining -= n;
        }
        let computed = crc.finalize();
        if computed != stored_crc {
            return Err(CliError::AtepIntegrity {
                reason: format!("crc mismatch: stored {stored_crc:#x} computed {computed:#x}"),
            });
        }

        // index trailer: located at total_len - 24 (16 bytes index_offset+len, 4 crc, 4 tail)
        let index_trailer_pos = total_len - 24;
        reader
            .seek(SeekFrom::Start(index_trailer_pos))
            .map_err(|e| CliError::Internal(format!("seek trailer: {e}")))?;
        let mut idx_buf = [0u8; 16];
        reader
            .read_exact(&mut idx_buf)
            .map_err(|e| CliError::Internal(format!("read trailer: {e}")))?;
        let index_offset = u64::from_le_bytes(idx_buf[0..8].try_into().unwrap());

        Ok(Self {
            reader,
            header: SegmentHeader {
                version,
                flags,
                event_count,
                first_hlc,
                last_hlc,
                merkle_root,
            },
            frames_start: HEADER_SIZE,
            index_offset,
        })
    }

    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Read all events and return them as a `Vec`.
    pub fn read_all(&mut self) -> CliResult<Vec<AtepEvent>> {
        let mut events = Vec::with_capacity(self.header.event_count as usize);
        self.reader
            .seek(SeekFrom::Start(self.frames_start))
            .map_err(|e| CliError::Internal(format!("seek frames: {e}")))?;
        let frames_end = self.index_offset;
        let mut pos = self.frames_start;
        while pos < frames_end {
            let mut len_buf = [0u8; 4];
            self.reader
                .read_exact(&mut len_buf)
                .map_err(|e| CliError::AtepIntegrity {
                    reason: format!("frame_len read: {e}"),
                })?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut frame = vec![0u8; len];
            self.reader
                .read_exact(&mut frame)
                .map_err(|e| CliError::AtepIntegrity {
                    reason: format!("frame read: {e}"),
                })?;
            let ev: AtepEvent = ciborium::de::from_reader(frame.as_slice()).map_err(|e| {
                CliError::AtepIntegrity {
                    reason: format!("frame decode: {e}"),
                }
            })?;
            events.push(ev);
            pos += 4 + len as u64;
        }
        Ok(events)
    }

    /// Verify the merkle root by recomputing over event causal_hashes.
    pub fn verify_merkle_root(&mut self) -> CliResult<()> {
        let events = self.read_all()?;
        let leaves: Vec<[u8; 32]> = events.iter().map(|e| e.causal_hash.0).collect();
        let computed = compute_merkle_root(&leaves);
        if computed != self.header.merkle_root {
            return Err(CliError::AtepIntegrity {
                reason: format!(
                    "merkle root mismatch: stored {} computed {}",
                    hex::encode(self.header.merkle_root),
                    hex::encode(computed)
                ),
            });
        }
        Ok(())
    }
}

fn build_header_bytes(
    event_count: u32,
    first_hlc: Hlc,
    last_hlc: Hlc,
    merkle_root: &[u8; 32],
) -> [u8; HEADER_SIZE as usize] {
    let mut out = [0u8; HEADER_SIZE as usize];
    out[0..4].copy_from_slice(SEGMENT_MAGIC_HEAD);
    out[4..6].copy_from_slice(&SEGMENT_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags
    out[8..12].copy_from_slice(&event_count.to_le_bytes());
    out[12..28].copy_from_slice(&first_hlc.to_le_bytes());
    out[28..44].copy_from_slice(&last_hlc.to_le_bytes());
    out[44..76].copy_from_slice(merkle_root);
    out
}

/// Compute the BLAKE3 Merkle root over an ordered list of 32-byte hashes.
/// Empty input → all-zero hash. Single input → input itself. Otherwise
/// builds a binary tree, duplicating odd nodes.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let l = layer[i];
            let r = if i + 1 < layer.len() { layer[i + 1] } else { l };
            let mut h = Hasher::new();
            h.update(b"ATEP-NODE-v1\0");
            h.update(&l);
            h.update(&r);
            next.push(*h.finalize().as_bytes());
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Hlc;
    use crate::event::{AtepEvent, EventHeader, EventPayload, StreamId};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::io::Cursor;

    fn make_event(seq: u64, sk: &SigningKey) -> AtepEvent {
        let h = EventHeader {
            schema_version: 1,
            event_id: ulid::Ulid::new().to_bytes(),
            agent_id: "agent://acme/foo".into(),
            stream: StreamId::Capability,
            stream_seq: seq,
            clock: Hlc::new(1000 + seq, 0, 1),
            parents: vec![],
            event_type: "capability.skill_added".into(),
            payload_schema_uri: "atep://schemas/v1/capability/skill_added".into(),
        };
        let p = EventPayload(ciborium::value::Value::Integer(seq.into()));
        AtepEvent::seal(h, p, sk, "k1".into()).unwrap()
    }

    #[test]
    fn write_read_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = SegmentWriter::new(Cursor::new(&mut buf)).unwrap();
            for i in 0..10 {
                w.append(&make_event(i, &sk)).unwrap();
            }
            let s = w.finalize().unwrap();
            assert_eq!(s.event_count, 10);
        }
        let mut r = SegmentReader::open(Cursor::new(buf)).unwrap();
        assert_eq!(r.header().event_count, 10);
        r.verify_merkle_root().unwrap();
        let events = r.read_all().unwrap();
        assert_eq!(events.len(), 10);
        for e in &events {
            e.verify(&sk.verifying_key()).unwrap();
        }
    }

    #[test]
    fn tampered_byte_breaks_crc() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = SegmentWriter::new(Cursor::new(&mut buf)).unwrap();
            w.append(&make_event(1, &sk)).unwrap();
            w.append(&make_event(2, &sk)).unwrap();
            w.finalize().unwrap();
        }
        // Flip a byte in the middle of a frame
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;
        let r = SegmentReader::open(Cursor::new(buf));
        assert!(matches!(r, Err(CliError::AtepIntegrity { .. })));
    }

    #[test]
    fn empty_segment_works() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let w = SegmentWriter::new(Cursor::new(&mut buf)).unwrap();
            w.finalize().unwrap();
        }
        let mut r = SegmentReader::open(Cursor::new(buf)).unwrap();
        assert_eq!(r.header().event_count, 0);
        assert!(r.read_all().unwrap().is_empty());
        r.verify_merkle_root().unwrap();
    }
}
