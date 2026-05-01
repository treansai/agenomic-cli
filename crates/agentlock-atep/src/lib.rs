//! ATEP — Agentic Trajectory Event Protocol.
//!
//! Two formats:
//!
//! 1. **Canonical CBOR** (RFC 8949 §4.2) — what gets hashed and signed.
//!    See [`event::AtepEvent::compute_causal_hash`].
//! 2. **Segment file** (`.atep`) — append-only on-disk container of multiple
//!    events. See [`segment`] for the binary layout.
//!
//! On-disk an agent's history lives in an [`AtepStore`]: a `manifest.json` plus
//! a `streams/` directory of segment files.

pub mod clock;
pub mod event;
pub mod keys;
pub mod segment;
pub mod store;

pub use clock::Hlc;
pub use event::{
    AtepEvent, CausalHash, EventAttestation, EventHeader, EventPayload, StreamId,
    ATEP_DOMAIN_SEPARATOR,
};
pub use keys::{generate_signing_key, load_signing_key, load_verifying_key, short_key_id};
pub use segment::{
    compute_merkle_root, SegmentHeader, SegmentReader, SegmentSummary, SegmentWriter,
    SEGMENT_MAGIC_HEAD, SEGMENT_MAGIC_TAIL, SEGMENT_VERSION,
};
pub use store::{
    AgentState, AtepManifest, AtepStore, SegmentRecord, VerificationReport,
    ATEP_MANIFEST_VERSION,
};
