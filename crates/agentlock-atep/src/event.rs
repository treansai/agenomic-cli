//! ATEP event types and canonical encoding.
//!
//! ## Canonical encoding
//!
//! For hashing and signing, we use **CBOR** (RFC 8949 §4.2 — "Core
//! Deterministic Encoding"): definite-length arrays/maps, integer-encoded
//! lengths, sorted map keys (we encode ordered structs only, never raw maps,
//! so this is automatic for [`EventHeader`]).
//!
//! The `causal_hash` is computed as:
//!
//! ```text
//! causal_hash = BLAKE3(
//!     ATEP-DOMAIN
//!     || u64_le(len(body))
//!     || body                                // canonical CBOR(header, payload)
//!     || u32_le(len(parents))
//!     || sorted(parent_hash)*                // each parent is 32 bytes
//! )
//! ```

use agentlock_core::{CliError, CliResult};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::clock::Hlc;

/// Domain separator for ATEP causal hashes.
pub const ATEP_DOMAIN_SEPARATOR: &[u8] = b"ATEP-v1\0";

/// 32-byte BLAKE3 causal hash of an ATEP event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct CausalHash(#[serde(with = "hex_serde")] pub [u8; 32]);

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

/// One of the seven ATEP streams.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StreamId {
    Identity,
    Capability,
    Knowledge,
    Policy,
    Runtime,
    Interaction,
    Governance,
}

impl StreamId {
    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Capability => "capability",
            Self::Knowledge => "knowledge",
            Self::Policy => "policy",
            Self::Runtime => "runtime",
            Self::Interaction => "interaction",
            Self::Governance => "governance",
        }
    }

    pub const ALL: [Self; 7] = [
        Self::Identity,
        Self::Capability,
        Self::Knowledge,
        Self::Policy,
        Self::Runtime,
        Self::Interaction,
        Self::Governance,
    ];
}

/// Header for an ATEP event.
///
/// Fields are listed in **canonical order**; ciborium serializes structs
/// field-by-field, giving us a deterministic encoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventHeader {
    pub schema_version: u16,
    /// 16-byte ULID.
    #[serde(with = "ulid_bytes")]
    pub event_id: [u8; 16],
    /// Canonical agent URI (`agent://org/name`).
    pub agent_id: String,
    pub stream: StreamId,
    pub stream_seq: u64,
    pub clock: Hlc,
    pub parents: Vec<CausalHash>,
    pub event_type: String,
    pub payload_schema_uri: String,
}

mod ulid_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        let id = ulid::Ulid::from_bytes(*b);
        s.serialize_str(&id.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let id: ulid::Ulid = s.parse().map_err(serde::de::Error::custom)?;
        Ok(id.to_bytes())
    }
}

/// Opaque event payload — an arbitrary CBOR value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventPayload(pub ciborium::value::Value);

impl Eq for EventPayload {}

/// Detached signature block over the event's `causal_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventAttestation {
    pub signer_key_id: String,
    /// Algorithm identifier — only `"ed25519"` in v1.
    pub algo: String,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

/// A complete sealed ATEP event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtepEvent {
    pub header: EventHeader,
    pub payload: EventPayload,
    pub causal_hash: CausalHash,
    pub attestation: EventAttestation,
}

/// Canonical CBOR body bytes of `(header, payload)`.
///
/// Parents are sorted before encoding so the body is parent-order-independent.
fn canonical_body(header: &EventHeader, payload: &EventPayload) -> CliResult<Vec<u8>> {
    let mut canon = header.clone();
    canon.parents.sort();
    let mut out = Vec::new();
    let pair = (&canon, payload);
    ciborium::ser::into_writer(&pair, &mut out)
        .map_err(|e| CliError::Internal(format!("cbor encode: {e}")))?;
    Ok(out)
}

impl AtepEvent {
    /// Compute the canonical body CBOR bytes for `(header, payload)`.
    pub fn canonical_body_bytes(
        header: &EventHeader,
        payload: &EventPayload,
    ) -> CliResult<Vec<u8>> {
        canonical_body(header, payload)
    }

    /// Compute the causal_hash for `(header, payload)`.
    pub fn compute_causal_hash(
        header: &EventHeader,
        payload: &EventPayload,
    ) -> CliResult<CausalHash> {
        let body = canonical_body(header, payload)?;
        let mut sorted_parents: Vec<CausalHash> = header.parents.clone();
        sorted_parents.sort();

        let mut h = Hasher::new();
        h.update(ATEP_DOMAIN_SEPARATOR);
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(&body);
        h.update(&(sorted_parents.len() as u32).to_le_bytes());
        for p in &sorted_parents {
            h.update(&p.0);
        }
        let bytes = *h.finalize().as_bytes();
        Ok(CausalHash(bytes))
    }

    /// Build a signed event. Caller fills `header.parents` and `header.clock`.
    ///
    /// ```no_run
    /// use agentlock_atep::*;
    /// use ed25519_dalek::SigningKey;
    /// # let mut rng = rand::rngs::OsRng;
    /// # let sk = SigningKey::generate(&mut rng);
    /// let header = EventHeader {
    ///     schema_version: 1,
    ///     event_id: [0u8; 16],
    ///     agent_id: "agent://acme/foo".into(),
    ///     stream: StreamId::Capability,
    ///     stream_seq: 0,
    ///     clock: Hlc::new(0, 0, 1),
    ///     parents: vec![],
    ///     event_type: "capability.skill_added".into(),
    ///     payload_schema_uri: "atep://schemas/v1/capability/skill_added".into(),
    /// };
    /// let p = EventPayload(ciborium::value::Value::Null);
    /// let _e = AtepEvent::seal(header, p, &sk, "key-1".into()).unwrap();
    /// ```
    pub fn seal(
        header: EventHeader,
        payload: EventPayload,
        signing_key: &ed25519_dalek::SigningKey,
        key_id: String,
    ) -> CliResult<Self> {
        use ed25519_dalek::Signer;
        let causal = Self::compute_causal_hash(&header, &payload)?;
        let signature = signing_key.sign(&causal.0);
        Ok(Self {
            header,
            payload,
            causal_hash: causal,
            attestation: EventAttestation {
                signer_key_id: key_id,
                algo: "ed25519".into(),
                signature: signature.to_bytes(),
            },
        })
    }

    /// Verify the event recomputes its `causal_hash` AND that the signature
    /// is valid for the given verifying key.
    pub fn verify(&self, vk: &ed25519_dalek::VerifyingKey) -> CliResult<()> {
        use ed25519_dalek::Verifier;
        let recomputed = Self::compute_causal_hash(&self.header, &self.payload)?;
        if recomputed != self.causal_hash {
            return Err(CliError::AtepIntegrity {
                reason: format!(
                    "causal_hash recomputed mismatch: stored={} computed={}",
                    hex::encode(self.causal_hash.0),
                    hex::encode(recomputed.0)
                ),
            });
        }
        if self.attestation.algo != "ed25519" {
            return Err(CliError::AtepIntegrity {
                reason: format!("unsupported algo {}", self.attestation.algo),
            });
        }
        let sig = ed25519_dalek::Signature::from_bytes(&self.attestation.signature);
        vk.verify(&self.causal_hash.0, &sig).map_err(|_| {
            CliError::AtepSignatureInvalid {
                event_id: ulid::Ulid::from_bytes(self.header.event_id).to_string(),
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn sample_header() -> EventHeader {
        EventHeader {
            schema_version: 1,
            event_id: [0u8; 16],
            agent_id: "agent://acme/foo".into(),
            stream: StreamId::Capability,
            stream_seq: 0,
            clock: Hlc::new(1, 0, 1),
            parents: vec![],
            event_type: "capability.skill_added".into(),
            payload_schema_uri: "atep://schemas/v1/capability/skill_added".into(),
        }
    }

    #[test]
    fn seal_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let h = sample_header();
        let p = EventPayload(ciborium::value::Value::Null);
        let e = AtepEvent::seal(h, p, &sk, "k1".into()).unwrap();
        e.verify(&vk).unwrap();
    }

    #[test]
    fn tampered_payload_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let h = sample_header();
        let p = EventPayload(ciborium::value::Value::Null);
        let mut e = AtepEvent::seal(h, p, &sk, "k1".into()).unwrap();
        e.payload = EventPayload(ciborium::value::Value::Bool(true));
        let r = e.verify(&vk);
        assert!(matches!(r, Err(CliError::AtepIntegrity { .. })));
    }

    #[test]
    fn tampered_signature_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let h = sample_header();
        let p = EventPayload(ciborium::value::Value::Null);
        let mut e = AtepEvent::seal(h, p, &sk, "k1".into()).unwrap();
        e.attestation.signature[0] ^= 0xFF;
        let r = e.verify(&vk);
        assert!(matches!(r, Err(CliError::AtepSignatureInvalid { .. })));
    }

    #[test]
    fn parent_order_doesnt_affect_hash() {
        let sk = SigningKey::generate(&mut OsRng);
        let p1 = CausalHash([1u8; 32]);
        let p2 = CausalHash([2u8; 32]);

        let mut h1 = sample_header();
        h1.parents = vec![p1, p2];
        let mut h2 = sample_header();
        h2.parents = vec![p2, p1];

        let payload = EventPayload(ciborium::value::Value::Null);
        let c1 = AtepEvent::compute_causal_hash(&h1, &payload).unwrap();
        let c2 = AtepEvent::compute_causal_hash(&h2, &payload).unwrap();
        assert_eq!(c1, c2);

        let _ = sk; // unused except to silence warnings if any
    }

    #[test]
    fn cbor_canonical_roundtrip() {
        let h = sample_header();
        let p = EventPayload(ciborium::value::Value::Text("hello".into()));
        let body1 = canonical_body(&h, &p).unwrap();
        // Parse and re-encode
        let pair: (EventHeader, EventPayload) = ciborium::de::from_reader(body1.as_slice()).unwrap();
        let body2 = canonical_body(&pair.0, &pair.1).unwrap();
        assert_eq!(body1, body2);
    }
}
