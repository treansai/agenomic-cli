//! Canonical JSON (RFC 8785 / JCS-flavoured) and hashing primitives for
//! ledger entries.
//!
//! This is a faithful port of `agenomic-canonical` (agenomic-cloud), itself a
//! byte-compatible Rust port of the spec's reference implementation
//! (`agenomic-spec/scripts/trace-crypto.js`, canonical run-trace v0.3 / RFC
//! 0010). Keeping the three byte-for-byte compatible is what lets a ledger
//! written here be re-verified by the spec's reference verifier and by the
//! cloud, and vice-versa. Do not "improve" the rendering rules — any change
//! is a format break and requires a new domain separator version.
//!
//! Normative rules:
//!
//! ```text
//! canonical_json(v): keys sorted by UTF-16 code units, compact, primitives
//!                    rendered like ECMAScript JSON.stringify.
//! entry digest     = blake3( "AGENOMIC-LEDGER-ENTRY-v1\0" ‖ canonical_json(core) )
//! entry_hash       = "blake3:" + hex(entry digest)
//! ```
//!
//! BLAKE3 everywhere (Q2: no divergent digest vs ATEP / RFC 0010). Hashed
//! surfaces must not carry non-integer floats; payloads are committed by
//! `event_payload_hash`, never hashed inline.

use serde_json::Value;
use std::cmp::Ordering;

/// Domain separator for a ledger entry digest. Follows the platform pattern
/// (`ATEP-v1\0`, `AGENOMIC-TRACK-EVENT-v1\0`); bump the version on any format
/// break.
pub const LEDGER_ENTRY_DOMAIN: &[u8] = b"AGENOMIC-LEDGER-ENTRY-v1\0";

/// Prefix for a single BLAKE3 content hash (`blake3:<hex>`).
pub const BLAKE3_PREFIX: &str = "blake3:";

/// Genesis value for `previous_entry_hash` / `previous_run_entry_hash` of the
/// first entry in a chain. Matches the RFC 0010 reference verifier
/// (`blake3:` followed by 64 zero hex chars).
pub const GENESIS_ENTRY_HASH: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

/// Serialize `value` to the canonical JSON string used for hashing.
///
/// Object keys are emitted in ascending UTF-16 code-unit order, there is no
/// insignificant whitespace, and scalars are rendered exactly like
/// ECMAScript's `JSON.stringify`.
///
/// ```
/// # use agenomic_ledger_local::canonical::canonical_json;
/// # use serde_json::json;
/// let v = json!({ "b": 1, "a": 2 });
/// assert_eq!(canonical_json(&v), r#"{"a":2,"b":1}"#);
/// ```
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&format_number(n)),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                if let Some(v) = map.get(*key) {
                    write_canonical(v, out);
                }
            }
            out.push('}');
        }
    }
}

/// Append the `JSON.stringify`-equivalent rendering of a JSON string.
/// `serde_json`'s string serializer matches ECMAScript escaping for our
/// inputs (escapes `"`, `\`, the C0 controls with short forms where defined,
/// leaves `/` and non-ASCII untouched).
fn write_json_string(s: &str, out: &mut String) {
    match serde_json::to_string(s) {
        Ok(encoded) => out.push_str(&encoded),
        Err(_) => {
            // Unreachable for valid UTF-8, but never panic in library code.
            out.push('"');
            out.push('"');
        }
    }
}

fn format_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        // ECMAScript renders integer-valued numbers without a decimal point
        // (`JSON.stringify(1.0) === "1"`). 2^53 is the safe-integer bound.
        if f.is_finite() && f == f.trunc() && f.abs() < 9_007_199_254_740_992.0 {
            return (f as i64).to_string();
        }
        return serde_json::to_string(&Value::Number(n.clone())).unwrap_or_else(|_| f.to_string());
    }
    // Non-finite numbers cannot occur in a parsed serde_json::Number.
    "null".to_string()
}

/// Compare two strings by their UTF-16 code-unit sequences (the ordering
/// ECMAScript applies to object keys). Identical to byte order for the BMP;
/// differs only for astral-plane keys, which do not occur in our schemas.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Lower-case hex of `blake3(input)`.
///
/// ```
/// # use agenomic_ledger_local::canonical::blake3_hex;
/// assert_eq!(blake3_hex(b"abc").len(), 64);
/// ```
pub fn blake3_hex(input: &[u8]) -> String {
    hex::encode(blake3::hash(input).as_bytes())
}

/// `"blake3:" + blake3_hex(input)` — the platform's content-hash form.
///
/// ```
/// # use agenomic_ledger_local::canonical::prefixed_blake3;
/// assert!(prefixed_blake3(b"abc").starts_with("blake3:"));
/// ```
pub fn prefixed_blake3(input: &[u8]) -> String {
    format!("{BLAKE3_PREFIX}{}", blake3_hex(input))
}

/// The 32-byte domain-separated digest of a canonical entry core. This is
/// both the preimage of [`entry_hash_from_digest`] and the exact message
/// signed by Ed25519 ("sign the hash, not the body" — the ATEP rule).
///
/// ```
/// # use agenomic_ledger_local::canonical::{canonical_json, entry_digest};
/// # use serde_json::json;
/// let core = json!({ "event_type": "agent.started" });
/// let d1 = entry_digest(&canonical_json(&core));
/// let d2 = entry_digest(&canonical_json(&core));
/// assert_eq!(d1, d2);
/// ```
pub fn entry_digest(canonical_core: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEDGER_ENTRY_DOMAIN);
    hasher.update(canonical_core.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The `blake3:`-prefixed entry hash for a 32-byte entry digest.
///
/// ```
/// # use agenomic_ledger_local::canonical::{entry_digest, entry_hash_from_digest};
/// let h = entry_hash_from_digest(&entry_digest("{}"));
/// assert!(h.starts_with("blake3:"));
/// assert_eq!(h.len(), "blake3:".len() + 64);
/// ```
pub fn entry_hash_from_digest(digest: &[u8; 32]) -> String {
    format!("{BLAKE3_PREFIX}{}", hex::encode(digest))
}

/// Commit an arbitrary JSON payload by hash: the canonical form is hashed,
/// the payload itself is never stored in the entry (Q4 `hash_only` default).
///
/// ```
/// # use agenomic_ledger_local::canonical::payload_hash;
/// # use serde_json::json;
/// // Key order does not affect the committed hash.
/// let a = payload_hash(&json!({ "x": 1, "y": 2 }));
/// let b = payload_hash(&json!({ "y": 2, "x": 1 }));
/// assert_eq!(a, b);
/// ```
pub fn payload_hash(payload: &Value) -> String {
    prefixed_blake3(canonical_json(payload).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These first five tests are vendored from agenomic-canonical's suite —
    // they pin byte-compatibility with the cloud port and the JS reference.

    #[test]
    fn canonical_json_sorts_keys_and_is_compact() {
        let v = json!({ "b": 1, "a": 2, "nested": { "z": [3, 2, 1], "y": true } });
        assert_eq!(
            canonical_json(&v),
            "{\"a\":2,\"b\":1,\"nested\":{\"y\":true,\"z\":[3,2,1]}}"
        );
    }

    #[test]
    fn canonical_json_renders_integers_and_strings_like_json_stringify() {
        let v = json!({ "n": 12345, "s": "a\"b\\c", "neg": -7 });
        assert_eq!(
            canonical_json(&v),
            "{\"n\":12345,\"neg\":-7,\"s\":\"a\\\"b\\\\c\"}"
        );
    }

    #[test]
    fn integer_valued_float_renders_without_decimal() {
        let v: Value = serde_json::from_str("{\"x\":1.0,\"y\":2.5}").unwrap();
        assert_eq!(canonical_json(&v), "{\"x\":1,\"y\":2.5}");
    }

    #[test]
    fn canonical_json_is_order_independent() {
        let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn genesis_hash_has_platform_shape() {
        assert!(GENESIS_ENTRY_HASH.starts_with(BLAKE3_PREFIX));
        assert_eq!(GENESIS_ENTRY_HASH.len(), BLAKE3_PREFIX.len() + 64);
    }

    #[test]
    fn entry_digest_is_domain_separated() {
        // Same bytes without the domain must not collide with the entry
        // digest — the separator is doing its job.
        let core = canonical_json(&json!({ "k": "v" }));
        let with_domain = entry_digest(&core);
        let without_domain: [u8; 32] = *blake3::hash(core.as_bytes()).as_bytes();
        assert_ne!(with_domain, without_domain);
    }

    #[test]
    fn control_characters_escape_like_ecmascript() {
        let v = json!({ "s": "line\nbreak\ttab\u{0001}" });
        assert_eq!(canonical_json(&v), "{\"s\":\"line\\nbreak\\ttab\\u0001\"}");
    }

    #[test]
    fn non_ascii_passes_through_unescaped() {
        let v = json!({ "s": "héllo — 事件" });
        assert_eq!(canonical_json(&v), "{\"s\":\"héllo — 事件\"}");
    }
}
