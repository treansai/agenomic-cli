//! Ed25519 signing-key helpers used by both ATEP and the attestation crate.

use std::path::Path;

use agentlock_core::{io_at, CliError, CliResult};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand_core::OsRng;

/// Generate a new ed25519 signing key, write it as PKCS#8 PEM at `path`,
/// also write the public key as PEM at `path.pub`, and return the hex-encoded
/// short key id (first 8 bytes of BLAKE3(public_key)).
///
/// The private key file is created with mode 0600 on Unix.
pub fn generate_signing_key(path: &Path) -> CliResult<String> {
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pem = sk
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| CliError::Internal(format!("encode pkcs8 pem: {e}")))?;
    agentlock_fs::write_atomic(path, pem.as_bytes())?;
    agentlock_fs::set_secret_mode(path)?;

    let vk_pem = sk
        .verifying_key()
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| CliError::Internal(format!("encode public pem: {e}")))?;
    let pub_path = path.with_file_name(format!(
        "{}.pub",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    agentlock_fs::write_atomic(&pub_path, vk_pem.as_bytes())?;

    Ok(short_key_id(&sk.verifying_key()))
}

/// Load a PKCS#8 PEM private key from disk.
pub fn load_signing_key(path: &Path) -> CliResult<ed25519_dalek::SigningKey> {
    let pem = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
    ed25519_dalek::SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| CliError::Internal(format!("parse signing key pem: {e}")))
}

/// Load a public key (PKCS#8 SubjectPublicKeyInfo PEM).
pub fn load_verifying_key(path: &Path) -> CliResult<ed25519_dalek::VerifyingKey> {
    let pem = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
    ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)
        .map_err(|e| CliError::Internal(format!("parse public key pem: {e}")))
}

/// Compute the canonical short key id used in attestations and ATEP headers.
pub fn short_key_id(vk: &ed25519_dalek::VerifyingKey) -> String {
    let h = blake3::hash(vk.as_bytes());
    let bytes = h.as_bytes();
    format!("ed25519:{}", hex::encode(&bytes[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_and_reload() {
        let d = tempdir().unwrap();
        let key = d.path().join("k.pem");
        let id1 = generate_signing_key(&key).unwrap();
        assert!(id1.starts_with("ed25519:"));

        let sk = load_signing_key(&key).unwrap();
        let id2 = short_key_id(&sk.verifying_key());
        assert_eq!(id1, id2);

        let pub_path = d.path().join("k.pem.pub");
        let vk = load_verifying_key(&pub_path).unwrap();
        assert_eq!(vk.as_bytes(), sk.verifying_key().as_bytes());
    }
}
