//! Signing-key store: Ed25519 key lifecycle for the ledger.
//!
//! v1 ships the local file keystore (Q7 floor); the trait is shaped after
//! `agenomic-crypto::SigningKeyStore` (agenomic-cloud) so a KMS-backed
//! implementation bolts on in the cloud follow-up without touching call
//! sites. Key material handling reuses `agenomic-atep::keys` (PKCS#8 PEM,
//! atomic writes, mode 0600, `ed25519:<8hex>` short key ids).
//!
//! Lifecycle rules:
//! - **generate** — first key becomes active.
//! - **rotate** — a new key becomes active; the old key is kept with status
//!   `rotated` so historical signatures verify forever.
//! - **revoke** — the key is marked untrusted; entries signed by it still
//!   *cryptographically* verify but the verification engine reports a
//!   revoked-key warning. The active key cannot be revoked (rotate first) —
//!   a ledger must never be left without a signing key.
//!
//! Private keys never appear in logs, reports, or errors.

use agenomic_core::{io_at, CliError, CliResult};
use agenomic_fs::write_atomic;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Manifest schema version for the key store.
pub const KEYS_MANIFEST_VERSION: &str = "agenomic.ledger.keys/v0.1";
/// File name of the key manifest inside the keystore root.
pub const KEYS_MANIFEST_FILE: &str = "keys-manifest.json";

/// Lifecycle status of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// The current signing key.
    Active,
    /// Superseded by rotation; still trusted for historical verification.
    Rotated,
    /// Untrusted; signatures verify cryptographically but are flagged.
    Revoked,
}

/// One key's manifest record. The private key lives in `pem_file` (0600);
/// the public key is embedded so verification needs no extra files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Short key id: `ed25519:<8hex>` = first 8 bytes of BLAKE3(public key).
    pub key_id: String,
    /// File name of the PKCS#8 PEM private key, relative to the store root.
    pub pem_file: String,
    /// SPKI PEM of the public key (safe to embed and export).
    pub public_key_pem: String,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeysManifest {
    manifest_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_key_id: Option<String>,
    /// Keyed by `key_id` for stable, sorted serialization.
    keys: BTreeMap<String, KeyRecord>,
}

/// Signing and key-resolution surface used by the ledger.
///
/// `sign` uses the active key; `verifying_key`/`key_status` resolve *any*
/// known key so historical entries verify after rotation and revoked keys
/// can be flagged rather than failing to resolve.
pub trait SigningKeyStore {
    /// Key id of the current active signing key.
    fn active_key_id(&self) -> CliResult<String>;
    /// Sign a 32-byte digest with the active key. Returns
    /// `(key_id, hex_signature)`.
    fn sign(&self, digest: &[u8; 32]) -> CliResult<(String, String)>;
    /// Resolve any known key (active, rotated, or revoked) for verification.
    fn verifying_key(&self, key_id: &str) -> CliResult<ed25519_dalek::VerifyingKey>;
    /// Lifecycle status of a known key.
    fn key_status(&self, key_id: &str) -> CliResult<KeyStatus>;
}

/// File-backed keystore rooted at a directory (default
/// `~/.config/agenomic/keys/`, Q8).
///
/// Layout: `keys-manifest.json` + one `ledger-<8hex>.pem` (+ `.pub`) per key.
#[derive(Debug)]
pub struct FileKeyStore {
    root: PathBuf,
    manifest: KeysManifest,
}

impl FileKeyStore {
    /// Open the keystore at `root`, creating an empty one (no keys yet) if
    /// the manifest does not exist.
    ///
    /// ```
    /// # use agenomic_ledger_local::keystore::FileKeyStore;
    /// # let dir = tempfile::tempdir().unwrap();
    /// let store = FileKeyStore::open(dir.path()).unwrap();
    /// assert!(store.list().is_empty());
    /// ```
    pub fn open(root: &Path) -> CliResult<Self> {
        let manifest_path = root.join(KEYS_MANIFEST_FILE);
        let manifest = if manifest_path.exists() {
            let raw =
                std::fs::read_to_string(&manifest_path).map_err(|e| io_at(&manifest_path, e))?;
            let manifest: KeysManifest = serde_json::from_str(&raw)
                .map_err(|e| CliError::LedgerKeyStore(format!("parse key manifest: {e}")))?;
            if manifest.manifest_version != KEYS_MANIFEST_VERSION {
                return Err(CliError::LedgerKeyStore(format!(
                    "unsupported key manifest version {:?} (expected {KEYS_MANIFEST_VERSION:?})",
                    manifest.manifest_version
                )));
            }
            manifest
        } else {
            std::fs::create_dir_all(root).map_err(|e| io_at(root, e))?;
            KeysManifest {
                manifest_version: KEYS_MANIFEST_VERSION.to_string(),
                active_key_id: None,
                keys: BTreeMap::new(),
            }
        };
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
        })
    }

    /// Generate a new Ed25519 key. The first generated key becomes active;
    /// later ones require [`FileKeyStore::rotate`] instead.
    ///
    /// ```
    /// # use agenomic_ledger_local::keystore::{FileKeyStore, SigningKeyStore};
    /// # let dir = tempfile::tempdir().unwrap();
    /// let mut store = FileKeyStore::open(dir.path()).unwrap();
    /// let key_id = store.generate().unwrap();
    /// assert_eq!(store.active_key_id().unwrap(), key_id);
    /// ```
    pub fn generate(&mut self) -> CliResult<String> {
        if self.manifest.active_key_id.is_some() {
            return Err(CliError::LedgerKeyStore(
                "an active key already exists; use rotate to supersede it".to_string(),
            ));
        }
        let key_id = self.create_key_files()?;
        self.manifest.active_key_id = Some(key_id.clone());
        self.save()?;
        Ok(key_id)
    }

    /// Rotate: generate a fresh key and make it active; the previous active
    /// key becomes `rotated` and keeps verifying historical signatures.
    ///
    /// ```
    /// # use agenomic_ledger_local::keystore::{FileKeyStore, KeyStatus, SigningKeyStore};
    /// # let dir = tempfile::tempdir().unwrap();
    /// let mut store = FileKeyStore::open(dir.path()).unwrap();
    /// let old = store.generate().unwrap();
    /// let new = store.rotate().unwrap();
    /// assert_ne!(old, new);
    /// assert_eq!(store.key_status(&old).unwrap(), KeyStatus::Rotated);
    /// assert_eq!(store.active_key_id().unwrap(), new);
    /// ```
    pub fn rotate(&mut self) -> CliResult<String> {
        let Some(previous) = self.manifest.active_key_id.clone() else {
            return Err(CliError::LedgerKeyStore(
                "no active key to rotate; generate one first".to_string(),
            ));
        };
        let key_id = self.create_key_files()?;
        if let Some(record) = self.manifest.keys.get_mut(&previous) {
            record.status = KeyStatus::Rotated;
            record.rotated_at = Some(Utc::now());
        }
        self.manifest.active_key_id = Some(key_id.clone());
        self.save()?;
        Ok(key_id)
    }

    /// Revoke a non-active key. Signatures made with it remain
    /// cryptographically verifiable but the verification engine flags them.
    /// Revoking the active key is refused — rotate first.
    pub fn revoke(&mut self, key_id: &str) -> CliResult<()> {
        if self.manifest.active_key_id.as_deref() == Some(key_id) {
            return Err(CliError::LedgerKeyStore(format!(
                "{key_id} is the active key; rotate before revoking"
            )));
        }
        let record = self
            .manifest
            .keys
            .get_mut(key_id)
            .ok_or_else(|| CliError::LedgerKeyStore(format!("unknown key {key_id}")))?;
        if record.status == KeyStatus::Revoked {
            return Err(CliError::LedgerKeyStore(format!(
                "{key_id} is already revoked"
            )));
        }
        record.status = KeyStatus::Revoked;
        record.revoked_at = Some(Utc::now());
        self.save()
    }

    /// All key records, sorted by key id.
    pub fn list(&self) -> Vec<&KeyRecord> {
        self.manifest.keys.values().collect()
    }

    /// SPKI PEM of a key's public half (for export; never the private key).
    pub fn export_public(&self, key_id: &str) -> CliResult<String> {
        Ok(self.record(key_id)?.public_key_pem.clone())
    }

    /// Root directory of this keystore.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn record(&self, key_id: &str) -> CliResult<&KeyRecord> {
        self.manifest
            .keys
            .get(key_id)
            .ok_or_else(|| CliError::LedgerKeyStore(format!("unknown key {key_id}")))
    }

    /// Generate key material on disk and register the manifest record.
    fn create_key_files(&mut self) -> CliResult<String> {
        // Two-step: generate to a temp name (the key id is derived from the
        // public key, so it isn't known before generation), then rename to
        // the canonical `ledger-<8hex>.pem`.
        let temp = self.root.join(".ledger-keygen.pem");
        agenomic_atep::keys::generate_signing_key(&temp)?;
        let sk = agenomic_atep::keys::load_signing_key(&temp)?;
        let key_id = agenomic_atep::keys::short_key_id(&sk.verifying_key());
        let short_hex = key_id.trim_start_matches("ed25519:");
        let pem_file = format!("ledger-{short_hex}.pem");
        let final_path = self.root.join(&pem_file);
        std::fs::rename(&temp, &final_path).map_err(|e| io_at(&final_path, e))?;
        let temp_pub = self.root.join(".ledger-keygen.pem.pub");
        let final_pub = self.root.join(format!("{pem_file}.pub"));
        std::fs::rename(&temp_pub, &final_pub).map_err(|e| io_at(&final_pub, e))?;
        let public_key_pem =
            std::fs::read_to_string(&final_pub).map_err(|e| io_at(&final_pub, e))?;

        self.manifest.keys.insert(
            key_id.clone(),
            KeyRecord {
                key_id: key_id.clone(),
                pem_file,
                public_key_pem,
                status: KeyStatus::Active,
                created_at: Utc::now(),
                rotated_at: None,
                revoked_at: None,
            },
        );
        Ok(key_id)
    }

    fn save(&self) -> CliResult<()> {
        let raw = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| CliError::LedgerKeyStore(format!("serialize key manifest: {e}")))?;
        write_atomic(&self.root.join(KEYS_MANIFEST_FILE), &raw)
    }
}

impl SigningKeyStore for FileKeyStore {
    fn active_key_id(&self) -> CliResult<String> {
        self.manifest
            .active_key_id
            .clone()
            .ok_or_else(|| CliError::LedgerKeyStore("keystore has no active key".to_string()))
    }

    fn sign(&self, digest: &[u8; 32]) -> CliResult<(String, String)> {
        let key_id = self.active_key_id()?;
        let record = self.record(&key_id)?;
        let sk = agenomic_atep::keys::load_signing_key(&self.root.join(&record.pem_file))?;
        let signature = sk.sign(digest);
        Ok((key_id, hex::encode(signature.to_bytes())))
    }

    fn verifying_key(&self, key_id: &str) -> CliResult<ed25519_dalek::VerifyingKey> {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        let record = self.record(key_id)?;
        ed25519_dalek::VerifyingKey::from_public_key_pem(&record.public_key_pem)
            .map_err(|e| CliError::LedgerKeyStore(format!("parse public key {key_id}: {e}")))
    }

    fn key_status(&self, key_id: &str) -> CliResult<KeyStatus> {
        Ok(self.record(key_id)?.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_then_reload_keeps_active_key() {
        let dir = tempdir().unwrap();
        let key_id = {
            let mut store = FileKeyStore::open(dir.path()).unwrap();
            store.generate().unwrap()
        };
        let store = FileKeyStore::open(dir.path()).unwrap();
        assert_eq!(store.active_key_id().unwrap(), key_id);
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn second_generate_is_refused() {
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        store.generate().unwrap();
        assert!(matches!(
            store.generate().unwrap_err(),
            CliError::LedgerKeyStore(_)
        ));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        store.generate().unwrap();
        let digest = [7u8; 32];
        let (key_id, sig_hex) = store.sign(&digest).unwrap();
        let vk = store.verifying_key(&key_id).unwrap();
        let bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        assert!(vk.verify_strict(&digest, &sig).is_ok());
    }

    #[test]
    fn rotation_keeps_old_key_verifiable() {
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        store.generate().unwrap();
        let digest = [9u8; 32];
        let (old_id, old_sig) = store.sign(&digest).unwrap();

        let new_id = store.rotate().unwrap();
        assert_ne!(old_id, new_id);
        assert_eq!(store.key_status(&old_id).unwrap(), KeyStatus::Rotated);

        // The historical signature still verifies via the rotated key.
        let vk = store.verifying_key(&old_id).unwrap();
        let bytes: [u8; 64] = hex::decode(old_sig).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        assert!(vk.verify_strict(&digest, &sig).is_ok());

        // New signatures come from the new key.
        let (signer, _) = store.sign(&digest).unwrap();
        assert_eq!(signer, new_id);
    }

    #[test]
    fn revoking_active_key_is_refused_but_rotated_key_revokes() {
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        let first = store.generate().unwrap();
        assert!(store.revoke(&first).is_err());

        store.rotate().unwrap();
        store.revoke(&first).unwrap();
        assert_eq!(store.key_status(&first).unwrap(), KeyStatus::Revoked);
        // Still resolvable for verification (flagging, not failing).
        assert!(store.verifying_key(&first).is_ok());
        // Double-revoke is refused.
        assert!(store.revoke(&first).is_err());
    }

    #[test]
    fn export_public_never_leaks_private_material() {
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        let key_id = store.generate().unwrap();
        let pem = store.export_public(&key_id).unwrap();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
        assert!(!pem.contains("PRIVATE"));
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut store = FileKeyStore::open(dir.path()).unwrap();
        let key_id = store.generate().unwrap();
        let short = key_id.trim_start_matches("ed25519:");
        let pem = dir.path().join(format!("ledger-{short}.pem"));
        let mode = std::fs::metadata(&pem).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
