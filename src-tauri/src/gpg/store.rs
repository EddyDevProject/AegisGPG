//! On-disk keyring: one ASCII-armored certificate (with secret parts, if any)
//! per file, named by the primary key's fingerprint.
//!
//! Secret material protected by a passphrase is stored exactly as
//! generated/imported. Secret keys *without* a passphrase are moved to the OS
//! credential store and only the public part stays on disk (marked by a
//! `<FP>.vault` file). If the credential store is unavailable the key simply
//! stays in the file, as before.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use sequoia_openpgp as openpgp;

use super::vault::{OsVault, SecretVault};
use super::wot::Trust;
use super::{GpgError, Result};

/// Atomically writes `bytes` to `path`. On Unix the temp file is created with
/// mode 0600, so the content is never readable by other users, even briefly.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` is ignored if a stale temp file already existed.
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp, path)
}

pub struct KeyStore {
    dir: PathBuf,
    /// Ownertrust per fingerprint, persisted in `trust.json`.
    trust: Mutex<HashMap<String, Trust>>,
    vault: Box<dyn SecretVault>,
}

/// True when some secret key in `cert` is stored without passphrase protection.
fn has_unprotected_secret(cert: &Cert) -> bool {
    cert.keys().secret().any(|k| !k.key().secret().is_encrypted())
}

impl KeyStore {
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        Self::open_with(dir, Box::new(OsVault))
    }

    pub fn open_with(dir: PathBuf, vault: Box<dyn SecretVault>) -> std::io::Result<Self> {
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let trust = fs::read(dir.join("trust.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let store = Self { dir, trust: Mutex::new(trust), vault };
        store.migrate_unprotected();
        Ok(store)
    }

    /// Moves existing unprotected secret keys into the credential store.
    fn migrate_unprotected(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else { return };
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().and_then(|e| e.to_str()) != Some("asc") {
                continue;
            }
            if let Ok(cert) = Cert::from_file(&path) {
                if has_unprotected_secret(&cert) {
                    // Best effort: on failure the file is left untouched.
                    let _ = self.write_cert(&cert);
                }
            }
        }
    }

    fn marker_for(&self, fingerprint: &str) -> Result<PathBuf> {
        Ok(self.path_for(fingerprint)?.with_extension("vault"))
    }

    /// Writes `cert` to disk. An unprotected secret goes to the vault first,
    /// is read back to verify it, and only then removed from the file.
    fn write_cert(&self, cert: &Cert) -> Result<()> {
        let fp = cert.fingerprint().to_hex();
        let path = self.path_for(&fp)?;
        let marker = self.marker_for(&fp)?;

        if cert.is_tsk() && has_unprotected_secret(cert) {
            let secret = zeroize::Zeroizing::new(cert.as_tsk().to_vec()?);
            let stored = self.vault.set(&fp, &secret).is_ok()
                && self.vault.get(&fp).map(|b| *b == *secret).unwrap_or(false);
            if stored {
                let public = cert.clone().strip_secret_key_material().armored().to_vec()?;
                write_private(&marker, b"")?;
                write_private(&path, &public)?;
                return Ok(());
            }
            self.vault.delete(&fp);
        }

        // Plain file: passphrase-protected secret, public-only, or no vault.
        write_private(&path, &cert.as_tsk().armored().to_vec()?)?;
        if marker.exists() {
            fs::remove_file(&marker)?;
            self.vault.delete(&fp);
        }
        Ok(())
    }

    /// Reads a certificate, re-attaching its secret from the vault if needed.
    fn read_cert(&self, path: &std::path::Path) -> Result<Cert> {
        let cert = Cert::from_file(path)?;
        if !path.with_extension("vault").exists() {
            return Ok(cert);
        }
        let fp = cert.fingerprint().to_hex();
        match self.vault.get(&fp).ok().and_then(|b| Cert::from_bytes(&b).ok()) {
            Some(secret) => Ok(cert.merge_public_and_secret(secret)?),
            // Vault entry gone or locked: keep the public key usable.
            None => Ok(cert),
        }
    }

    fn path_for(&self, fingerprint: &str) -> Result<PathBuf> {
        // Guard against path traversal: fingerprints are hex only.
        let fp = fingerprint.trim().to_uppercase();
        if fp.is_empty() || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(GpgError::InvalidInput("Invalid key fingerprint".into()));
        }
        Ok(self.dir.join(format!("{fp}.asc")))
    }

    pub fn all(&self) -> Result<Vec<Cert>> {
        let mut certs = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("asc") {
                continue;
            }
            // Skip unreadable files rather than hiding the whole keyring.
            if let Ok(cert) = self.read_cert(&path) {
                certs.push(cert);
            }
        }
        Ok(certs)
    }

    pub fn get(&self, fingerprint: &str) -> Result<Cert> {
        let path = self.path_for(fingerprint)?;
        if !path.exists() {
            return Err(GpgError::KeyNotFound(fingerprint.to_string()));
        }
        self.read_cert(&path)
    }

    /// Insert or merge. Merging never drops existing secret key material.
    pub fn put(&self, cert: Cert) -> Result<Cert> {
        let fp = cert.fingerprint().to_hex();
        let merged = match self.get(&fp) {
            Ok(existing) => existing.merge_public_and_secret(cert)?,
            Err(GpgError::KeyNotFound(_)) => cert,
            Err(e) => return Err(e),
        };
        self.write_cert(&merged)?;
        Ok(merged)
    }

    pub fn delete(&self, fingerprint: &str) -> Result<()> {
        let path = self.path_for(fingerprint)?;
        if !path.exists() {
            return Err(GpgError::KeyNotFound(fingerprint.to_string()));
        }
        fs::remove_file(path)?;
        let marker = self.marker_for(fingerprint)?;
        if marker.exists() {
            fs::remove_file(marker)?;
        }
        self.vault.delete(&fingerprint.trim().to_uppercase());
        let mut trust = self.trust.lock().unwrap();
        if trust.remove(&fingerprint.to_uppercase()).is_some() {
            self.persist_trust(&trust)?;
        }
        Ok(())
    }

    /// Own keys (secret material present) default to Ultimate, as in GnuPG.
    pub fn ownertrust_map(&self, certs: &[Cert]) -> HashMap<String, Trust> {
        let stored = self.trust.lock().unwrap();
        certs
            .iter()
            .map(|c| {
                let fp = c.fingerprint().to_hex();
                let default = if c.is_tsk() { Trust::Ultimate } else { Trust::Unknown };
                let t = stored.get(&fp).copied().unwrap_or(default);
                (fp, t)
            })
            .collect()
    }

    pub fn set_ownertrust(&self, fingerprint: &str, level: Trust) -> Result<()> {
        self.get(fingerprint)?; // must exist (also validates the fingerprint)
        let mut trust = self.trust.lock().unwrap();
        trust.insert(fingerprint.trim().to_uppercase(), level);
        self.persist_trust(&trust)
    }

    fn persist_trust(&self, trust: &HashMap<String, Trust>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(trust).map_err(|e| GpgError::Other(e.to_string()))?;
        let path = self.dir.join("trust.json");
        write_private(&path, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod vault_tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    #[derive(Default, Clone)]
    struct MemVault(Arc<Mutex<HashMap<String, Vec<u8>>>>);

    impl SecretVault for MemVault {
        fn set(&self, fp: &str, s: &[u8]) -> std::result::Result<(), String> {
            self.0.lock().unwrap().insert(fp.into(), s.to_vec());
            Ok(())
        }
        fn get(&self, fp: &str) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
            self.0.lock().unwrap().get(fp).cloned().map(Zeroizing::new).ok_or("missing".into())
        }
        fn delete(&self, fp: &str) {
            self.0.lock().unwrap().remove(fp);
        }
    }

    struct FailVault;
    impl SecretVault for FailVault {
        fn set(&self, _: &str, _: &[u8]) -> std::result::Result<(), String> { Err("no".into()) }
        fn get(&self, _: &str) -> std::result::Result<Zeroizing<Vec<u8>>, String> { Err("no".into()) }
        fn delete(&self, _: &str) {}
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn unprotected_secret_leaves_disk_and_round_trips() {
        let dir = tmp("vault");
        let vault = MemVault::default();
        let store = KeyStore::open_with(dir.clone(), Box::new(vault.clone())).unwrap();
        let (cert, _) = CertBuilder::general_purpose(Some("a@b.c")).generate().unwrap();
        let fp = cert.fingerprint().to_hex();
        store.put(cert).unwrap();

        let on_disk = Cert::from_file(dir.join(format!("{fp}.asc"))).unwrap();
        assert!(!on_disk.is_tsk(), "secret must not be in the file");
        assert!(store.get(&fp).unwrap().is_tsk(), "secret is re-attached from the vault");
        assert!(store.all().unwrap()[0].is_tsk());

        store.delete(&fp).unwrap();
        assert!(vault.get(&fp).is_err());
        assert!(!dir.join(format!("{fp}.vault")).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_file_is_migrated_on_open() {
        let dir = tmp("migrate");
        let (cert, _) = CertBuilder::general_purpose(Some("a@b.c")).generate().unwrap();
        let fp = cert.fingerprint().to_hex();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{fp}.asc")), cert.as_tsk().armored().to_vec().unwrap()).unwrap();

        let store = KeyStore::open_with(dir.clone(), Box::new(MemVault::default())).unwrap();
        assert!(!Cert::from_file(dir.join(format!("{fp}.asc"))).unwrap().is_tsk());
        assert!(store.get(&fp).unwrap().is_tsk());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn backup_restores_into_a_fresh_and_into_the_same_store() {
        use crate::gpg::backup;
        let (dir_a, dir_b) = (tmp("bk-a"), tmp("bk-b"));
        let a = KeyStore::open_with(dir_a.clone(), Box::new(MemVault::default())).unwrap();
        let (plain, _) = CertBuilder::general_purpose(Some("a@b.c")).generate().unwrap();
        let (other, _) = CertBuilder::general_purpose(Some("c@d.e")).generate().unwrap();
        a.put(plain.clone()).unwrap();
        a.put(other.strip_secret_key_material()).unwrap();

        let data = backup::create(&a.all().unwrap(), "a long backup phrase").unwrap();
        let restored = backup::restore(&data, "a long backup phrase").unwrap();
        assert_eq!(restored.len(), 2);

        let b = KeyStore::open_with(dir_b.clone(), Box::new(MemVault::default())).unwrap();
        for c in &restored {
            b.put(c.clone()).unwrap();
        }
        assert!(b.get(&plain.fingerprint().to_hex()).unwrap().is_tsk());
        // Restoring again over existing keys must work too.
        for c in &restored {
            a.put(c.clone()).unwrap();
        }
        assert!(a.get(&plain.fingerprint().to_hex()).unwrap().is_tsk());
        fs::remove_dir_all(dir_a).unwrap();
        fs::remove_dir_all(dir_b).unwrap();
    }

    #[test]
    fn unavailable_vault_keeps_secret_in_file() {
        let dir = tmp("fallback");
        let store = KeyStore::open_with(dir.clone(), Box::new(FailVault)).unwrap();
        let (cert, _) = CertBuilder::general_purpose(Some("a@b.c")).generate().unwrap();
        let fp = cert.fingerprint().to_hex();
        store.put(cert).unwrap();
        assert!(Cert::from_file(dir.join(format!("{fp}.asc"))).unwrap().is_tsk());
        assert!(!dir.join(format!("{fp}.vault")).exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::write_private;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_private_is_owner_only_and_overwrites() {
        let dir = std::env::temp_dir().join(format!("aegis-priv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.asc");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
