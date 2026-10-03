//! On-disk keyring: one ASCII-armored certificate (with secret parts, if any)
//! per file, named by the primary key's fingerprint.
//!
//! Secret material is stored exactly as generated/imported, i.e. protected by
//! the user's passphrase when one was set.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use sequoia_openpgp as openpgp;

use super::wot::Trust;
use super::{GpgError, Result};

pub struct KeyStore {
    dir: PathBuf,
    /// Ownertrust per fingerprint, persisted in `trust.json`.
    trust: Mutex<HashMap<String, Trust>>,
}

impl KeyStore {
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
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
        Ok(Self { dir, trust: Mutex::new(trust) })
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
            if let Ok(cert) = Cert::from_file(&path) {
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
        Cert::from_file(path).map_err(Into::into)
    }

    /// Insert or merge. Merging never drops existing secret key material.
    pub fn put(&self, cert: Cert) -> Result<Cert> {
        let fp = cert.fingerprint().to_hex();
        let merged = match self.get(&fp) {
            Ok(existing) => existing.merge_public_and_secret(cert)?,
            Err(GpgError::KeyNotFound(_)) => cert,
            Err(e) => return Err(e),
        };
        let bytes = merged.as_tsk().armored().to_vec()?;
        let path = self.path_for(&fp)?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(tmp, path)?;
        Ok(merged)
    }

    pub fn delete(&self, fingerprint: &str) -> Result<()> {
        let path = self.path_for(fingerprint)?;
        if !path.exists() {
            return Err(GpgError::KeyNotFound(fingerprint.to_string()));
        }
        fs::remove_file(path)?;
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
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}
