//! OS credential store for secret keys that have no passphrase.
//!
//! macOS Keychain, Windows Credential Manager or the Linux Secret Service
//! (GNOME Keyring / KWallet). Every operation can fail (no Secret Service
//! running, blob size limits on Windows); callers must fall back to the file.

use zeroize::Zeroizing;

pub trait SecretVault: Send + Sync {
    fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String>;
    fn get(&self, fingerprint: &str) -> Result<Zeroizing<Vec<u8>>, String>;
    fn delete(&self, fingerprint: &str);
}

/// Vault backed by the operating system.
pub struct OsVault;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl OsVault {
    fn entry(fingerprint: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new("app.aegisgpg.desktop", fingerprint).map_err(|e| e.to_string())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl SecretVault for OsVault {
    fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String> {
        Self::entry(fingerprint)?.set_secret(secret).map_err(|e| e.to_string())
    }

    fn get(&self, fingerprint: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Self::entry(fingerprint)?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|e| e.to_string())
    }

    fn delete(&self, fingerprint: &str) {
        if let Ok(entry) = Self::entry(fingerprint) {
            let _ = entry.delete_credential();
        }
    }
}

/// Platforms without a credential store: always fails, so keys stay in files.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
impl SecretVault for OsVault {
    fn set(&self, _: &str, _: &[u8]) -> Result<(), String> {
        Err("no credential store on this platform".into())
    }
    fn get(&self, _: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("no credential store on this platform".into())
    }
    fn delete(&self, _: &str) {}
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Touches the real Keychain, so it only runs on request:
    /// `cargo test --lib os_vault -- --ignored`
    #[test]
    #[ignore]
    fn os_vault_round_trip() {
        let fp = "AEGISTESTFINGERPRINT00000000000000000000";
        let secret = vec![7u8; 700];
        OsVault.set(fp, &secret).unwrap();
        assert_eq!(*OsVault.get(fp).unwrap(), secret);
        OsVault.delete(fp);
        assert!(OsVault.get(fp).is_err());
    }
}
