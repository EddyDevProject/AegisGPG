//! Unlock with KleyKnox: a vault on a USB stick that keeps each key's
//! passphrase encrypted under one master passphrase, so typing that one
//! unlocks every key it holds. KleyKnox is a separate command-line tool; this
//! module only reads its vault. Keep the format in sync with kleyknox:
//!
//! - `kleyknox/<name>.gpg.age`: age, passphrase (scrypt) recipient, wrapping
//!   `kleyknox-gpg-v1\nfingerprint <fpr>\n(keygrip <grip>\n)*passphrase <pw>\n\n<armored secret key>`
//! - `kleyknox/<name>.asc`: the matching public key

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use serde::Serialize;
use zeroize::Zeroizing;

use super::{GpgError, Result};

const DIR_NAME: &str = "kleyknox";
const ENTRY_SUFFIX: &str = ".gpg.age";
const BUNDLE_MAGIC: &str = "kleyknox-gpg-v1";
/// Highest scrypt cost accepted (kleyknox writes 20). Without it age caps the
/// cost from this machine's speed, refusing vaults made on faster ones.
const MAX_WORK_FACTOR: u8 = 22;

/// One decrypted vault entry.
pub struct Entry {
    pub name: String,
    pub fingerprint: String,
    pub passphrase: Zeroizing<String>,
    pub secret_armor: Zeroizing<String>,
}

#[derive(Serialize)]
pub struct Status {
    /// Vault directory, when a stick with one is mounted.
    pub dir: Option<String>,
    /// Names of the GPG entries in it.
    pub entries: Vec<String>,
}

/// Where removable volumes are mounted on each platform.
fn mount_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if cfg!(target_os = "macos") {
        roots.push(PathBuf::from("/Volumes"));
    } else if cfg!(windows) {
        // Drive letters are the roots themselves: D:\kleyknox, E:\kleyknox...
        return ('D'..='Z').map(|d| PathBuf::from(format!("{d}:\\"))).collect();
    } else {
        let user = std::env::var("USER").unwrap_or_default();
        roots.push(PathBuf::from("/run/media").join(&user));
        roots.push(PathBuf::from("/media").join(&user));
        roots.push(PathBuf::from("/media"));
        roots.push(PathBuf::from("/mnt"));
    }
    roots
        .into_iter()
        .flat_map(|root| fs::read_dir(root).into_iter().flatten().flatten().map(|e| e.path()))
        .collect()
}

/// The vault: `$KLEYKNOX_DIR` if set, else the first mounted volume with a
/// `kleyknox/` directory holding at least one GPG entry.
pub fn locate() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("KLEYKNOX_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir)).filter(|d| d.is_dir());
    }
    mount_roots()
        .into_iter()
        .map(|volume| volume.join(DIR_NAME))
        .find(|dir| !entry_names(dir).is_empty())
}

fn entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok()?.strip_suffix(ENTRY_SUFFIX).map(str::to_owned))
        .collect();
    names.sort();
    names
}

pub fn status() -> Status {
    match locate() {
        Some(dir) => Status { entries: entry_names(&dir), dir: Some(dir.display().to_string()) },
        None => Status { dir: None, entries: Vec::new() },
    }
}

/// Decrypts every GPG entry with the kleyknox passphrase. Each entry costs a
/// deliberate scrypt run (about a second), so call it off the UI thread.
pub fn open_all(dir: &Path, passphrase: &str) -> Result<Vec<Entry>> {
    let names = entry_names(dir);
    if names.is_empty() {
        return Err(GpgError::NotFound(format!("GPG keys in {}", dir.display())));
    }
    let mut entries = Vec::new();
    for name in names {
        let text = decrypt_file(&dir.join(format!("{name}{ENTRY_SUFFIX}")), passphrase)?;
        entries.push(parse(name, &text)?);
    }
    Ok(entries)
}

fn decrypt_file(path: &Path, passphrase: &str) -> Result<Zeroizing<String>> {
    let decryptor = age::Decryptor::new(fs::File::open(path)?)
        .map_err(|_| GpgError::InvalidInput(format!("{} is not a kleyknox entry", path.display())))?;
    let mut identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => GpgError::WrongPassphrase,
            other => GpgError::Other(format!("Cannot read {}: {other}", path.display())),
        })?;
    let mut text = Zeroizing::new(String::new());
    reader
        .read_to_string(&mut text)
        .map_err(|_| GpgError::Corrupted)?;
    Ok(text)
}

fn parse(name: String, text: &str) -> Result<Entry> {
    let malformed = || GpgError::InvalidInput(format!("KleyKnox entry {name} is malformed"));
    let (header, armor) = text.split_once("\n\n").ok_or_else(malformed)?;
    let mut lines = header.lines();
    if lines.next() != Some(BUNDLE_MAGIC) {
        return Err(malformed());
    }
    let mut fingerprint = None;
    let mut passphrase = Zeroizing::new(String::new());
    for line in lines {
        match line.split_once(' ') {
            Some(("fingerprint", v)) => fingerprint = Some(v.to_uppercase()),
            Some(("passphrase", v)) => passphrase.push_str(v),
            Some(("keygrip", _)) => {}
            _ => return Err(malformed()),
        }
    }
    Ok(Entry {
        fingerprint: fingerprint.ok_or_else(malformed)?,
        name,
        passphrase,
        secret_armor: Zeroizing::new(armor.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_entry(dir: &Path, name: &str, body: &str, pass: &str) {
        let mut out = Vec::new();
        let enc = age::Encryptor::with_user_passphrase(SecretString::from(pass.to_owned()));
        let mut w = enc.wrap_output(&mut out).unwrap();
        w.write_all(body.as_bytes()).unwrap();
        w.finish().unwrap();
        fs::write(dir.join(format!("{name}{ENTRY_SUFFIX}")), out).unwrap();
    }

    #[test]
    fn opens_entries_and_rejects_wrong_passphrase() {
        let dir = std::env::temp_dir().join(format!("aegis-kleyknox-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let body = "kleyknox-gpg-v1\nfingerprint abcd\nkeygrip 1234\npassphrase s3cret\n\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
        write_entry(&dir, "mail", body, "master passphrase");

        let entries = open_all(&dir, "master passphrase").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "mail");
        assert_eq!(entries[0].fingerprint, "ABCD");
        assert_eq!(entries[0].passphrase.as_str(), "s3cret");
        assert!(entries[0].secret_armor.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        assert!(matches!(open_all(&dir, "wrong one"), Err(GpgError::WrongPassphrase)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_malformed_bundle() {
        assert!(parse("x".into(), "not a bundle\n\narmor").is_err());
        assert!(parse("x".into(), "kleyknox-gpg-v1\npassphrase p\n\narmor").is_err());
    }
}

/// End-to-end check against a vault made by the real `kleyknox` tool:
/// `KLEYKNOX_TEST_DIR=… KLEYKNOX_TEST_PASS=… cargo test --lib -- --ignored kleyknox_vault`
#[cfg(test)]
mod interop {
    use super::*;
    use crate::gpg::keys;

    #[test]
    #[ignore]
    fn kleyknox_vault() {
        let dir = PathBuf::from(std::env::var("KLEYKNOX_TEST_DIR").expect("KLEYKNOX_TEST_DIR"));
        let pass = std::env::var("KLEYKNOX_TEST_PASS").expect("KLEYKNOX_TEST_PASS");
        let wrong = open_all(&dir, "not the passphrase");
        assert!(matches!(wrong, Err(GpgError::WrongPassphrase)), "{:?}", wrong.err());
        let entries = open_all(&dir, &pass).unwrap();
        assert!(!entries.is_empty());
        for e in entries {
            let certs = keys::parse(e.secret_armor.as_bytes()).unwrap();
            let cert = certs.iter().find(|c| c.fingerprint().to_hex() == e.fingerprint).unwrap();
            assert!(cert.is_tsk(), "{}: no secret key material", e.name);
            keys::check_passphrase(cert, &e.passphrase).unwrap();
            assert!(matches!(keys::check_passphrase(cert, "wrong"), Err(GpgError::WrongPassphrase)));
        }
    }
}

