//! Whole-keyring backup: every certificate (secret parts included) in one
//! file, encrypted with a passphrase chosen for the backup.
//!
//! The passphrase is the only protection for keys that have none of their
//! own, so it must be long enough to matter.

use std::io::{self, Write};

use openpgp::cert::prelude::*;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::{keys, GpgError, Result};

pub const MIN_PASSPHRASE_CHARS: usize = 10;

/// Encrypts `certs` (with their secret keys) into an ASCII-armored message.
pub fn create(certs: &[Cert], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(GpgError::InvalidInput(format!(
            "The backup passphrase must have at least {MIN_PASSPHRASE_CHARS} characters"
        )));
    }
    let mut payload = Zeroizing::new(Vec::new());
    for cert in certs {
        payload.extend_from_slice(&cert.as_tsk().to_vec()?);
    }

    let mut out = Vec::new();
    let message = Armorer::new(Message::new(&mut out)).build()?;
    let message = Encryptor::with_passwords(message, [Password::from(passphrase)]).build()?;
    let mut message = LiteralWriter::new(message).build()?;
    message.write_all(&payload)?;
    message.finalize()?;
    Ok(out)
}

struct PasswordHelper(Password);

impl VerificationHelper for PasswordHelper {
    fn get_certs(&mut self, _: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for PasswordHelper {
    fn decrypt(
        &mut self,
        _: &[PKESK],
        skesks: &[SKESK],
        _: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for skesk in skesks {
            if let Ok((algo, key)) = skesk.decrypt(&self.0) {
                if decrypt(algo, &key) {
                    return Ok(None);
                }
            }
        }
        Err(GpgError::WrongPassphrase.into())
    }
}

/// Decrypts a backup made by [`create`] and returns the certificates in it.
pub fn restore(data: &[u8], passphrase: &str) -> Result<Vec<Cert>> {
    let policy = StandardPolicy::new();
    let helper = PasswordHelper(Password::from(passphrase));
    let mut decryptor = DecryptorBuilder::from_bytes(data)?.with_policy(&policy, None, helper)?;
    let mut payload = Zeroizing::new(Vec::new());
    io::copy(&mut decryptor, &mut *payload).map_err(|_| GpgError::Corrupted)?;
    keys::parse(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::{Algorithm, GenerateKeyRequest};

    fn key(pass: Option<&str>) -> Cert {
        keys::generate(GenerateKeyRequest {
            name: "Test".into(),
            email: "t@example.com".into(),
            comment: None,
            passphrase: pass.map(String::from),
            algorithm: Algorithm::Ed25519,
            validity_days: None,
        })
        .unwrap()
    }

    #[test]
    fn round_trip_keeps_secrets_and_contacts() {
        let plain = key(None);
        let locked = key(Some("own passphrase"));
        let contact = key(None).strip_secret_key_material();
        let data = create(&[plain.clone(), locked.clone(), contact.clone()], "a long backup phrase").unwrap();
        assert!(String::from_utf8_lossy(&data).contains("BEGIN PGP MESSAGE"));

        let back = restore(&data, "a long backup phrase").unwrap();
        assert_eq!(back.len(), 3);
        let find = |c: &Cert| back.iter().find(|b| b.fingerprint() == c.fingerprint()).unwrap();
        assert!(find(&plain).is_tsk());
        assert!(find(&locked).is_tsk());
        assert!(!find(&contact).is_tsk());
    }

    #[test]
    fn wrong_or_short_passphrase_is_rejected() {
        let data = create(&[key(None)], "a long backup phrase").unwrap();
        assert!(matches!(restore(&data, "another phrase!"), Err(GpgError::WrongPassphrase)));
        assert!(matches!(restore(b"not a backup", "a long backup phrase"), Err(_)));
        assert!(matches!(create(&[key(None)], "short"), Err(GpgError::InvalidInput(_))));
    }
}
