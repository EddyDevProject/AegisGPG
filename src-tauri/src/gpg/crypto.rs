//! Streaming encrypt / sign / decrypt / verify.
//!
//! All entry points work on `Read`/`Write`, so files are processed in
//! chunks (never fully buffered) and the same code serves the text tools.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use openpgp::cert::prelude::*;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::stream::*;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Fingerprint, KeyID};
use serde::Serialize;
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::{GpgError, Result};

pub struct EncryptOptions<'a> {
    /// Public certificates of the recipients (may be empty when only signing).
    pub recipients: &'a [Cert],
    /// Certificate holding the secret key to sign with.
    pub signer: Option<&'a Cert>,
    pub passphrase: Option<&'a str>,
    pub armor: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid { fingerprint: String, signer: Option<String> },
    Invalid { fingerprint: Option<String> },
    UnknownSigner { fingerprint: Option<String> },
}

pub fn encrypt<R: Read, W: Write + Send + Sync>(
    mut input: R,
    output: W,
    opts: &EncryptOptions,
) -> Result<()> {
    if opts.recipients.is_empty() && opts.signer.is_none() {
        return Err(GpgError::NothingToDo);
    }
    let policy = StandardPolicy::new();

    let mut message = Message::new(output);
    if opts.armor {
        message = Armorer::new(message).build()?;
    }

    if !opts.recipients.is_empty() {
        let mut keys = Vec::new();
        for cert in opts.recipients {
            let found: Vec<_> = cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .for_storage_encryption()
                .collect();
            if found.is_empty() {
                return Err(GpgError::MissingRecipient(cert.fingerprint().to_hex()));
            }
            keys.extend(found);
        }
        message = Encryptor2::for_recipients(message, keys).build()?;
    }

    if let Some(cert) = opts.signer {
        let keypair = signing_keypair(cert, &policy, opts.passphrase)?;
        message = Signer::new(message, keypair).build()?;
    }

    let mut message = LiteralWriter::new(message).build()?;
    io::copy(&mut input, &mut message)?;
    message.finalize()?;
    Ok(())
}

fn signing_keypair(
    cert: &Cert,
    policy: &dyn Policy,
    passphrase: Option<&str>,
) -> Result<openpgp::crypto::KeyPair> {
    let ka = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .next()
        .ok_or(GpgError::NoSigningKey)?;

    let mut key = ka.key().clone();
    if key.secret().is_encrypted() {
        let pw = passphrase
            .filter(|p| !p.is_empty())
            .map(Password::from)
            .ok_or(GpgError::PassphraseRequired)?;
        key = key.decrypt_secret(&pw).map_err(|_| GpgError::WrongPassphrase)?;
    }
    Ok(key.into_keypair()?)
}

struct Helper {
    /// Every cert in the keyring: used both for decryption and verification.
    certs: Vec<Cert>,
    passphrase: Option<Zeroizing<String>>,
    results: Arc<Mutex<Vec<SignatureStatus>>>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut out = self.results.lock().unwrap();
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    out.push(match r {
                        Ok(good) => {
                            let cert = good.ka.cert();
                            let signer = cert
                                .userids()
                                .next()
                                .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned());
                            SignatureStatus::Valid {
                                fingerprint: cert.fingerprint().to_hex(),
                                signer,
                            }
                        }
                        Err(VerificationError::MissingKey { sig }) => {
                            SignatureStatus::UnknownSigner {
                                fingerprint: sig.get_issuers().first().map(|h| h.to_hex()),
                            }
                        }
                        Err(VerificationError::BadKey { sig, .. })
                        | Err(VerificationError::BadSignature { sig, .. })
                        | Err(VerificationError::MalformedSignature { sig, .. })
                        | Err(VerificationError::UnboundKey { sig, .. }) => {
                            SignatureStatus::Invalid {
                                fingerprint: sig.get_issuers().first().map(|h| h.to_hex()),
                            }
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let policy = StandardPolicy::new();
        let mut needs_passphrase = false;
        let mut wrong_passphrase = false;

        for pkesk in pkesks {
            let wanted: &KeyID = pkesk.recipient();
            for cert in &self.certs {
                for ka in cert
                    .keys()
                    .with_policy(&policy, None)
                    .secret()
                    .for_transport_encryption()
                    .for_storage_encryption()
                {
                    if !wanted.is_wildcard() && *wanted != ka.key().keyid() {
                        continue;
                    }
                    let mut key = ka.key().clone();
                    if key.secret().is_encrypted() {
                        let Some(pw) = &self.passphrase else {
                            needs_passphrase = true;
                            continue;
                        };
                        match key.decrypt_secret(&Password::from(pw.as_str())) {
                            Ok(k) => key = k,
                            Err(_) => {
                                wrong_passphrase = true;
                                continue;
                            }
                        }
                    }
                    let mut pair = key.into_keypair()?;
                    if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym_algo) {
                        if decrypt(algo, &sk) {
                            return Ok(Some(ka.cert().fingerprint()));
                        }
                    }
                }
            }
        }

        Err(if wrong_passphrase {
            GpgError::WrongPassphrase
        } else if needs_passphrase {
            GpgError::PassphraseRequired
        } else {
            GpgError::NoSecretKey
        }
        .into())
    }
}

/// Decrypts `input` into `output` and returns the signature verdicts.
/// Signatures are checked as the stream is consumed; callers should discard
/// the output if this returns `Err`.
pub fn decrypt<R: Read + Send + Sync, W: Write>(
    input: R,
    mut output: W,
    certs: Vec<Cert>,
    passphrase: Option<&str>,
) -> Result<Vec<SignatureStatus>> {
    let policy = StandardPolicy::new();
    let results = Arc::new(Mutex::new(Vec::new()));
    let helper = Helper {
        certs,
        passphrase: passphrase.filter(|p| !p.is_empty()).map(|p| Zeroizing::new(p.to_string())),
        results: results.clone(),
    };

    let mut decryptor = DecryptorBuilder::from_reader(input)?.with_policy(&policy, None, helper)?;
    io::copy(&mut decryptor, &mut output).map_err(|e| {
        // Sequoia reports parse/integrity failures as io::Error wrapping its
        // own error types; genuine I/O failures (disk full...) have no payload.
        let wrapped = e
            .get_ref()
            .map(|inner| inner.is::<openpgp::Error>())
            .unwrap_or(false);
        if wrapped || e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::InvalidData {
            GpgError::Corrupted
        } else {
            GpgError::Io(e)
        }
    })?;
    output.flush()?;

    let out = results.lock().unwrap().clone();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::{self, Algorithm, GenerateKeyRequest};
    use std::io::Cursor;

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
    fn roundtrip_sign_and_verify() {
        let k = key(Some("hunter2"));
        let public = k.clone().strip_secret_key_material();
        let mut ct = Vec::new();
        encrypt(
            Cursor::new(b"hello world".to_vec()),
            &mut ct,
            &EncryptOptions { recipients: &[public], signer: Some(&k), passphrase: Some("hunter2"), armor: true },
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&ct).contains("BEGIN PGP MESSAGE"));

        // No passphrase -> typed error; wrong -> typed error; right -> ok.
        let mut sink = Vec::new();
        let e = decrypt(Cursor::new(ct.clone()), &mut sink, vec![k.clone()], None).unwrap_err();
        assert!(matches!(e, GpgError::PassphraseRequired), "{e:?}");
        let e = decrypt(Cursor::new(ct.clone()), &mut sink, vec![k.clone()], Some("nope")).unwrap_err();
        assert!(matches!(e, GpgError::WrongPassphrase), "{e:?}");

        let mut pt = Vec::new();
        let sigs = decrypt(Cursor::new(ct), &mut pt, vec![k], Some("hunter2")).unwrap();
        assert_eq!(pt, b"hello world");
        assert!(matches!(sigs[..], [SignatureStatus::Valid { .. }]), "{sigs:?}");
    }

    #[test]
    fn unknown_signer_and_missing_secret() {
        let signer = key(None);
        let other = key(None);
        let mut ct = Vec::new();
        encrypt(
            Cursor::new(b"x".to_vec()),
            &mut ct,
            &EncryptOptions { recipients: &[other.clone()], signer: Some(&signer), passphrase: None, armor: false },
        )
        .unwrap();
        let mut pt = Vec::new();
        let sigs = decrypt(Cursor::new(ct.clone()), &mut pt, vec![other], None).unwrap();
        assert!(matches!(sigs[..], [SignatureStatus::UnknownSigner { .. }]), "{sigs:?}");

        let e = decrypt(Cursor::new(ct), &mut Vec::new(), vec![signer], None).unwrap_err();
        assert!(matches!(e, GpgError::NoSecretKey), "{e:?}");
    }
}
