//! Streaming encrypt / sign / decrypt / verify.
//!
//! All entry points work on `Read`/`Write`, so files are processed in
//! chunks (never fully buffered) and the same code serves the text tools.

use std::collections::HashMap;
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
        message = Encryptor::for_recipients(message, keys).build()?;
    }

    if let Some(cert) = opts.signer {
        let keypair = signing_keypair(cert, &policy, opts.passphrase)?;
        message = Signer::new(message, keypair)?.build()?;
    }

    let mut message = LiteralWriter::new(message).build()?;
    io::copy(&mut input, &mut message)?;
    message.finalize()?;
    Ok(())
}

/// Signs `text` as a cleartext message (readable as is, with the signature below it).
pub fn sign_cleartext(text: &[u8], signer: &Cert, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let keypair = signing_keypair(signer, &policy, passphrase)?;
    let mut out = Vec::new();
    let mut message = Signer::new(Message::new(&mut out), keypair)?.cleartext().build()?;
    message.write_all(text)?;
    message.finalize()?;
    Ok(out)
}

/// Checks a cleartext-signed message and returns its text with the verdicts.
pub fn verify_cleartext(input: &[u8], certs: Vec<Cert>) -> Result<(Vec<u8>, Vec<SignatureStatus>)> {
    let policy = StandardPolicy::new();
    let results = Arc::new(Mutex::new(Vec::new()));
    let helper = Helper {
        certs,
        passphrase: None,
        cached: HashMap::new(),
        unlocked: Arc::new(Mutex::new(None)),
        results: results.clone(),
    };
    let mut verifier = VerifierBuilder::from_bytes(input)?.with_policy(&policy, None, helper)?;
    let mut text = Vec::new();
    io::copy(&mut verifier, &mut text).map_err(|_| GpgError::Corrupted)?;
    let out = results.lock().unwrap().clone();
    Ok((text, out))
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

/// A key that was unlocked with the passphrase the caller supplied (not a cached one).
pub struct Unlocked {
    pub fingerprint: String,
    pub passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked").field("fingerprint", &self.fingerprint).finish_non_exhaustive()
    }
}

struct Helper {
    /// Every cert in the keyring: used both for decryption and verification.
    certs: Vec<Cert>,
    passphrase: Option<Zeroizing<String>>,
    /// Remembered passphrases by cert fingerprint, tried when none was supplied.
    cached: HashMap<String, Zeroizing<String>>,
    unlocked: Arc<Mutex<Option<Unlocked>>>,
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
                        // The enum is non-exhaustive: an unknown failure is never "valid".
                        Err(_) => SignatureStatus::Invalid { fingerprint: None },
                    });
                }
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        let policy = StandardPolicy::new();
        let mut needs_passphrase = false;
        let mut wrong_passphrase = false;

        for pkesk in pkesks {
            // `None` is a wildcard recipient: try every key.
            let wanted = pkesk.recipient();
            for cert in &self.certs {
                for ka in cert
                    .keys()
                    .with_policy(&policy, None)
                    .secret()
                    .for_transport_encryption()
                    .for_storage_encryption()
                {
                    if let Some(w) = &wanted {
                        if !w.aliases(&ka.key().key_handle()) {
                            continue;
                        }
                    }
                    let mut key = ka.key().clone();
                    let mut typed: Option<Unlocked> = None;
                    if key.secret().is_encrypted() {
                        let cert_fp = cert.fingerprint().to_hex();
                        let (pw, from_cache) = match (&self.passphrase, self.cached.get(&cert_fp)) {
                            (Some(p), _) => (p, false),
                            (None, Some(p)) => (p, true),
                            (None, None) => {
                                needs_passphrase = true;
                                continue;
                            }
                        };
                        match key.decrypt_secret(&Password::from(pw.as_str())) {
                            Ok(k) => key = k,
                            Err(_) => {
                                // A stale cached passphrase is just "ask again".
                                if from_cache {
                                    needs_passphrase = true;
                                } else {
                                    wrong_passphrase = true;
                                }
                                continue;
                            }
                        }
                        if !from_cache {
                            typed = Some(Unlocked { fingerprint: cert_fp, passphrase: pw.clone() });
                        }
                    }
                    let mut pair = key.into_keypair()?;
                    if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym_algo) {
                        if decrypt(algo, &sk) {
                            *self.unlocked.lock().unwrap() = typed;
                            return Ok(Some(cert.clone()));
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
/// the output if this returns `Err`. Also returns the key unlocked by
/// `passphrase`, if any, so the caller can remember it.
pub fn decrypt<R: Read + Send + Sync, W: Write>(
    input: R,
    mut output: W,
    certs: Vec<Cert>,
    passphrase: Option<&str>,
    cached: HashMap<String, Zeroizing<String>>,
) -> Result<(Vec<SignatureStatus>, Option<Unlocked>)> {
    let policy = StandardPolicy::new();
    let results = Arc::new(Mutex::new(Vec::new()));
    let unlocked = Arc::new(Mutex::new(None));
    let helper = Helper {
        certs,
        passphrase: passphrase.filter(|p| !p.is_empty()).map(|p| Zeroizing::new(p.to_string())),
        cached,
        unlocked: unlocked.clone(),
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
    let unlocked = unlocked.lock().unwrap().take();
    Ok((out, unlocked))
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
        let e = decrypt(Cursor::new(ct.clone()), &mut sink, vec![k.clone()], None, HashMap::new()).unwrap_err();
        assert!(matches!(e, GpgError::PassphraseRequired), "{e:?}");
        let e = decrypt(Cursor::new(ct.clone()), &mut sink, vec![k.clone()], Some("nope"), HashMap::new()).unwrap_err();
        assert!(matches!(e, GpgError::WrongPassphrase), "{e:?}");

        let mut pt = Vec::new();
        let (sigs, unlocked) = decrypt(Cursor::new(ct.clone()), &mut pt, vec![k.clone()], Some("hunter2"), HashMap::new()).unwrap();
        assert_eq!(pt, b"hello world");
        let unlocked = unlocked.expect("typed passphrase is reported");
        assert_eq!(unlocked.fingerprint, k.fingerprint().to_hex());
        assert_eq!(unlocked.passphrase.as_str(), "hunter2");

        // A cached passphrase unlocks without being reported again; a stale one asks again.
        let cache = HashMap::from([(k.fingerprint().to_hex(), Zeroizing::new("hunter2".to_string()))]);
        let mut pt2 = Vec::new();
        let (_, again) = decrypt(Cursor::new(ct.clone()), &mut pt2, vec![k.clone()], None, cache).unwrap();
        assert_eq!(pt2, b"hello world");
        assert!(again.is_none());
        let stale = HashMap::from([(k.fingerprint().to_hex(), Zeroizing::new("old".to_string()))]);
        let e = decrypt(Cursor::new(ct), &mut Vec::new(), vec![k], None, stale).unwrap_err();
        assert!(matches!(e, GpgError::PassphraseRequired), "{e:?}");
        assert!(matches!(sigs[..], [SignatureStatus::Valid { .. }]), "{sigs:?}");
    }

    #[test]
    fn cleartext_sign_and_verify() {
        let k = key(Some("hunter2"));
        let public = k.clone().strip_secret_key_material();
        let e = sign_cleartext(b"hello\n", &k, None).unwrap_err();
        assert!(matches!(e, GpgError::PassphraseRequired), "{e:?}");
        let signed = sign_cleartext(b"hello\n", &k, Some("hunter2")).unwrap();
        let armored = String::from_utf8_lossy(&signed).into_owned();
        assert!(armored.contains("BEGIN PGP SIGNED MESSAGE") && armored.contains("hello"));

        let (text, sigs) = verify_cleartext(&signed, vec![public.clone()]).unwrap();
        assert_eq!(String::from_utf8_lossy(&text).trim(), "hello");
        assert!(matches!(sigs[..], [SignatureStatus::Valid { .. }]), "{sigs:?}");

        // Tampering with the text must not verify.
        let forged = armored.replace("hello", "HELLO");
        let (_, sigs) = verify_cleartext(forged.as_bytes(), vec![public]).unwrap_or_default();
        assert!(!matches!(sigs[..], [SignatureStatus::Valid { .. }]), "{sigs:?}");

        // Unknown signer.
        let (_, sigs) = verify_cleartext(&signed, vec![]).unwrap();
        assert!(matches!(sigs[..], [SignatureStatus::UnknownSigner { .. }]), "{sigs:?}");
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
        let (sigs, _) = decrypt(Cursor::new(ct.clone()), &mut pt, vec![other], None, HashMap::new()).unwrap();
        assert!(matches!(sigs[..], [SignatureStatus::UnknownSigner { .. }]), "{sigs:?}");

        let e = decrypt(Cursor::new(ct), &mut Vec::new(), vec![signer], None, HashMap::new()).unwrap_err();
        assert!(matches!(e, GpgError::NoSecretKey), "{e:?}");
    }
}
