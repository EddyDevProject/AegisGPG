//! Key generation, inspection, import and export.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use serde::{Deserialize, Serialize};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::wot::Trust;
use super::{GpgError, Result};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Ed25519,
    Rsa4096,
}

#[derive(Deserialize)]
pub struct GenerateKeyRequest {
    pub name: String,
    pub email: String,
    pub comment: Option<String>,
    pub passphrase: Option<String>,
    pub algorithm: Algorithm,
    pub validity_days: Option<u64>,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub email: Option<String>,
    pub ownertrust: Trust,
    pub validity: Trust,
    pub user_ids: Vec<String>,
    pub algorithm: String,
    pub created: u64,
    pub expires: Option<u64>,
    pub has_secret: bool,
    pub secret_encrypted: bool,
    pub revoked: bool,
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn generate(req: GenerateKeyRequest) -> Result<Cert> {
    let name = req.name.trim();
    let email = req.email.trim();
    if name.is_empty() || !email.contains('@') {
        return Err(GpgError::InvalidInput("A name and a valid email are required".into()));
    }
    let uid = match req.comment.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => format!("{name} ({c}) <{email}>"),
        None => format!("{name} <{email}>"),
    };

    let suite = match req.algorithm {
        Algorithm::Ed25519 => CipherSuite::Cv25519,
        Algorithm::Rsa4096 => CipherSuite::RSA4k,
    };

    let mut builder = CertBuilder::new()
        .set_cipher_suite(suite)
        .add_userid(uid)
        // Like GnuPG's default layout: the primary key certifies *and* signs,
        // plus one encryption subkey. Fewer packets = smaller key (QR-friendly).
        .set_primary_key_flags(openpgp::types::KeyFlags::empty().set_certification().set_signing())
        .add_subkey(
            openpgp::types::KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None,
        );

    match req.validity_days {
        Some(days) if days > 0 => {
            builder = builder.set_validity_period(Duration::from_secs(days * 86_400));
        }
        _ => builder = builder.set_validity_period(None),
    }

    let passphrase = req.passphrase.filter(|p| !p.is_empty()).map(Zeroizing::new);
    if let Some(p) = &passphrase {
        builder = builder.set_password(Some(Password::from(p.as_str())));
    }

    let (cert, _revocation) = builder.generate()?;
    Ok(cert)
}

pub fn info(cert: &Cert, ownertrust: Trust, validity: Trust) -> KeyInfo {
    let policy = StandardPolicy::new();
    let primary = cert.primary_key().key();

    let user_ids: Vec<String> = cert
        .userids()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .collect();
    let first = cert.userids().next();
    let name = first.as_ref().and_then(|u| u.userid().name2().ok().flatten().map(|s| s.to_string()));
    let comment = first.as_ref().and_then(|u| u.userid().comment2().ok().flatten().map(|s| s.to_string()));
    let email = first.as_ref().and_then(|u| u.userid().email2().ok().flatten().map(|s| s.to_string()));

    let valid = cert.with_policy(&policy, None).ok();
    let expires = valid
        .as_ref()
        .and_then(|v| v.primary_key().key_expiration_time())
        .map(unix);
    let revoked = !matches!(
        cert.revocation_status(&policy, None),
        openpgp::types::RevocationStatus::NotAsFarAsWeKnow
    );

    let secret_encrypted = cert
        .keys()
        .secret()
        .any(|k| k.key().secret().is_encrypted());

    KeyInfo {
        fingerprint: cert.fingerprint().to_hex(),
        key_id: cert.keyid().to_hex(),
        name,
        comment,
        email,
        ownertrust,
        validity,
        user_ids,
        algorithm: primary.pk_algo().to_string(),
        created: unix(primary.creation_time()),
        expires,
        has_secret: cert.is_tsk(),
        secret_encrypted,
        revoked,
    }
}

/// Parse one or more certificates from armored or binary data.
pub fn parse(data: &[u8]) -> Result<Vec<Cert>> {
    let certs = CertParser::from_bytes(data)
        .map_err(|_| GpgError::Corrupted)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| GpgError::Corrupted)?;
    if certs.is_empty() {
        return Err(GpgError::InvalidInput("No OpenPGP key found in the input".into()));
    }
    Ok(certs)
}

/// Armored export. For secret export the stored (passphrase-protected)
/// material is emitted unchanged, after verifying the passphrase if set.
pub fn export(cert: &Cert, secret: bool, passphrase: Option<&str>) -> Result<Vec<u8>> {
    if !secret {
        return Ok(cert.clone().strip_secret_key_material().armored().to_vec()?);
    }
    if !cert.is_tsk() {
        return Err(GpgError::NoSigningKey);
    }
    for ka in cert.keys().secret() {
        if ka.key().secret().is_encrypted() {
            let pw = passphrase
                .filter(|p| !p.is_empty())
                .map(|p| Password::from(p))
                .ok_or(GpgError::PassphraseRequired)?;
            ka.key()
                .clone()
                .decrypt_secret(&pw)
                .map_err(|_| GpgError::WrongPassphrase)?;
            break;
        }
    }
    Ok(cert.as_tsk().armored().to_vec()?)
}

#[derive(Serialize)]
pub struct SubkeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub algorithm: String,
    /// Subset of: certify, sign, encrypt, authenticate
    pub purposes: Vec<&'static str>,
    pub created: u64,
    pub expires: Option<u64>,
    pub is_primary: bool,
    pub revoked: bool,
}

/// The primary key followed by all subkeys, with their capabilities.
pub fn subkeys(cert: &Cert) -> Vec<SubkeyInfo> {
    use std::collections::HashMap;
    let policy = StandardPolicy::new();

    struct Meta {
        purposes: Vec<&'static str>,
        expires: Option<u64>,
        revoked: bool,
    }
    let mut meta: HashMap<String, Meta> = HashMap::new();
    if let Ok(valid) = cert.with_policy(&policy, None) {
        for ka in valid.keys() {
            let mut purposes = Vec::new();
            if let Some(f) = ka.key_flags() {
                if f.for_certification() { purposes.push("certify"); }
                if f.for_signing() { purposes.push("sign"); }
                if f.for_transport_encryption() || f.for_storage_encryption() { purposes.push("encrypt"); }
                if f.for_authentication() { purposes.push("authenticate"); }
            }
            meta.insert(
                ka.key().fingerprint().to_hex(),
                Meta {
                    purposes,
                    expires: ka.key_expiration_time().map(unix),
                    revoked: !matches!(
                        ka.revocation_status(),
                        openpgp::types::RevocationStatus::NotAsFarAsWeKnow
                    ),
                },
            );
        }
    }

    let primary = cert.fingerprint();
    cert.keys()
        .map(|ka| {
            let key = ka.key();
            let fp = key.fingerprint();
            let m = meta.remove(&fp.to_hex());
            SubkeyInfo {
                key_id: key.keyid().to_hex(),
                algorithm: key.pk_algo().to_string(),
                created: unix(key.creation_time()),
                is_primary: fp == primary,
                purposes: m.as_ref().map(|m| m.purposes.clone()).unwrap_or_default(),
                expires: m.as_ref().and_then(|m| m.expires),
                revoked: m.as_ref().is_some_and(|m| m.revoked),
                fingerprint: fp.to_hex(),
            }
        })
        .collect()
}
