//! Certifying (signing) another party's key with one of our own keys.

use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::Packet;
use openpgp::types::SignatureType;
use serde::Deserialize;
use sequoia_openpgp as openpgp;

use super::{GpgError, Result};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// "I have not checked" (generic certification).
    None,
    /// "I did casual checking".
    Casual,
    /// "I did very careful checking" (positive certification).
    Careful,
}

pub fn certify(
    target: &Cert,
    signer: &Cert,
    level: Level,
    user_ids: &[String],
    passphrase: Option<&str>,
) -> Result<Cert> {
    if target.fingerprint() == signer.fingerprint() {
        return Err(GpgError::InvalidInput("You cannot certify your own key".into()));
    }

    let primary = signer
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| GpgError::NoSigningKey)?;
    let primary = if primary.secret().is_encrypted() {
        let pw = passphrase
            .filter(|p| !p.is_empty())
            .map(Password::from)
            .ok_or(GpgError::PassphraseRequired)?;
        primary.decrypt_secret(&pw).map_err(|_| GpgError::WrongPassphrase)?
    } else {
        primary
    };
    let mut keypair = primary.into_keypair()?;

    let sig_type = match level {
        Level::None => SignatureType::GenericCertification,
        Level::Casual => SignatureType::CasualCertification,
        Level::Careful => SignatureType::PositiveCertification,
    };

    let mut packets: Vec<Packet> = Vec::new();
    for ua in target.userids() {
        let text = String::from_utf8_lossy(ua.userid().value()).into_owned();
        if !user_ids.contains(&text) {
            continue;
        }
        let sig = SignatureBuilder::new(sig_type).sign_userid_binding(
            &mut keypair,
            target.primary_key().key(),
            ua.userid(),
        )?;
        packets.push(sig.into());
    }
    if packets.is_empty() {
        return Err(GpgError::InvalidInput("Select at least one user ID to certify".into()));
    }
    Ok(target.clone().insert_packets(packets)?)
}
