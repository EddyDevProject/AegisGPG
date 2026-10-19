//! Revoking one of our own keys.

use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::types::ReasonForRevocation;
use serde::Deserialize;
use sequoia_openpgp as openpgp;

use super::{GpgError, Result};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    /// The secret key was lost, stolen or exposed.
    Compromised,
    /// Replaced by a newer key.
    Superseded,
    /// No longer used, nothing is wrong with it.
    Retired,
    Unspecified,
}

impl From<Reason> for ReasonForRevocation {
    fn from(r: Reason) -> Self {
        match r {
            Reason::Compromised => ReasonForRevocation::KeyCompromised,
            Reason::Superseded => ReasonForRevocation::KeySuperseded,
            Reason::Retired => ReasonForRevocation::KeyRetired,
            Reason::Unspecified => ReasonForRevocation::Unspecified,
        }
    }
}

/// Returns `cert` with a revocation signature added. Needs the secret part of
/// the primary key (and its passphrase, if it has one).
pub fn revoke(cert: &Cert, reason: Reason, message: &str, passphrase: Option<&str>) -> Result<Cert> {
    let primary = cert
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
    let mut signer = primary.into_keypair()?;

    let sig = CertRevocationBuilder::new()
        .set_reason_for_revocation(reason.into(), message.trim().as_bytes())?
        .build(&mut signer, cert, None)?;
    Ok(cert.clone().insert_packets(sig)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::{self, Algorithm, GenerateKeyRequest};
    use openpgp::policy::StandardPolicy;
    use openpgp::types::RevocationStatus;

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

    fn is_revoked(c: &Cert) -> bool {
        !matches!(c.revocation_status(&StandardPolicy::new(), None), RevocationStatus::NotAsFarAsWeKnow)
    }

    #[test]
    fn revokes_with_and_without_passphrase() {
        let plain = key(None);
        assert!(!is_revoked(&plain));
        assert!(is_revoked(&revoke(&plain, Reason::Retired, "", None).unwrap()));

        let locked = key(Some("hunter2"));
        let e = revoke(&locked, Reason::Compromised, "lost laptop", None).unwrap_err();
        assert!(matches!(e, GpgError::PassphraseRequired), "{e:?}");
        let e = revoke(&locked, Reason::Compromised, "", Some("nope")).unwrap_err();
        assert!(matches!(e, GpgError::WrongPassphrase), "{e:?}");
        let done = revoke(&locked, Reason::Compromised, "lost laptop", Some("hunter2")).unwrap();
        assert!(is_revoked(&done));
        // The revocation survives being exported without secrets and merged back.
        let public = done.strip_secret_key_material();
        assert!(is_revoked(&locked.merge_public_and_secret(public).unwrap()));
    }

    #[test]
    fn public_only_key_cannot_be_revoked() {
        let public = key(None).strip_secret_key_material();
        assert!(matches!(revoke(&public, Reason::Retired, "", None), Err(GpgError::NoSigningKey)));
    }
}
