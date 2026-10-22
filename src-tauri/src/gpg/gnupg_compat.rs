//! Unlocking secret keys exported by GnuPG.
//!
//! GnuPG 2.4 can write a protected secret MPI whose bit count is not minimal
//! (the top bit of the first byte is clear). Sequoia rejects that encoding
//! once the key is decrypted ("Malformed MPI"), so such keys could never be
//! used here. On that error the key is decrypted again by this module, its
//! MPIs rewritten in canonical form, and handed back to Sequoia.

use std::io::Read;

use sequoia_openpgp as openpgp;
use openpgp::crypto::mpi::{self, SecretKeyChecksum};
use openpgp::crypto::symmetric::{BlockCipherMode, Decryptor, UnpaddingMode};
use openpgp::crypto::Password;
use openpgp::packet::key::{Encrypted, KeyRole, SecretKeyMaterial, SecretParts, Unencrypted};
use openpgp::packet::Key;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use super::{GpgError, Result};

/// `Key::decrypt_secret`, tolerant of GnuPG's non-canonical MPIs.
/// Any failure other than that encoding reads as a wrong passphrase.
pub fn decrypt_secret<R: KeyRole>(key: Key<SecretParts, R>, pw: &Password) -> Result<Key<SecretParts, R>> {
    match key.clone().decrypt_secret(pw) {
        Ok(key) => Ok(key),
        Err(e) if is_malformed_mpi(&e) => decrypt_lenient(key, pw),
        Err(_) => Err(GpgError::WrongPassphrase),
    }
}

fn is_malformed_mpi(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<openpgp::Error>(), Some(openpgp::Error::MalformedMPI(_)))
}

/// The pre-RFC 9580 protection GnuPG uses: CFB under an S2K-derived key,
/// MPIs followed by a SHA-1 (or 16-bit sum) checksum.
fn decrypt_lenient<R: KeyRole>(key: Key<SecretParts, R>, pw: &Password) -> Result<Key<SecretParts, R>> {
    let SecretKeyMaterial::Encrypted(enc) = key.secret() else {
        return Ok(key);
    };
    let canonical = decrypt_mpis(enc, pw)?;
    let mpis = mpi::SecretKeyMaterial::from_bytes(key.pk_algo(), &canonical)?;
    let (public, _) = key.take_secret();
    let (key, _) = public.add_secret(SecretKeyMaterial::Unencrypted(Unencrypted::from(mpis)));
    Ok(key)
}

/// Decrypts the protected MPIs, checks their checksum and canonicalizes them.
fn decrypt_mpis(enc: &Encrypted, pw: &Password) -> Result<Zeroizing<Vec<u8>>> {
    if enc.aead_algo().is_some() {
        return Err(GpgError::WrongPassphrase);
    }
    let checksum = enc.checksum().ok_or(GpgError::WrongPassphrase)?;
    let algo = enc.algo();
    let derived = enc.s2k().derive_key(pw, algo.key_size()?)?;
    let ciphertext = enc.ciphertext()?;
    let block = algo.block_size()?;
    if ciphertext.len() <= block {
        return Err(GpgError::Corrupted);
    }

    // The first block is the IV, encrypted under an all-zero IV.
    let source = buffered_reader::Memory::with_cookie(ciphertext, Default::default());
    let mut dec = Decryptor::new(algo, BlockCipherMode::CFB, UnpaddingMode::None, &derived, None, source)?;
    let mut iv = Zeroizing::new(vec![0u8; block]);
    dec.read_exact(&mut iv)?;
    let mut plain = Zeroizing::new(vec![0u8; ciphertext.len() - block]);
    dec.read_exact(&mut plain)?;

    let sum_len = match checksum {
        SecretKeyChecksum::SHA1 => 20,
        SecretKeyChecksum::Sum16 => 2,
    };
    if plain.len() < sum_len {
        return Err(GpgError::WrongPassphrase);
    }
    let (body, sum) = plain.split_at(plain.len() - sum_len);
    let valid = match checksum {
        SecretKeyChecksum::SHA1 => Sha1::digest(body).as_slice() == sum,
        SecretKeyChecksum::Sum16 => {
            let total = body.iter().fold(0u16, |acc, b| acc.wrapping_add(*b as u16));
            total.to_be_bytes() == sum
        }
    };
    if !valid {
        return Err(GpgError::WrongPassphrase);
    }

    canonical_mpis(body).ok_or(GpgError::Corrupted)
}

/// Rewrites a run of MPIs with leading zero bits dropped and the bit count
/// recomputed, as RFC 9580 section 3.2 requires.
fn canonical_mpis(mut data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    while !data.is_empty() {
        let bits = u16::from_be_bytes([*data.first()?, *data.get(1)?]) as usize;
        let len = bits.div_ceil(8);
        let value = data.get(2..2 + len)?;
        data = &data[2 + len..];

        let value = &value[value.iter().take_while(|b| **b == 0).count()..];
        let bits = match value.first() {
            Some(first) => (value.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
            None => 0,
        };
        out.extend_from_slice(&(bits as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_bit_counts_and_leading_zeros() {
        // 256 bits declared for a value whose top bit is clear, then a
        // leading zero byte, then an already canonical MPI.
        let input = [0x01, 0x00, 0x40, 0xAA, 0x00, 0x10, 0x00, 0x7F, 0x00, 0x08, 0xFF];
        let out = canonical_mpis(&input[..4]).is_none();
        assert!(out, "truncated input is rejected");

        let mut long = vec![0x01, 0x00];
        long.extend([0x40; 32]);
        let canon = canonical_mpis(&long).unwrap();
        assert_eq!(&canon[..2], &255u16.to_be_bytes());
        assert_eq!(canon.len(), 34);

        let canon = canonical_mpis(&input[4..]).unwrap();
        assert_eq!(&canon[..], &[0x00, 0x07, 0x7F, 0x00, 0x08, 0xFF]);
    }
}

#[cfg(test)]
mod gnupg_export {
    use super::*;
    use crate::gpg::keys;

    /// Exported by GnuPG 2.4.9 (`gpg --export-secret-keys`), passphrase
    /// "abc123456789": both its Ed25519 and Cv25519 secrets carry a
    /// non-canonical MPI that plain Sequoia refuses.
    const KEY: &str = include_str!("testdata/gnupg24-protected.asc");

    #[test]
    fn unlocks_keys_sequoia_alone_rejects() {
        let cert = keys::parse(KEY.as_bytes()).unwrap().remove(0);
        let pw = Password::from("abc123456789");
        let mut rescued = 0;
        for ka in cert.keys().secret() {
            if ka.key().clone().decrypt_secret(&pw).is_err() {
                rescued += 1;
            }
            let key = decrypt_secret(ka.key().clone(), &pw).unwrap();
            assert!(!key.secret().is_encrypted());
            key.into_keypair().unwrap();
        }
        assert!(rescued > 0, "fixture no longer exercises the fallback");
        assert!(matches!(
            decrypt_secret(cert.primary_key().key().clone().parts_into_secret().unwrap(), &Password::from("wrong")),
            Err(GpgError::WrongPassphrase)
        ));
        keys::check_passphrase(&cert, "abc123456789").unwrap();
    }

    /// The recovered secrets must be the real ones: decrypt a message GnuPG
    /// encrypted to the Cv25519 subkey (`--rfc4880`, ZLIB-compressed as GnuPG
    /// does by default), and sign with the Ed25519 primary.
    #[test]
    fn recovered_keys_decrypt_and_sign() {
        use crate::gpg::crypto::{self, SignatureStatus};
        let cert = keys::parse(KEY.as_bytes()).unwrap().remove(0);
        let message = include_bytes!("testdata/gnupg24-message.asc");

        let mut plain = Vec::new();
        crypto::decrypt(&message[..], &mut plain, vec![cert.clone()], Some("abc123456789"), Default::default())
            .unwrap();
        assert_eq!(plain, b"messaggio cifrato da GnuPG");

        let signed = crypto::sign_cleartext(b"ciao", &cert, Some("abc123456789")).unwrap();
        let (_, verdicts) = crypto::verify_cleartext(&signed, vec![cert]).unwrap();
        assert!(matches!(verdicts.as_slice(), [SignatureStatus::Valid { .. }]), "{verdicts:?}");
    }
}


