//! QR code sharing of public keys: fingerprint URI, full armored key, or a
//! keyserver link. Rendering is done here so SVG and PNG are pixel-identical.

use std::io::Cursor;

use image::{ImageBuffer, ImageFormat, Luma};
use openpgp::armor;
use openpgp::cert::Cert;
use openpgp::serialize::Serialize as _;
use qrcode::{Color, EcLevel, QrCode, Version};
use serde::Deserialize;
use sequoia_openpgp as openpgp;

use super::{GpgError, Result};

/// Beyond this a phone has trouble reading a QR code from a screen
/// (roughly QR version 26+), so we refuse instead of producing a dense code.
const MAX_KEY_BYTES: usize = 1200;
/// Up to this size Medium error correction still keeps the code coarse enough.
const MEDIUM_KEY_BYTES: usize = 600;
const QUIET_ZONE: usize = 4;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Fingerprint,
    Key,
    Url,
}

pub struct Qr {
    pub payload: String,
    pub code: QrCode,
    pub ec: &'static str,
}

impl Qr {
    pub fn version(&self) -> u8 {
        match self.code.version() {
            Version::Normal(v) => v as u8,
            Version::Micro(v) => v as u8,
        }
    }
}

pub fn build(cert: &Cert, mode: Mode) -> Result<Qr> {
    let fp = cert.fingerprint().to_hex();
    let (payload, level) = match mode {
        Mode::Fingerprint => (format!("openpgp4fpr:{fp}"), EcLevel::M),
        Mode::Url => (format!("https://keys.openpgp.org/vks/v1/by-fingerprint/{fp}"), EcLevel::M),
        Mode::Key => {
            let armored = armored_public(cert)?;
            if armored.len() > MAX_KEY_BYTES {
                return Err(GpgError::QrTooLarge);
            }
            let level = if armored.len() <= MEDIUM_KEY_BYTES { EcLevel::M } else { EcLevel::L };
            (armored, level)
        }
    };
    let code = QrCode::with_error_correction_level(payload.as_bytes(), level)
        .map_err(|_| GpgError::QrTooLarge)?;
    Ok(Qr {
        payload,
        code,
        ec: if matches!(level, EcLevel::M) { "M" } else { "L" },
    })
}

/// Public key without the per-key "Comment:" headers `Cert::armored` adds,
/// to keep the QR code as small as possible.
fn armored_public(cert: &Cert) -> Result<String> {
    let mut out = Vec::new();
    {
        let mut w = armor::Writer::new(&mut out, armor::Kind::PublicKey)?;
        cert.clone().strip_secret_key_material().serialize(&mut w)?;
        w.finalize()?;
    }
    String::from_utf8(out).map_err(|_| GpgError::Other("Could not armor the key".into()))
}

/// Scalable SVG: black modules on a white background including the quiet zone.
pub fn svg(code: &QrCode) -> String {
    let w = code.width();
    let size = w + 2 * QUIET_ZONE;
    let colors = code.to_colors();
    let mut path = String::new();
    for y in 0..w {
        let mut x = 0;
        while x < w {
            if colors[y * w + x] == Color::Dark {
                let start = x;
                while x < w && colors[y * w + x] == Color::Dark {
                    x += 1;
                }
                path.push_str(&format!("M{} {}h{}v1h-{}z", start + QUIET_ZONE, y + QUIET_ZONE, x - start, x - start));
            } else {
                x += 1;
            }
        }
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges"><rect width="{size}" height="{size}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
    )
}

/// High-resolution PNG (at least ~1000 px wide).
pub fn png(code: &QrCode) -> Result<Vec<u8>> {
    let w = code.width();
    let size = w + 2 * QUIET_ZONE;
    let scale = (1000 / size).max(8);
    let colors = code.to_colors();
    let px = (size * scale) as u32;
    let img = ImageBuffer::<Luma<u8>, _>::from_fn(px, px, |x, y| {
        let (mx, my) = (x as usize / scale, y as usize / scale);
        let dark = mx >= QUIET_ZONE
            && my >= QUIET_ZONE
            && mx < QUIET_ZONE + w
            && my < QUIET_ZONE + w
            && colors[(my - QUIET_ZONE) * w + (mx - QUIET_ZONE)] == Color::Dark;
        Luma([if dark { 0 } else { 255 }])
    });
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| GpgError::Other(e.to_string()))?;
    Ok(out)
}

/// Accepts `openpgp4fpr:<hex>` (case-insensitive, spaces tolerated) and, as a
/// convenience, a bare fingerprint. Returns the upper-case hex fingerprint.
pub fn parse_fingerprint_uri(input: &str) -> Result<String> {
    let t = input.trim();
    let body = match t.get(..12) {
        Some(p) if p.eq_ignore_ascii_case("openpgp4fpr:") => &t[12..],
        _ => t,
    };
    let hex: String = body
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if matches!(hex.len(), 40 | 64) && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err(GpgError::InvalidInput(
            "Not a valid openpgp4fpr: URI or fingerprint (40 hex digits expected)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::{generate, Algorithm, GenerateKeyRequest};

    fn key(alg: Algorithm) -> Cert {
        generate(GenerateKeyRequest {
            name: "Qr Test".into(),
            email: "qr@example.com".into(),
            comment: None,
            passphrase: None,
            algorithm: alg,
            validity_days: None,
        })
        .unwrap()
    }

    #[test]
    fn parses_uris() {
        let fp = "4B40DE2FAE6237F38021E2295C6CD274560D3BB5";
        assert_eq!(parse_fingerprint_uri(&format!("openpgp4fpr:{fp}")).unwrap(), fp);
        assert_eq!(parse_fingerprint_uri(&format!("OpenPGP4FPR:{}", fp.to_lowercase())).unwrap(), fp);
        assert_eq!(parse_fingerprint_uri("4B40 DE2F AE62 37F3 8021  E229 5C6C D274 560D 3BB5").unwrap(), fp);
        assert!(parse_fingerprint_uri("openpgp4fpr:1234").is_err());
        assert!(parse_fingerprint_uri("hello").is_err());
        assert!(parse_fingerprint_uri("é").is_err()); // multi-byte input must not panic
    }

    #[test]
    fn small_key_fits_and_renders() {
        let cert = key(Algorithm::Ed25519);
        let fpqr = build(&cert, Mode::Fingerprint).unwrap();
        assert_eq!(fpqr.payload, format!("openpgp4fpr:{}", cert.fingerprint().to_hex()));
        let keyqr = build(&cert, Mode::Key).unwrap();
        assert!(keyqr.payload.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!keyqr.payload.contains("Comment:"));
        println!("ed25519 armored = {} bytes, QR v{}", keyqr.payload.len(), keyqr.version());
        assert!(svg(&keyqr.code).starts_with("<svg"));
        assert_eq!(&png(&keyqr.code).unwrap()[1..4], b"PNG");
    }

    #[test]
    fn rsa4096_is_rejected_as_too_large() {
        let cert = key(Algorithm::Rsa4096);
        assert!(matches!(build(&cert, Mode::Key), Err(GpgError::QrTooLarge)));
        assert!(build(&cert, Mode::Fingerprint).is_ok());
        assert!(build(&cert, Mode::Url).is_ok());
    }
}
