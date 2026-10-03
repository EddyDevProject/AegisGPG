//! Remote key discovery: WKD and keyservers (VKS for keys.openpgp.org, HKP
//! for keyserver.ubuntu.com). Every request is async, HTTPS-only, size-capped
//! and bounded by connect/total timeouts so the UI never hangs.
//!
//! Everything downloaded is untrusted: secret key material is stripped and
//! callers must check that the key matches what was asked for.

use std::time::Duration;

use openpgp::cert::prelude::*;
use openpgp::serialize::SerializeInto;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sequoia_openpgp as openpgp;
use sha1::{Digest, Sha1};

use super::{keys, GpgError, Result};

const MAX_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Server {
    KeysOpenpgpOrg,
    KeyserverUbuntuCom,
}

impl Server {
    fn base(self) -> &'static str {
        match self {
            Server::KeysOpenpgpOrg => "https://keys.openpgp.org",
            Server::KeyserverUbuntuCom => "https://keyserver.ubuntu.com",
        }
    }
}

fn client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(concat!("AegisGPG/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| GpgError::Network(e.to_string()))
}

fn net_err(e: reqwest::Error) -> GpgError {
    GpgError::Network(if e.is_timeout() {
        "The server did not respond in time".into()
    } else if e.is_connect() {
        "Could not reach the server. Check your internet connection".into()
    } else {
        "Network request failed".into()
    })
}

fn require_https(url: &Url) -> Result<()> {
    if url.scheme() == "https" {
        Ok(())
    } else {
        Err(GpgError::InvalidInput("Only HTTPS endpoints are allowed".into()))
    }
}

/// GET returning `None` on 404. The body is capped at `MAX_BYTES`.
async fn get(url: Url) -> Result<Option<Vec<u8>>> {
    require_https(&url)?;
    let mut resp = client()?.get(url).send().await.map_err(net_err)?;
    match resp.status() {
        StatusCode::NOT_FOUND => return Ok(None),
        s if !s.is_success() => {
            return Err(GpgError::Network(format!("The server answered with an error ({s})")))
        }
        _ => {}
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(net_err)? {
        if body.len() + chunk.len() > MAX_BYTES {
            return Err(GpgError::Network("The server response is too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

// ------------------------------------------------------------------ WKD ----

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

fn zbase32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn split_email(email: &str) -> Result<(&str, String)> {
    let email = email.trim();
    let (local, domain) = email
        .rsplit_once('@')
        .filter(|(l, d)| !l.is_empty() && !d.is_empty())
        .ok_or_else(|| GpgError::InvalidInput("Enter a valid email address".into()))?;
    let domain = domain.to_ascii_lowercase();
    if !domain.contains('.')
        || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(GpgError::InvalidInput("Unsupported email domain".into()));
    }
    Ok((local, domain))
}

/// Advanced method first (`openpgpkey.<domain>`), then the direct method.
fn wkd_urls(email: &str) -> Result<Vec<Url>> {
    let (local, domain) = split_email(email)?;
    let hash = zbase32(&Sha1::digest(local.to_lowercase().as_bytes()));
    let build = |s: String| -> Result<Url> {
        let mut u = Url::parse(&s).map_err(|_| GpgError::InvalidInput("Invalid email address".into()))?;
        u.query_pairs_mut().append_pair("l", local);
        Ok(u)
    };
    Ok(vec![
        build(format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}"))?,
        build(format!("https://{domain}/.well-known/openpgpkey/hu/{hash}"))?,
    ])
}

fn has_email(cert: &Cert, email: &str) -> bool {
    cert.userids().any(|u| {
        u.userid()
            .email2()
            .ok()
            .flatten()
            .is_some_and(|e| e.eq_ignore_ascii_case(email.trim()))
    })
}

fn parse_remote(data: &[u8]) -> Result<Vec<Cert>> {
    Ok(keys::parse(data)?
        .into_iter()
        .map(|c| c.strip_secret_key_material())
        .collect())
}

pub async fn wkd(email: &str) -> Result<Vec<Cert>> {
    let mut last_err = None;
    for url in wkd_urls(email)? {
        match get(url).await {
            Ok(Some(data)) => {
                // The key must actually carry the requested address.
                let certs: Vec<_> = parse_remote(&data)?
                    .into_iter()
                    .filter(|c| has_email(c, email))
                    .collect();
                if !certs.is_empty() {
                    return Ok(certs);
                }
            }
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Err(GpgError::NotFound(email.trim().to_string())),
    }
}

// ------------------------------------------------------------ keyservers ----

enum Query {
    Email(String),
    Hex(String), // 8, 16 or 40 hex digits, upper-case
}

fn parse_query(q: &str) -> Result<Query> {
    let q = q.trim();
    if q.contains('@') {
        return Ok(Query::Email(q.to_string()));
    }
    let hex: String = q
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if matches!(hex.len(), 8 | 16 | 40) && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(Query::Hex(hex))
    } else {
        Err(GpgError::InvalidInput("Enter an email address or a key fingerprint / ID".into()))
    }
}

fn matches_query(cert: &Cert, q: &Query) -> bool {
    match q {
        Query::Email(e) => has_email(cert, e),
        Query::Hex(h) => cert.fingerprint().to_hex().ends_with(h.as_str()),
    }
}

fn server_url(server: Server, segments: &[&str]) -> Result<Url> {
    let mut u = Url::parse(server.base()).expect("static url");
    u.path_segments_mut().expect("base url").extend(segments);
    Ok(u)
}

pub async fn search(server: Server, query: &str) -> Result<Vec<Cert>> {
    let q = parse_query(query)?;
    let url = match (server, &q) {
        (Server::KeysOpenpgpOrg, Query::Email(e)) => server_url(server, &["vks", "v1", "by-email", e])?,
        (Server::KeysOpenpgpOrg, Query::Hex(h)) if h.len() == 40 => {
            server_url(server, &["vks", "v1", "by-fingerprint", h])?
        }
        (Server::KeysOpenpgpOrg, Query::Hex(h)) if h.len() == 16 => {
            server_url(server, &["vks", "v1", "by-keyid", h])?
        }
        (Server::KeysOpenpgpOrg, Query::Hex(_)) => {
            return Err(GpgError::InvalidInput(
                "keys.openpgp.org needs a full fingerprint or a 16-digit key ID".into(),
            ))
        }
        (Server::KeyserverUbuntuCom, q) => {
            let mut u = server_url(server, &["pks", "lookup"])?;
            let search = match q {
                Query::Email(e) => e.clone(),
                Query::Hex(h) => format!("0x{h}"),
            };
            u.query_pairs_mut()
                .append_pair("op", "get")
                .append_pair("options", "mr")
                .append_pair("search", &search);
            u
        }
    };

    let data = get(url).await?.ok_or_else(|| GpgError::NotFound(query.trim().to_string()))?;
    let certs: Vec<_> = parse_remote(&data)?
        .into_iter()
        .filter(|c| matches_query(c, &q))
        .collect();
    if certs.is_empty() {
        return Err(GpgError::NotFound(query.trim().to_string()));
    }
    Ok(certs)
}

/// Fetch the current copy of a key we already hold. `None` = not on server.
pub async fn fetch_by_fingerprint(server: Server, fingerprint: &str) -> Result<Option<Cert>> {
    match search(server, fingerprint).await {
        Ok(certs) => Ok(certs
            .into_iter()
            .find(|c| c.fingerprint().to_hex().eq_ignore_ascii_case(fingerprint))),
        Err(GpgError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Serialize)]
pub struct EmailStatus {
    pub email: String,
    /// published | pending | unpublished | revoked
    pub status: String,
}

#[derive(Serialize)]
pub struct UploadReport {
    pub fingerprint: String,
    pub emails: Vec<EmailStatus>,
    pub verification_requested: bool,
}

/// Publishes the *public* part of `cert`.
pub async fn upload(server: Server, cert: &Cert) -> Result<UploadReport> {
    let armored = String::from_utf8(cert.clone().strip_secret_key_material().armored().to_vec()?)
        .map_err(|_| GpgError::Other("Could not armor the key".into()))?;
    let fingerprint = cert.fingerprint().to_hex();
    let client = client()?;

    match server {
        Server::KeyserverUbuntuCom => {
            let url = server_url(server, &["pks", "add"])?;
            let resp = client
                .post(url)
                .form(&[("keytext", armored.as_str())])
                .send()
                .await
                .map_err(net_err)?;
            if !resp.status().is_success() {
                return Err(GpgError::Network(format!("The server rejected the key ({})", resp.status())));
            }
            Ok(UploadReport {
                fingerprint,
                emails: Vec::new(),
                verification_requested: false,
            })
        }
        Server::KeysOpenpgpOrg => {
            let resp = client
                .post(server_url(server, &["vks", "v1", "upload"])?)
                .json(&json!({ "keytext": armored }))
                .send()
                .await
                .map_err(net_err)?;
            if !resp.status().is_success() {
                return Err(GpgError::Network(format!("The server rejected the key ({})", resp.status())));
            }
            let body: Value = resp.json().await.map_err(net_err)?;
            let token = body["token"].as_str().unwrap_or_default().to_string();
            let mut emails: Vec<EmailStatus> = body["status"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| EmailStatus {
                            email: k.clone(),
                            status: v.as_str().unwrap_or("unpublished").to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Ask the server to send verification mails for unpublished addresses.
            let todo: Vec<String> = emails
                .iter()
                .filter(|e| e.status == "unpublished")
                .map(|e| e.email.clone())
                .collect();
            let mut requested = false;
            if !todo.is_empty() && !token.is_empty() {
                let r = client
                    .post(server_url(server, &["vks", "v1", "request-verify"])?)
                    .json(&json!({ "token": token, "addresses": todo }))
                    .send()
                    .await
                    .map_err(net_err)?;
                if r.status().is_success() {
                    requested = true;
                    for e in emails.iter_mut().filter(|e| todo.contains(&e.email)) {
                        e.status = "pending".into();
                    }
                } else if r.status() == StatusCode::TOO_MANY_REQUESTS {
                    return Err(GpgError::Network(
                        "Too many verification requests: try again in a few minutes".into(),
                    ));
                }
            }
            Ok(UploadReport { fingerprint, emails, verification_requested: requested })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zbase32_matches_wkd_spec_example() {
        // From draft-koch-openpgp-webkey-service: "Joe.Doe" -> iy9q119eutrkn8s1mk4r39qejnbu3n5q
        let h = zbase32(&Sha1::digest(b"joe.doe"));
        assert_eq!(h, "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    #[test]
    fn wkd_urls_shape() {
        let urls = wkd_urls("Joe.Doe@Example.ORG").unwrap();
        assert_eq!(
            urls[0].as_str(),
            "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
        );
        assert!(urls[1].as_str().starts_with("https://example.org/.well-known/openpgpkey/hu/"));
        assert!(wkd_urls("not-an-email").is_err());
        assert!(wkd_urls("a@b/evil.com").is_err());
    }
}
