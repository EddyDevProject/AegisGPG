//! Web of Trust: ownertrust levels, verified certification extraction, and a
//! simplified GnuPG-style validity calculation.
//!
//! Validity rule (simplified, "classic" trust model with GnuPG defaults):
//! a key is *fully* valid if it carries a verified certification from one
//! valid signer whose ownertrust is Full/Ultimate, or from three valid signers
//! with Marginal ownertrust; *marginally* valid with at least one marginal
//! signer. Keys with ownertrust Ultimate are roots. Path depth is limited to 5.
//! Revocations of individual certifications are not evaluated.

use std::collections::{HashMap, HashSet};

use openpgp::cert::prelude::*;
use openpgp::policy::StandardPolicy;
use serde::{Deserialize, Serialize};
use sequoia_openpgp as openpgp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    #[default]
    Unknown,
    None,
    Marginal,
    Full,
    Ultimate,
}

impl Trust {
    fn counts_full(self) -> bool {
        matches!(self, Trust::Full | Trust::Ultimate)
    }
}

/// Verified certifications as `(signer_fingerprint, target_fingerprint)`.
/// Only signatures whose issuer is in `certs` can be checked and are returned.
pub fn certifications(certs: &[Cert]) -> Vec<(String, String)> {
    let by_fp: HashMap<String, &Cert> =
        certs.iter().map(|c| (c.fingerprint().to_hex(), c)).collect();
    let by_id: HashMap<String, String> = certs
        .iter()
        .map(|c| (c.keyid().to_hex(), c.fingerprint().to_hex()))
        .collect();

    let mut out = Vec::new();
    for cert in certs {
        let target = cert.fingerprint().to_hex();
        let mut seen = HashSet::new();
        for ua in cert.userids() {
            for sig in ua.certifications() {
                for issuer in sig.get_issuers() {
                    let h = issuer.to_hex();
                    let signer_fp = if by_fp.contains_key(&h) {
                        h
                    } else if let Some(fp) = by_id.get(&h) {
                        fp.clone()
                    } else {
                        continue;
                    };
                    if signer_fp == target || seen.contains(&signer_fp) {
                        continue;
                    }
                    let signer = by_fp[&signer_fp];
                    let sig = sig.clone();
                    if sig
                        .verify_userid_binding(
                            signer.primary_key().key(),
                            cert.primary_key().key(),
                            ua.userid(),
                        )
                        .is_ok()
                    {
                        seen.insert(signer_fp.clone());
                        out.push((signer_fp, target.clone()));
                    }
                }
            }
        }
    }
    out
}

/// Computes the validity of every key. `owner` maps fingerprint → ownertrust.
pub fn validity(
    certs: &[Cert],
    owner: &HashMap<String, Trust>,
    edges: &[(String, String)],
) -> HashMap<String, Trust> {
    let policy = StandardPolicy::new();
    let revoked: HashSet<String> = certs
        .iter()
        .filter(|c| {
            !matches!(
                c.revocation_status(&policy, None),
                openpgp::types::RevocationStatus::NotAsFarAsWeKnow
            )
        })
        .map(|c| c.fingerprint().to_hex())
        .collect();

    let trust_of = |fp: &String| owner.get(fp).copied().unwrap_or_default();
    let mut valid: HashMap<String, Trust> = certs
        .iter()
        .map(|c| c.fingerprint().to_hex())
        .map(|fp| {
            let v = if trust_of(&fp) == Trust::Ultimate && !revoked.contains(&fp) {
                Trust::Ultimate
            } else {
                Trust::Unknown
            };
            (fp, v)
        })
        .collect();

    for _ in 0..5 {
        let prev = valid.clone();
        for (fp, v) in valid.iter_mut() {
            if *v == Trust::Ultimate || revoked.contains(fp) {
                continue;
            }
            let (mut full, mut marginal) = (0, 0);
            for (signer, target) in edges {
                if target != fp || revoked.contains(signer) {
                    continue;
                }
                if !prev.get(signer).copied().unwrap_or_default().counts_full() {
                    continue;
                }
                match trust_of(signer) {
                    t if t.counts_full() => full += 1,
                    Trust::Marginal => marginal += 1,
                    _ => {}
                }
            }
            *v = if full >= 1 || marginal >= 3 {
                Trust::Full
            } else if marginal >= 1 {
                Trust::Marginal
            } else {
                Trust::Unknown
            };
        }
        if prev == valid {
            break;
        }
    }
    valid
}

#[derive(Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub email: Option<String>,
    pub ownertrust: Trust,
    pub validity: Trust,
    pub is_own: bool,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    /// How much this certification contributes: full / marginal / none.
    pub weight: &'static str,
}

#[derive(Serialize)]
pub struct Graph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

pub fn graph(
    certs: &[Cert],
    owner: &HashMap<String, Trust>,
    edges: &[(String, String)],
    valid: &HashMap<String, Trust>,
) -> Graph {
    let policy = StandardPolicy::new();
    let nodes = certs
        .iter()
        .map(|c| {
            let fp = c.fingerprint().to_hex();
            let first = c.userids().next();
            let email = first.as_ref().and_then(|u| u.userid().email2().ok().flatten().map(|s| s.to_string()));
            let name = first.as_ref().and_then(|u| u.userid().name2().ok().flatten().map(|s| s.to_string()));
            GraphNode {
                label: name.or_else(|| email.clone()).unwrap_or_else(|| fp[fp.len() - 8..].to_string()),
                email,
                ownertrust: owner.get(&fp).copied().unwrap_or_default(),
                validity: valid.get(&fp).copied().unwrap_or_default(),
                is_own: c.is_tsk(),
                revoked: !matches!(
                    c.revocation_status(&policy, None),
                    openpgp::types::RevocationStatus::NotAsFarAsWeKnow
                ),
                id: fp,
            }
        })
        .collect();

    let edges = edges
        .iter()
        .map(|(from, to)| {
            let signer_valid = valid.get(from).copied().unwrap_or_default().counts_full();
            let weight = match (signer_valid, owner.get(from).copied().unwrap_or_default()) {
                (true, t) if t.counts_full() => "full",
                (true, Trust::Marginal) => "marginal",
                _ => "none",
            };
            GraphEdge { from: from.clone(), to: to.clone(), weight }
        })
        .collect();

    Graph { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::certify::{certify, Level};
    use crate::gpg::keys::{generate, Algorithm, GenerateKeyRequest};

    fn key(name: &str) -> Cert {
        generate(GenerateKeyRequest {
            name: name.into(),
            email: format!("{}@example.com", name.to_lowercase()),
            comment: None,
            passphrase: None,
            algorithm: Algorithm::Ed25519,
            validity_days: None,
        })
        .unwrap()
    }
    fn uids(c: &Cert) -> Vec<String> {
        c.userids().map(|u| String::from_utf8_lossy(u.userid().value()).into_owned()).collect()
    }
    fn public(c: &Cert) -> Cert {
        c.clone().strip_secret_key_material()
    }

    #[test]
    fn certifications_and_trust_propagation() {
        let (me, bob, carol) = (key("Me"), key("Bob"), key("Carol"));
        // Me certifies Bob; Bob (a secret key here only to sign) certifies Carol.
        let bob_c = certify(&public(&bob), &me, Level::Careful, &uids(&bob), None).unwrap();
        let carol_c = certify(&public(&carol), &bob, Level::Casual, &uids(&carol), None).unwrap();
        let certs = vec![me.clone(), bob_c, carol_c];

        let edges = certifications(&certs);
        let fp = |c: &Cert| c.fingerprint().to_hex();
        assert!(edges.contains(&(fp(&me), fp(&bob))));
        assert!(edges.contains(&(fp(&bob), fp(&carol))));
        assert_eq!(edges.len(), 2);

        // Own key is Ultimate by default; nobody else trusted yet.
        let mut owner: HashMap<String, Trust> = certs.iter().map(|c| (fp(c), Trust::Unknown)).collect();
        owner.insert(fp(&me), Trust::Ultimate);
        let v = validity(&certs, &owner, &edges);
        assert_eq!(v[&fp(&bob)], Trust::Full);
        assert_eq!(v[&fp(&carol)], Trust::Unknown, "Bob has no ownertrust yet");

        // Trusting Bob fully makes Carol valid; marginal only gives marginal.
        owner.insert(fp(&bob), Trust::Full);
        assert_eq!(validity(&certs, &owner, &edges)[&fp(&carol)], Trust::Full);
        owner.insert(fp(&bob), Trust::Marginal);
        assert_eq!(validity(&certs, &owner, &edges)[&fp(&carol)], Trust::Marginal);
    }

    #[test]
    fn forged_certification_is_ignored() {
        let (me, bob) = (key("Me"), key("Bob"));
        let signed = certify(&public(&bob), &me, Level::Careful, &uids(&bob), None).unwrap();
        // Move the signature onto a different key: it must not verify.
        let mallory = key("Mallory");
        let sig_packets: Vec<_> = signed
            .userids()
            .flat_map(|u| u.certifications().cloned().collect::<Vec<_>>())
            .collect();
        let forged = public(&mallory).insert_packets(sig_packets).unwrap();
        assert!(certifications(&[me, forged]).is_empty());
    }
}
