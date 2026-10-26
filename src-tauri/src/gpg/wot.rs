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

    /// Order of confidence, for picking the best-validated identity.
    pub fn rank(self) -> u8 {
        match self {
            Trust::None => 0,
            Trust::Unknown => 1,
            Trust::Marginal => 2,
            Trust::Full => 3,
            Trust::Ultimate => 4,
        }
    }
}

/// A verified certification: `signer` vouches that `userid` belongs to `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub signer: String,
    pub target: String,
    pub userid: String,
}

/// Lossy text of a user ID, the same form `KeyInfo.user_ids` uses.
pub fn userid_text(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

/// Verified certifications, one per (signer, target, user ID).
/// Only signatures whose issuer is in `certs` can be checked and are returned.
pub fn certifications(certs: &[Cert]) -> Vec<Edge> {
    let by_fp: HashMap<String, &Cert> =
        certs.iter().map(|c| (c.fingerprint().to_hex(), c)).collect();
    let by_id: HashMap<String, String> = certs
        .iter()
        .map(|c| (c.keyid().to_hex(), c.fingerprint().to_hex()))
        .collect();

    let mut out = Vec::new();
    for cert in certs {
        let target = cert.fingerprint().to_hex();
        for ua in cert.userids() {
            let userid = userid_text(ua.userid().value());
            let mut seen = HashSet::new();
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
                        out.push(Edge { signer: signer_fp, target: target.clone(), userid: userid.clone() });
                    }
                }
            }
        }
    }
    out
}

/// Validity through the web of trust, for each key and for each of its user IDs.
pub struct Levels {
    /// Best validity among a key's user IDs: what it is worth as an introducer.
    pub key: HashMap<String, Trust>,
    /// Fingerprint → user ID → validity. A certification vouches for the user
    /// ID it signed only, so an identity added later stays unvalidated.
    pub uid: HashMap<String, HashMap<String, Trust>>,
}

/// Computes the validity of every user ID. `owner` maps fingerprint → ownertrust.
pub fn levels(certs: &[Cert], owner: &HashMap<String, Trust>, edges: &[Edge]) -> Levels {
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
    let mut by_uid: HashMap<(&String, &String), Vec<&Edge>> = HashMap::new();
    for e in edges {
        by_uid.entry((&e.target, &e.userid)).or_default().push(e);
    }

    let mut valid: HashMap<String, HashMap<String, Trust>> = certs
        .iter()
        .map(|c| {
            let fp = c.fingerprint().to_hex();
            let root = trust_of(&fp) == Trust::Ultimate && !revoked.contains(&fp);
            let uids = c
                .userids()
                .map(|u| (userid_text(u.userid().value()), if root { Trust::Ultimate } else { Trust::Unknown }))
                .collect();
            (fp, uids)
        })
        .collect();
    let best = |uids: &HashMap<String, Trust>| {
        uids.values().copied().max_by_key(|t| t.rank()).unwrap_or_default()
    };

    for _ in 0..5 {
        let prev = valid.clone();
        for (fp, uids) in valid.iter_mut() {
            if revoked.contains(fp) {
                continue;
            }
            for (uid, v) in uids.iter_mut() {
                if *v == Trust::Ultimate {
                    continue;
                }
                let (mut full, mut marginal) = (0, 0);
                for e in by_uid.get(&(fp, uid)).into_iter().flatten() {
                    if revoked.contains(&e.signer) {
                        continue;
                    }
                    if !prev.get(&e.signer).map(best).unwrap_or_default().counts_full() {
                        continue;
                    }
                    match trust_of(&e.signer) {
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
        }
        if prev == valid {
            break;
        }
    }
    let key = valid.iter().map(|(fp, uids)| (fp.clone(), best(uids))).collect();
    Levels { key, uid: valid }
}

/// Key-level validity only (see [`Levels::key`]).
pub fn validity(certs: &[Cert], owner: &HashMap<String, Trust>, edges: &[Edge]) -> HashMap<String, Trust> {
    levels(certs, owner, edges).key
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
    edges: &[Edge],
    valid: &HashMap<String, Trust>,
) -> Graph {
    let policy = StandardPolicy::new();
    let nodes = certs
        .iter()
        .map(|c| {
            let fp = c.fingerprint().to_hex();
            let first = c.userids().next();
            let email = first.as_ref().and_then(|u| u.userid().email().ok().flatten().map(|s| s.to_string()));
            let name = first.as_ref().and_then(|u| u.userid().name().ok().flatten().map(|s| s.to_string()));
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

    // One arrow per pair of keys, however many user IDs the signer certified.
    let pairs: Vec<(&String, &String)> = edges
        .iter()
        .map(|e| (&e.signer, &e.target))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let edges = pairs
        .into_iter()
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
        let has = |s: &Cert, t: &Cert| edges.iter().any(|e| e.signer == fp(s) && e.target == fp(t));
        assert!(has(&me, &bob));
        assert!(has(&bob, &carol));
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
    fn an_added_user_id_is_not_validated() {
        use crate::gpg::keys;
        use openpgp::packet::{signature::SignatureBuilder, UserID};
        use openpgp::types::SignatureType;
        use openpgp::Packet;

        let (me, bob) = (key("Me"), key("Bob"));
        let real = uids(&bob);
        // Bob adds an identity nobody certified; Me certifies only the real one.
        let mut signer = bob.primary_key().key().clone().parts_into_secret().unwrap().into_keypair().unwrap();
        let fake = UserID::from("Boss <boss@example.com>");
        let binding = fake
            .bind(&mut signer, &bob, SignatureBuilder::new(SignatureType::PositiveCertification))
            .unwrap();
        let bob2 = bob.clone().insert_packets(vec![Packet::from(fake), Packet::from(binding)]).unwrap().0;
        assert_eq!(uids(&bob2).len(), 2);
        let certified = certify(&public(&bob2), &me, Level::Careful, &real, None).unwrap();

        let certs = vec![me.clone(), certified.clone()];
        let bob_fp = bob.fingerprint().to_hex();
        let mut owner: HashMap<String, Trust> = certs.iter().map(|c| (c.fingerprint().to_hex(), Trust::Unknown)).collect();
        owner.insert(me.fingerprint().to_hex(), Trust::Ultimate);
        let lv = levels(&certs, &owner, &certifications(&certs));

        assert_eq!(lv.uid[&bob_fp][&real[0]], Trust::Full);
        assert_eq!(lv.uid[&bob_fp]["Boss <boss@example.com>"], Trust::Unknown);
        assert_eq!(lv.key[&bob_fp], Trust::Full, "still a usable introducer through its real identity");

        // Presented under the identity that earned the validity, never the other one.
        let info = keys::info(&certified, Trust::Unknown, &lv.uid[&bob_fp]);
        assert_eq!(info.email.as_deref(), Some("bob@example.com"));
        assert_eq!(info.validity, Trust::Full);
        let boss = info.identities.iter().find(|i| i.user_id.starts_with("Boss")).unwrap();
        assert_eq!(boss.validity, Trust::Unknown);
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
        let forged = public(&mallory).insert_packets(sig_packets).unwrap().0;
        assert!(certifications(&[me, forged]).is_empty());
    }
}
