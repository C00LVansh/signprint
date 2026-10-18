//! Handing out challenges and turning a correct attestation into a session.
//!
//! ```text
//! GET  challenge  -> { cid, ephemeral_public, program }       (stateless, cid is sealed)
//! POST attest     -> body {cid, client_public, probe, ...}
//!                    header signprint-attest: base64(HMAC(k, "signprint/1 attest\n" || body))
//!                 <- { token, expires_at }
//! ```
//!
//! `k` is the ECDH secret between the client's key and the challenge's
//! ephemeral key. The client derives it as a non-extractable WebCrypto key,
//! so a valid attest MAC also proves it holds the private key behind
//! `client_public`. The same `k` becomes the session's request-signing key.

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use signprint_wire::bind::{self, tags_equal};
use signprint_wire::challenge::{CanvasParams, Challenge, Pow};
use signprint_wire::keys::KeyRing;
use signprint_wire::token::{Flags, SessionToken};
use signprint_wire::{b64, sig};

use crate::network::Network;
use crate::probe::{self, Program};
use crate::store::Store;

pub const ATTEST_DOMAIN: &[u8] = b"signprint/1 attest\n";
pub const MAX_ATTEST_BODY: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct IssuerConfig {
    pub challenge_ttl_secs: u32,
    pub session_ttl_secs: u32,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: 60,
            session_ttl_secs: 600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub cid: String,
    /// Where the probe program registers itself on `self.__signprint`.
    pub probe_key: String,
    /// Uncompressed SEC1 point, the format WebCrypto's "raw" import expects.
    pub ephemeral_public: [u8; 65],
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub token: String,
    pub expires_at: u64,
    pub band: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestError {
    Malformed,
    /// Challenge expired; the client should fetch a new one.
    Expired,
    /// Bad challenge, bad MAC, reused challenge or wrong probe answer. One code
    /// for all of them, so the endpoint doesn't help anyone probe it.
    Rejected,
    Busy,
}

impl AttestError {
    pub fn code(self) -> &'static str {
        match self {
            AttestError::Malformed => "sp_malformed",
            AttestError::Expired => "sp_expired",
            AttestError::Rejected => "sp_attest",
            AttestError::Busy => "sp_busy",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            AttestError::Malformed => 400,
            AttestError::Busy => 503,
            _ => 401,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AttestBody {
    cid: String,
    client_public: String,
    probe: std::collections::HashMap<String, u64>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

fn new_ephemeral() -> SecretKey {
    loop {
        // a random 32-byte string is a valid scalar except with negligible
        // probability; just try again in that case
        if let Ok(k) = SecretKey::from_slice(&random::<32>()) {
            return k;
        }
    }
}

pub struct Issuer {
    ring: KeyRing,
    cfg: IssuerConfig,
}

impl Issuer {
    pub fn new(ring: KeyRing, cfg: IssuerConfig) -> Self {
        Self { ring, cfg }
    }

    fn net_tags(&self, net: &Network) -> (bind::Tag, Option<bind::Tag>) {
        let key = &self.ring.current().bind;
        let net_tag = bind::tag(key, "net", &bind::ip_prefix(net.peer_ip));
        let ja4 = net
            .ja4n
            .as_deref()
            .map(|j| bind::tag(key, "ja4n", j.as_bytes()));
        (net_tag, ja4)
    }

    pub fn challenge(&self, net: &Network, now: u64) -> Offer {
        let eph = new_ephemeral();
        let (bind_net, bind_ja4) = self.net_tags(net);
        let expires_at = now as u32 + self.cfg.challenge_ttl_secs;
        let c = Challenge {
            id: random(),
            issued_at: now as u32,
            expires_at,
            ephemeral_secret: eph.to_bytes().into(),
            bind_net,
            bind_ja4: bind_ja4.unwrap_or([0; 8]),
            // canvas and pow aren't wired up yet
            canvas: CanvasParams {
                known_seed: 0,
                calibration_seeds: vec![],
                rounds: 0,
                size: 0,
            },
            probe_seed: u64::from_be_bytes(random()),
            probe_subset: 0,
            pow: Pow::None,
            pack_set_hash: [0; 8],
        };
        let point = eph.public_key().to_sec1_point(false);
        Offer {
            probe_key: probe::registry_key(&c.id),
            cid: c.seal(&self.ring, random()),
            ephemeral_public: point
                .as_bytes()
                .try_into()
                .expect("uncompressed P-256 point is 65 bytes"),
            expires_at: expires_at as u64,
        }
    }

    fn open(&self, cid: &str, now: u64) -> Result<Challenge, AttestError> {
        let c = Challenge::open(&self.ring, cid).map_err(|_| AttestError::Rejected)?;
        if now >= c.expires_at as u64 {
            return Err(AttestError::Expired);
        }
        Ok(c)
    }

    /// The probe program for `/c/<cid>.js`.
    pub fn program(&self, cid: &str, now: u64) -> Result<Program, AttestError> {
        let c = self.open(cid, now)?;
        Ok(probe::generate(c.probe_seed, &c.id))
    }

    pub fn attest<S: Store>(
        &self,
        store: &S,
        body: &[u8],
        mac: Option<&str>,
        net: &Network,
        now: u64,
    ) -> Result<Issued, AttestError> {
        if body.len() > MAX_ATTEST_BODY {
            return Err(AttestError::Malformed);
        }
        let req: AttestBody = serde_json::from_slice(body).map_err(|_| AttestError::Malformed)?;
        let mac = mac.ok_or(AttestError::Rejected)?;
        let challenge = self.open(&req.cid, now)?;

        // The attestation has to come from the same TLS client that asked for
        // the challenge.
        if challenge.bind_ja4 != [0; 8] {
            let (_, ja4) = self.net_tags(net);
            if !ja4.is_some_and(|t| tags_equal(&t, &challenge.bind_ja4)) {
                return Err(AttestError::Rejected);
            }
        }

        let client_raw = b64::decode_url(&req.client_public).map_err(|_| AttestError::Malformed)?;
        if client_raw.len() != 65 {
            return Err(AttestError::Malformed);
        }
        let client = PublicKey::from_sec1_bytes(&client_raw).map_err(|_| AttestError::Malformed)?;
        let eph = SecretKey::from_slice(&challenge.ephemeral_secret)
            .map_err(|_| AttestError::Rejected)?;
        let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), client.as_affine());
        let key: [u8; 32] = shared
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .expect("P-256 shared secret is 32 bytes");

        let tag: [u8; 32] = signprint_wire::b64::decode_std(mac)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AttestError::Rejected)?;
        let mut signed = Vec::with_capacity(ATTEST_DOMAIN.len() + body.len());
        signed.extend_from_slice(ATTEST_DOMAIN);
        signed.extend_from_slice(body);
        if !sig::verify_mac_bytes(&key, &signed, &tag) {
            return Err(AttestError::Rejected);
        }

        if !store.spend_challenge(&challenge.id, challenge.expires_at as u64, now) {
            return Err(AttestError::Rejected);
        }

        let program = probe::generate(challenge.probe_seed, &challenge.id);
        if req.probe.get(&program.field) != Some(&(program.answer as u64)) {
            return Err(AttestError::Rejected);
        }

        // Scoring hooks in here once rule packs land; everything that gets
        // this far is band 0 for now.
        let band = 0;

        let (bind_net, bind_ja4) = self.net_tags(net);
        let mut flags = Flags::default();
        if bind_ja4.is_none() {
            flags = flags.with(Flags::NET_ABSENT);
        }
        let expires_at = now as u32 + self.cfg.session_ttl_secs;
        let token = SessionToken {
            sid: random(),
            issued_at: now as u32,
            expires_at,
            epoch: 0,
            mac_key: key,
            client_key_hash: Sha256::digest(&client_raw)[..16]
                .try_into()
                .expect("16 <= 32"),
            bind_ja4: bind_ja4.unwrap_or([0; 8]),
            bind_net,
            fp_digest: [0; 8],
            band,
            flags,
            policy: 0,
        };
        Ok(Issued {
            token: token.seal(&self.ring, random()),
            expires_at: expires_at as u64,
            band,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Provenance;
    use crate::store::MemoryStore;
    use hmac::{Hmac, KeyInit, Mac};

    const NOW: u64 = 1_760_716_800;

    fn issuer() -> Issuer {
        Issuer::new(
            KeyRing::new(1, 1, &[(1, [3; 32])]).unwrap(),
            IssuerConfig::default(),
        )
    }

    fn net() -> Network {
        Network {
            peer_ip: "198.51.100.4".parse().unwrap(),
            ja4n: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            provenance: Provenance::Direct,
        }
    }

    /// Plays the browser: makes a key pair, derives k, answers the probe.
    fn attest_body(offer: &Offer, answer_fix: impl Fn(u32) -> u64) -> (Vec<u8>, String, [u8; 32]) {
        let client = new_ephemeral();
        let eph = PublicKey::from_sec1_bytes(&offer.ephemeral_public).unwrap();
        let k: [u8; 32] = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        let program = issuer().program(&offer.cid, NOW).unwrap();
        let body = serde_json::json!({
            "cid": offer.cid,
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "probe": { program.field: answer_fix(program.answer) },
        })
        .to_string()
        .into_bytes();
        let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        m.update(ATTEST_DOMAIN);
        m.update(&body);
        (body, b64::encode_std(&m.finalize().into_bytes()), k)
    }

    #[test]
    fn full_flow_mints_a_working_token() {
        let i = issuer();
        let store = MemoryStore::default();
        let offer = i.challenge(&net(), NOW);
        let (body, mac, k) = attest_body(&offer, |a| a as u64);
        let issued = i
            .attest(&store, &body, Some(&mac), &net(), NOW + 1)
            .unwrap();

        let token = SessionToken::open(&i.ring, &issued.token).unwrap();
        assert_eq!(token.mac_key, k, "session key is the ECDH secret");
        assert_eq!(token.expires_at as u64, NOW + 1 + 600);
        assert!(!token.flags.has(Flags::NET_ABSENT));
    }

    #[test]
    fn challenge_is_single_use() {
        let i = issuer();
        let store = MemoryStore::default();
        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        assert!(i.attest(&store, &body, Some(&mac), &net(), NOW).is_ok());
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &net(), NOW),
            Err(AttestError::Rejected)
        );
    }

    #[test]
    fn wrong_answer_bad_mac_and_expiry() {
        let i = issuer();
        let store = MemoryStore::default();

        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64 + 1);
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &net(), NOW),
            Err(AttestError::Rejected)
        );

        let offer = i.challenge(&net(), NOW);
        let (body, _, _) = attest_body(&offer, |a| a as u64);
        let forged = b64::encode_std(&[0u8; 32]);
        assert_eq!(
            i.attest(&store, &body, Some(&forged), &net(), NOW),
            Err(AttestError::Rejected)
        );
        assert_eq!(
            i.attest(&store, &body, None, &net(), NOW),
            Err(AttestError::Rejected)
        );

        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &net(), NOW + 60),
            Err(AttestError::Expired)
        );
    }

    #[test]
    fn attest_must_come_from_the_same_tls_client() {
        let i = issuer();
        let store = MemoryStore::default();
        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        let mut other = net();
        other.ja4n = Some("t13d1715h2_5b57614c22b0_3d5424432f57".into());
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &other, NOW),
            Err(AttestError::Rejected)
        );
    }

    #[test]
    fn no_ja4_means_net_absent_session() {
        let i = issuer();
        let store = MemoryStore::default();
        let mut n = net();
        n.ja4n = None;
        let offer = i.challenge(&n, NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        let issued = i.attest(&store, &body, Some(&mac), &n, NOW).unwrap();
        let token = SessionToken::open(&i.ring, &issued.token).unwrap();
        assert!(token.flags.has(Flags::NET_ABSENT));
    }

    #[test]
    fn garbage_is_malformed() {
        let i = issuer();
        let store = MemoryStore::default();
        assert_eq!(
            i.attest(&store, b"not json", Some("x"), &net(), NOW),
            Err(AttestError::Malformed)
        );
        let big = vec![b' '; MAX_ATTEST_BODY + 1];
        assert_eq!(
            i.attest(&store, &big, Some("x"), &net(), NOW),
            Err(AttestError::Malformed)
        );
    }
}
