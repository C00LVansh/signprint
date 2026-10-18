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
use signprint_rules::{RuleSet, Signals, Value};
use signprint_wire::bind::{self, tags_equal};
use signprint_wire::challenge::{CanvasParams, Challenge, Pow};
use signprint_wire::keys::KeyRing;
use signprint_wire::token::{Flags, SessionToken};
use signprint_wire::{b64, sig};

use crate::network::Network;
use crate::probe::{self, Program};
use crate::store::Store;
use crate::verify::Verified;

pub const ATTEST_DOMAIN: &[u8] = b"signprint/1 attest\n";
pub const MAX_ATTEST_BODY: usize = 16 * 1024;
/// Prefixes the client may report. `http.*` and `net.*` come from the proxy.
const CLIENT_PREFIXES: [&str; 2] = ["js.", "worker."];

/// Signals sealed (as a keyed digest) into the token at attest time and
/// re-checked on every refresh. They shouldn't change during a session; if
/// they do, the session gets re-challenged.
pub const FINGERPRINT_KEYS: [&str; 6] = [
    "js.engine",
    "js.ua",
    "js.platform",
    "js.hw_concurrency",
    "js.languages_len",
    "js.webgl_renderer",
];
const MAX_SIGNALS: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct IssuerConfig {
    pub challenge_ttl_secs: u32,
    pub session_ttl_secs: u32,
    /// Hard cap on a session's life across refreshes.
    pub absolute_ttl_secs: u32,
    /// Score upper bounds for bands 0, 1 and 2; anything above is band 3.
    pub bands: [i32; 3],
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: 60,
            session_ttl_secs: 600,
            absolute_ttl_secs: 3600,
            bands: [0, 30, 70],
        }
    }
}

impl IssuerConfig {
    pub fn band(&self, score: i32) -> u8 {
        self.bands.iter().position(|max| score <= *max).unwrap_or(3) as u8
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
    pub score: i32,
    /// Ids of the rules that fired, for logging.
    pub hits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refreshed {
    pub token: String,
    /// New server key; the client derives the next session key from it with
    /// the same client private key.
    pub ephemeral_public: [u8; 65],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestError {
    Malformed,
    /// Challenge expired; the client should fetch a new one.
    Expired,
    /// Bad challenge, bad MAC, reused challenge or wrong probe answer. One code
    /// for all of them, so the endpoint doesn't help anyone probe it.
    Rejected,
    /// The fingerprint changed mid-session, or the session hit its absolute
    /// age; run a fresh challenge.
    Reattest,
    Busy,
}

impl AttestError {
    pub fn code(self) -> &'static str {
        match self {
            AttestError::Malformed => "sp_malformed",
            AttestError::Expired => "sp_expired",
            AttestError::Rejected => "sp_attest",
            AttestError::Reattest => "sp_reattest",
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
struct RefreshBody {
    client_public: String,
    #[serde(default)]
    fp: serde_json::Map<String, serde_json::Value>,
}

fn fp_canonical(signals: &Signals) -> Vec<u8> {
    let mut out = Vec::new();
    for k in FINGERPRINT_KEYS {
        let v = match signals.get(k) {
            None | Some(Value::Null) => "null".to_owned(),
            Some(Value::Bool(b)) => b.to_string(),
            Some(Value::Num(n)) => n.to_string(),
            Some(Value::Str(s)) => serde_json::to_string(s).expect("strings serialize"),
            Some(Value::List(_)) => "list".to_owned(),
        };
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    out
}

fn fp_from_json(m: &serde_json::Map<String, serde_json::Value>) -> Signals {
    FINGERPRINT_KEYS
        .iter()
        .filter_map(|k| m.get(*k).map(|v| (k.to_string(), Value::from(v))))
        .collect()
}

#[derive(Debug, Deserialize)]
struct AttestBody {
    cid: String,
    client_public: String,
    probe: std::collections::HashMap<String, u64>,
    #[serde(default)]
    signals: serde_json::Map<String, serde_json::Value>,
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
    rules: RuleSet,
    /// Client-side signals the loaded rules read; everything else is dropped.
    wanted: Vec<String>,
}

impl Issuer {
    pub fn new(ring: KeyRing, cfg: IssuerConfig, rules: RuleSet) -> Self {
        let mut wanted: Vec<String> = rules
            .signals()
            .into_iter()
            .filter(|s| CLIENT_PREFIXES.iter().any(|p| s.starts_with(p)))
            .collect();
        for k in FINGERPRINT_KEYS {
            if !wanted.iter().any(|w| w == k) {
                wanted.push(k.to_owned());
            }
        }
        Self {
            ring,
            cfg,
            rules,
            wanted,
        }
    }

    /// Signals the client should collect (sent with the challenge).
    pub fn wanted_signals(&self) -> &[String] {
        &self.wanted
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

    /// `server_signals` are what the proxy observed itself (`http.*`, `net.*`).
    /// They override anything the client sent under the same name.
    #[allow(clippy::too_many_arguments)]
    pub fn attest<S: Store>(
        &self,
        store: &S,
        body: &[u8],
        mac: Option<&str>,
        net: &Network,
        server_signals: &Signals,
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

        if req.signals.len() > MAX_SIGNALS {
            return Err(AttestError::Malformed);
        }
        let mut signals: Signals = req
            .signals
            .iter()
            .filter(|(k, _)| self.wanted.iter().any(|w| w == *k))
            .map(|(k, v)| (k.clone(), Value::from(v)))
            .collect();
        for (k, v) in server_signals {
            signals.insert(k.clone(), v.clone());
        }
        let fp_digest = bind::tag(&self.ring.current().bind, "fp", &fp_canonical(&signals));
        let score = self.rules.score(&signals);
        let band = self.cfg.band(score.total());

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
            fp_digest,
            band,
            flags,
            policy: 0,
        };
        Ok(Issued {
            token: token.seal(&self.ring, random()),
            expires_at: expires_at as u64,
            band,
            score: score.total(),
            hits: score.hits.into_iter().map(|h| h.rule).collect(),
        })
    }

    /// Swaps a live session for a new token and session key. `verified` is
    /// the already-verified signed refresh request. The client proves it still
    /// holds its key (its public key must match the token) and re-reports the
    /// fingerprint subset, which must match what was sealed at attest.
    pub fn refresh(
        &self,
        verified: &Verified,
        body: &[u8],
        net: &Network,
        now: u64,
    ) -> Result<Refreshed, AttestError> {
        if body.len() > MAX_ATTEST_BODY {
            return Err(AttestError::Malformed);
        }
        let req: RefreshBody = serde_json::from_slice(body).map_err(|_| AttestError::Malformed)?;
        let client_raw = b64::decode_url(&req.client_public).map_err(|_| AttestError::Malformed)?;
        if Sha256::digest(&client_raw)[..16] != verified.client_key_hash {
            return Err(AttestError::Rejected);
        }
        let client = PublicKey::from_sec1_bytes(&client_raw).map_err(|_| AttestError::Malformed)?;

        let absolute_end = verified.issued_at as u64 + self.cfg.absolute_ttl_secs as u64;
        if now >= absolute_end {
            return Err(AttestError::Reattest);
        }
        let fp = fp_canonical(&fp_from_json(&req.fp));
        let old_bind = &self
            .ring
            .get(verified.kid)
            .ok_or(AttestError::Rejected)?
            .bind;
        if !tags_equal(&bind::tag(old_bind, "fp", &fp), &verified.fp_digest) {
            return Err(AttestError::Reattest);
        }

        let eph = new_ephemeral();
        let key: [u8; 32] = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), client.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .expect("P-256 shared secret is 32 bytes");

        let (bind_net, bind_ja4) = self.net_tags(net);
        let mut flags = verified.flags;
        flags = if bind_ja4.is_none() {
            flags.with(Flags::NET_ABSENT)
        } else {
            signprint_wire::token::Flags(flags.0 & !Flags::NET_ABSENT)
        };
        let expires_at = (now + self.cfg.session_ttl_secs as u64).min(absolute_end) as u32;
        let token = SessionToken {
            sid: verified.sid,
            issued_at: verified.issued_at,
            expires_at,
            epoch: verified.epoch.wrapping_add(1),
            mac_key: key,
            client_key_hash: verified.client_key_hash,
            bind_ja4: bind_ja4.unwrap_or([0; 8]),
            bind_net,
            fp_digest: bind::tag(&self.ring.current().bind, "fp", &fp),
            band: verified.band,
            flags,
            policy: verified.policy,
        };
        Ok(Refreshed {
            token: token.seal(&self.ring, random()),
            ephemeral_public: eph
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .expect("uncompressed P-256 point is 65 bytes"),
            expires_at: expires_at as u64,
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
        let pack = signprint_rules::Pack::parse(
            r#"
            [pack]
            name = "t"
            version = "0"
            license = "Apache-2.0"
            [[rule]]
            id = "t.webdriver"
            family = "artifact"
            weight = 60
            when = "js.webdriver == true"
            [[rule]]
            id = "t.headless_header"
            family = "artifact"
            weight = 70
            when = 'contains(lower(http.ua), "headless")'
            "#,
        )
        .unwrap();
        Issuer::new(
            KeyRing::new(1, 1, &[(1, [3; 32])]).unwrap(),
            IssuerConfig::default(),
            RuleSet::new(vec![pack]),
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
        attest_body_with(offer, answer_fix, serde_json::json!({}))
    }

    fn attest_body_with(
        offer: &Offer,
        answer_fix: impl Fn(u32) -> u64,
        signals: serde_json::Value,
    ) -> (Vec<u8>, String, [u8; 32]) {
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
            "signals": signals,
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
            .attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW + 1)
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
        assert!(
            i.attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW)
                .is_ok()
        );
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW),
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
            i.attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW),
            Err(AttestError::Rejected)
        );

        let offer = i.challenge(&net(), NOW);
        let (body, _, _) = attest_body(&offer, |a| a as u64);
        let forged = b64::encode_std(&[0u8; 32]);
        assert_eq!(
            i.attest(&store, &body, Some(&forged), &net(), &Signals::new(), NOW),
            Err(AttestError::Rejected)
        );
        assert_eq!(
            i.attest(&store, &body, None, &net(), &Signals::new(), NOW),
            Err(AttestError::Rejected)
        );

        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        assert_eq!(
            i.attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW + 60),
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
            i.attest(&store, &body, Some(&mac), &other, &Signals::new(), NOW),
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
        let issued = i
            .attest(&store, &body, Some(&mac), &n, &Signals::new(), NOW)
            .unwrap();
        let token = SessionToken::open(&i.ring, &issued.token).unwrap();
        assert!(token.flags.has(Flags::NET_ABSENT));
    }

    #[test]
    fn signals_are_scored_into_a_band() {
        let i = issuer();
        let store = MemoryStore::default();

        let offer = i.challenge(&net(), NOW);
        let (body, mac, _) = attest_body(&offer, |a| a as u64);
        let clean = i
            .attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW)
            .unwrap();
        assert_eq!(clean.band, 0);

        let offer = i.challenge(&net(), NOW);
        let flagged = serde_json::json!({ "js.webdriver": true });
        let (body, mac, _) = attest_body_with(&offer, |a| a as u64, flagged);
        let issued = i
            .attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW)
            .unwrap();
        assert_eq!((issued.band, issued.score), (2, 60));
        assert_eq!(issued.hits, ["t.webdriver"]);
        let token = SessionToken::open(&i.ring, &issued.token).unwrap();
        assert_eq!(token.band, 2);
    }

    #[test]
    fn client_cant_set_server_signals() {
        let i = issuer();
        let store = MemoryStore::default();
        let offer = i.challenge(&net(), NOW);
        // the client claims a clean http.ua; the proxy's observed value wins
        let claimed = serde_json::json!({ "http.ua": "Mozilla/5.0 Chrome/141" });
        let (body, mac, _) = attest_body_with(&offer, |a| a as u64, claimed);
        let server: Signals = [(
            "http.ua".to_string(),
            Value::Str("HeadlessChrome/141".into()),
        )]
        .into();
        let issued = i
            .attest(&store, &body, Some(&mac), &net(), &server, NOW)
            .unwrap();
        assert_eq!(issued.hits, ["t.headless_header"]);

        // client-side signals the rules read, plus the fingerprint subset
        assert_eq!(i.wanted_signals()[0], "js.webdriver");
    }

    #[test]
    fn band_thresholds() {
        let c = IssuerConfig::default();
        let bands: Vec<u8> = [-10, 0, 1, 30, 31, 70, 71]
            .iter()
            .map(|s| c.band(*s))
            .collect();
        assert_eq!(bands, [0, 0, 1, 1, 2, 2, 3]);
    }

    fn verified_from(i: &Issuer, token: &str) -> Verified {
        let (t, kid) = SessionToken::open_with_kid(&i.ring, token).unwrap();
        Verified {
            sid: t.sid,
            band: t.band,
            flags: t.flags,
            policy: t.policy,
            issued_at: t.issued_at,
            expires_at: t.expires_at,
            epoch: t.epoch,
            client_key_hash: t.client_key_hash,
            fp_digest: t.fp_digest,
            kid,
            requests: 1,
        }
    }

    /// Attests with a known client key and fingerprint, returns what refresh needs.
    fn session_with_fp(i: &Issuer, fp: serde_json::Value) -> (Issued, SecretKey) {
        let store = MemoryStore::default();
        let offer = i.challenge(&net(), NOW);
        let client = new_ephemeral();
        let eph = PublicKey::from_sec1_bytes(&offer.ephemeral_public).unwrap();
        let k: [u8; 32] = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        let program = i.program(&offer.cid, NOW).unwrap();
        let body = serde_json::json!({
            "cid": offer.cid,
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "probe": { program.field: program.answer },
            "signals": fp,
        })
        .to_string()
        .into_bytes();
        let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        m.update(ATTEST_DOMAIN);
        m.update(&body);
        let mac = b64::encode_std(&m.finalize().into_bytes());
        (
            i.attest(&store, &body, Some(&mac), &net(), &Signals::new(), NOW)
                .unwrap(),
            client,
        )
    }

    fn refresh_body(client: &SecretKey, fp: serde_json::Value) -> Vec<u8> {
        serde_json::json!({
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "fp": fp,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn refresh_rotates_the_key_and_keeps_the_session() {
        let i = issuer();
        let fp = serde_json::json!({ "js.ua": "Mozilla/5.0 X", "js.hw_concurrency": 8, "js.engine": "blink" });
        let (issued, client) = session_with_fp(&i, fp.clone());
        let v = verified_from(&i, &issued.token);

        let r = i
            .refresh(&v, &refresh_body(&client, fp), &net(), NOW + 300)
            .unwrap();
        let old = SessionToken::open(&i.ring, &issued.token).unwrap();
        let new = SessionToken::open(&i.ring, &r.token).unwrap();
        assert_eq!(new.sid, old.sid);
        assert_eq!(new.epoch, 1);
        assert_eq!(new.issued_at, old.issued_at);
        assert_ne!(new.mac_key, old.mac_key);
        assert_eq!(new.expires_at as u64, NOW + 300 + 600);

        // the client can derive the new key from its own key + the new ephemeral
        let eph = PublicKey::from_sec1_bytes(&r.ephemeral_public).unwrap();
        let k = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph.as_affine());
        assert_eq!(k.raw_secret_bytes().as_slice(), new.mac_key);
    }

    #[test]
    fn refresh_rejects_changed_fingerprint_wrong_key_and_old_sessions() {
        let i = issuer();
        let fp = serde_json::json!({ "js.ua": "Mozilla/5.0 X", "js.hw_concurrency": 8 });
        let (issued, client) = session_with_fp(&i, fp.clone());
        let v = verified_from(&i, &issued.token);

        let changed = serde_json::json!({ "js.ua": "Mozilla/5.0 Y", "js.hw_concurrency": 8 });
        assert_eq!(
            i.refresh(&v, &refresh_body(&client, changed), &net(), NOW + 10),
            Err(AttestError::Reattest)
        );

        let stranger = new_ephemeral();
        assert_eq!(
            i.refresh(&v, &refresh_body(&stranger, fp.clone()), &net(), NOW + 10),
            Err(AttestError::Rejected)
        );

        assert_eq!(
            i.refresh(&v, &refresh_body(&client, fp.clone()), &net(), NOW + 3600),
            Err(AttestError::Reattest)
        );
        // near the cap, the new token stops at the absolute end
        let r = i
            .refresh(&v, &refresh_body(&client, fp), &net(), NOW + 3300)
            .unwrap();
        assert_eq!(r.expires_at, NOW + 3600);
    }

    #[test]
    fn fingerprint_keys_are_always_requested() {
        let i = issuer();
        for k in FINGERPRINT_KEYS {
            assert!(i.wanted_signals().iter().any(|w| w == k), "{k}");
        }
    }

    #[test]
    fn garbage_is_malformed() {
        let i = issuer();
        let store = MemoryStore::default();
        assert_eq!(
            i.attest(&store, b"not json", Some("x"), &net(), &Signals::new(), NOW),
            Err(AttestError::Malformed)
        );
        let big = vec![b' '; MAX_ATTEST_BODY + 1];
        assert_eq!(
            i.attest(&store, &big, Some("x"), &net(), &Signals::new(), NOW),
            Err(AttestError::Malformed)
        );
    }
}
