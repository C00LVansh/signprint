//! Verifying a signed request.
//!
//! The order matters. Cheap structural checks come first, then everything that
//! needs the session key, and only after the MAC passes do we touch replay
//! state or say anything specific about bindings. Until then every failure
//! looks the same from outside (`sp_auth`), so someone holding a stolen token
//! but not its key learns nothing from our responses.

use signprint_wire::bind::{self, tags_equal};
use signprint_wire::keys::KeyRing;
use signprint_wire::token::{Flags, SessionToken};
use signprint_wire::{digest, sig};

use crate::network::Network;
use crate::store::{ReplayOutcome, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No signature at all; the client should attest first.
    Missing,
    Malformed,
    /// `created` too far from our clock.
    Stale,
    /// Covers bad token, bad digest, bad MAC, replay and revocation alike.
    Auth,
    /// Session budget used up, or too many tabs; run a fresh challenge.
    Reattest,
    /// Valid request, but from a different network than the session was
    /// bound to. A refresh from the new network fixes it.
    Rebind,
    /// Store full. Rare, but we fail closed.
    Busy,
}

impl Reject {
    pub fn code(self) -> &'static str {
        match self {
            Reject::Missing => "sp_required",
            Reject::Malformed => "sp_malformed",
            Reject::Stale => "sp_stale",
            Reject::Auth => "sp_auth",
            Reject::Reattest => "sp_reattest",
            Reject::Rebind => "sp_rebind",
            Reject::Busy => "sp_busy",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Reject::Malformed => 400,
            Reject::Busy => 503,
            _ => 401,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Allowed distance between `created` and our clock, in seconds.
    pub skew_secs: u64,
    /// Signed requests allowed per session before a fresh challenge.
    pub max_requests: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            skew_secs: 30,
            max_requests: 1000,
        }
    }
}

/// What the verifier needs to know about an incoming request. Header values
/// are as received; the body is the buffered request body (empty if none).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub https: bool,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub signature_input: Option<&'a str>,
    pub signature: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub sid: [u8; 16],
    pub band: u8,
    pub flags: Flags,
    pub policy: u16,
    pub issued_at: u32,
    pub expires_at: u32,
    pub epoch: u16,
    pub client_key_hash: [u8; 16],
    pub fp_digest: [u8; 8],
    /// Key id the token was sealed with; its bind key made the tags above.
    pub kid: u8,
    pub requests: u64,
}

pub struct Verifier<S> {
    ring: KeyRing,
    store: S,
    cfg: Config,
}

impl<S: Store> Verifier<S> {
    pub fn new(ring: KeyRing, store: S, cfg: Config) -> Self {
        Self { ring, store, cfg }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn verify(&self, req: &Request<'_>, net: &Network, now: u64) -> Result<Verified, Reject> {
        self.verify_with(req, net, now, true)
    }

    /// `check_bindings = false` is only for the refresh endpoint: a client told
    /// to rebind refreshes from its new network, and the refresh re-binds the
    /// session there. Everything else (MAC, replay, budget) still applies.
    pub fn verify_with(
        &self,
        req: &Request<'_>,
        net: &Network,
        now: u64,
        check_bindings: bool,
    ) -> Result<Verified, Reject> {
        // 1. structure
        let (Some(input), Some(signature)) = (req.signature_input, req.signature) else {
            return Err(Reject::Missing);
        };
        let received = sig::parse(input, signature).map_err(|_| Reject::Malformed)?;
        let has_body = !req.body.is_empty();
        if has_body && matches!(req.method, "GET" | "HEAD") {
            return Err(Reject::Malformed);
        }
        let authority =
            sig::canonical_authority(req.authority, req.https).map_err(|_| Reject::Malformed)?;

        // 2. clock
        if now.abs_diff(received.params.created) > self.cfg.skew_secs {
            return Err(Reject::Stale);
        }

        // 3. token
        let (token, kid) = SessionToken::open_with_kid(&self.ring, &received.params.keyid)
            .map_err(|_| Reject::Auth)?;
        if token.is_expired(now as u32)
            || self.store.is_revoked(&token.sid, now)
            || token.epoch < self.store.min_epoch(&token.sid, now)
        {
            return Err(Reject::Auth);
        }

        // 4. body
        if received.covers_body != has_body {
            return Err(Reject::Auth);
        }
        let content_digest = if has_body {
            let value = req.content_digest.ok_or(Reject::Auth)?;
            digest::verify(value, req.body).map_err(|_| Reject::Auth)?;
            Some(value.trim())
        } else {
            None
        };

        // 5. MAC
        let query = sig::canonical_query(req.query);
        let components = sig::Components {
            method: req.method,
            authority: &authority,
            path: sig::canonical_path(req.path),
            query: &query,
            content_digest,
        };
        let base = sig::signature_base(&components, &received.params);
        if !sig::verify_mac(&token.mac_key, &base, &received.mac) {
            return Err(Reject::Auth);
        }

        // 6 + 7. replay and budget
        let nonce = received.params.nonce;
        let requests = match self.store.record_request(
            &token.sid,
            nonce.tab,
            nonce.ctr,
            token.expires_at as u64,
            now,
        ) {
            ReplayOutcome::Fresh { requests } => requests,
            ReplayOutcome::Replayed | ReplayOutcome::TooOld | ReplayOutcome::Revoked => {
                return Err(Reject::Auth);
            }
            ReplayOutcome::TooManyTabs => return Err(Reject::Reattest),
            ReplayOutcome::Full => return Err(Reject::Busy),
        };
        if requests > self.cfg.max_requests {
            return Err(Reject::Reattest);
        }

        // 8. bindings
        let keys = self.ring.get(kid).ok_or(Reject::Auth)?;
        if check_bindings && !token.flags.has(Flags::NET_ABSENT) {
            let ok = net.ja4n.as_deref().is_some_and(|j| {
                tags_equal(
                    &bind::tag(&keys.bind, "ja4n", j.as_bytes()),
                    &token.bind_ja4,
                )
            });
            if !ok {
                return Err(Reject::Rebind);
            }
        }
        let net_tag = bind::tag(&keys.bind, "net", &bind::ip_prefix(net.peer_ip));
        if check_bindings && !tags_equal(&net_tag, &token.bind_net) {
            return Err(Reject::Rebind);
        }

        Ok(Verified {
            sid: token.sid,
            band: token.band,
            flags: token.flags,
            policy: token.policy,
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            epoch: token.epoch,
            client_key_hash: token.client_key_hash,
            fp_digest: token.fp_digest,
            kid,
            requests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Provenance;
    use crate::store::MemoryStore;
    use signprint_wire::nonce::RequestNonce;
    use std::net::IpAddr;

    const NOW: u64 = 1_760_716_800;
    const JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";

    struct Fixture {
        verifier: Verifier<MemoryStore>,
        token: String,
        mac_key: [u8; 32],
        net: Network,
    }

    fn fixture_with(flags: Flags, cfg: Config) -> Fixture {
        let ring = KeyRing::new(1, 1, &[(1, [7; 32])]).unwrap();
        let bind_key = ring.current().bind;
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let mac_key = [0x42; 32];
        let token = SessionToken {
            sid: [5; 16],
            issued_at: NOW as u32,
            expires_at: NOW as u32 + 600,
            epoch: 0,
            mac_key,
            client_key_hash: [0; 16],
            bind_ja4: bind::tag(&bind_key, "ja4n", JA4.as_bytes()),
            bind_net: bind::tag(&bind_key, "net", &bind::ip_prefix(ip)),
            fp_digest: [0; 8],
            band: 0,
            flags,
            policy: 0,
        }
        .seal(&ring, [1; 24]);
        Fixture {
            verifier: Verifier::new(ring, MemoryStore::default(), cfg),
            token,
            mac_key,
            net: Network {
                peer_ip: ip,
                ja4n: Some(JA4.into()),
                provenance: Provenance::Direct,
            },
        }
    }

    fn fixture() -> Fixture {
        fixture_with(Flags::default(), Config::default())
    }

    struct Signed {
        input: String,
        signature: String,
        digest: Option<String>,
    }

    fn sign(f: &Fixture, method: &str, path: &str, body: &[u8], ctr: u64, created: u64) -> Signed {
        let digest = (!body.is_empty()).then(|| digest::content_digest(body));
        let params = sig::Params {
            created,
            keyid: f.token.clone(),
            nonce: RequestNonce { tab: 1, ctr },
        };
        let base = sig::signature_base(
            &sig::Components {
                method,
                authority: "shop.example",
                path,
                query: "?",
                content_digest: digest.as_deref(),
            },
            &params,
        );
        let (input, signature) =
            sig::header_values(&params, digest.is_some(), &sig::mac(&f.mac_key, &base));
        Signed {
            input,
            signature,
            digest,
        }
    }

    fn request<'a>(method: &'a str, path: &'a str, s: &'a Signed, body: &'a [u8]) -> Request<'a> {
        Request {
            method,
            authority: "Shop.Example:443",
            https: true,
            path,
            query: None,
            signature_input: Some(&s.input),
            signature: Some(&s.signature),
            content_digest: s.digest.as_deref(),
            body,
        }
    }

    #[test]
    fn accepts_a_good_request() {
        let f = fixture();
        let s = sign(&f, "POST", "/api/cart", b"{}", 0, NOW);
        let v = f
            .verifier
            .verify(&request("POST", "/api/cart", &s, b"{}"), &f.net, NOW + 2)
            .unwrap();
        assert_eq!(v.sid, [5; 16]);
        assert_eq!(v.requests, 1);
    }

    #[test]
    fn replay_is_auth_failure() {
        let f = fixture();
        let s = sign(&f, "GET", "/a", b"", 0, NOW);
        let r = request("GET", "/a", &s, b"");
        assert!(f.verifier.verify(&r, &f.net, NOW).is_ok());
        assert_eq!(f.verifier.verify(&r, &f.net, NOW), Err(Reject::Auth));
    }

    #[test]
    fn tampering_is_auth_failure() {
        let f = fixture();
        let s = sign(&f, "POST", "/api/cart", b"{\"qty\":1}", 0, NOW);
        // different body, same headers
        let r = request("POST", "/api/cart", &s, b"{\"qty\":9}");
        assert_eq!(f.verifier.verify(&r, &f.net, NOW), Err(Reject::Auth));
        // different path
        let r = request("POST", "/api/admin", &s, b"{\"qty\":1}");
        assert_eq!(f.verifier.verify(&r, &f.net, NOW), Err(Reject::Auth));
        // body dropped
        let r = request("POST", "/api/cart", &s, b"");
        assert_eq!(f.verifier.verify(&r, &f.net, NOW), Err(Reject::Auth));
    }

    #[test]
    fn missing_and_stale() {
        let f = fixture();
        let s = sign(&f, "GET", "/", b"", 0, NOW);
        let mut r = request("GET", "/", &s, b"");
        assert_eq!(f.verifier.verify(&r, &f.net, NOW + 31), Err(Reject::Stale));
        r.signature = None;
        assert_eq!(f.verifier.verify(&r, &f.net, NOW), Err(Reject::Missing));
    }

    #[test]
    fn expired_or_revoked_token() {
        let f = fixture();
        let s = sign(&f, "GET", "/", b"", 0, NOW + 600);
        let r = request("GET", "/", &s, b"");
        assert_eq!(f.verifier.verify(&r, &f.net, NOW + 600), Err(Reject::Auth));

        let s = sign(&f, "GET", "/", b"", 1, NOW);
        f.verifier.store().revoke(&[5; 16], NOW + 600);
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &f.net, NOW),
            Err(Reject::Auth)
        );
    }

    #[test]
    fn superseded_epoch_is_refused() {
        let f = fixture();
        let s = sign(&f, "GET", "/", b"", 0, NOW);
        // a refresh moved the session on to epoch 1; this token is epoch 0
        f.verifier.store().advance_epoch(&[5; 16], 1, NOW + 600);
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &f.net, NOW),
            Err(Reject::Auth)
        );
    }

    #[test]
    fn network_change_asks_for_rebind() {
        let f = fixture();
        let s = sign(&f, "GET", "/", b"", 0, NOW);
        let mut moved = f.net.clone();
        moved.peer_ip = "198.51.100.1".parse().unwrap();
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &moved, NOW),
            Err(Reject::Rebind)
        );

        let s = sign(&f, "GET", "/", b"", 1, NOW);
        let mut other_tls = f.net.clone();
        other_tls.ja4n = Some("t13d1715h2_5b57614c22b0_3d5424432f57".into());
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &other_tls, NOW),
            Err(Reject::Rebind)
        );
    }

    #[test]
    fn net_absent_sessions_skip_ja4() {
        let f = fixture_with(Flags::default().with(Flags::NET_ABSENT), Config::default());
        let s = sign(&f, "GET", "/", b"", 0, NOW);
        let mut net = f.net.clone();
        net.ja4n = None;
        assert!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &net, NOW)
                .is_ok()
        );
    }

    #[test]
    fn budget_runs_out() {
        let f = fixture_with(
            Flags::default(),
            Config {
                max_requests: 2,
                ..Config::default()
            },
        );
        for ctr in 0..2 {
            let s = sign(&f, "GET", "/", b"", ctr, NOW);
            assert!(
                f.verifier
                    .verify(&request("GET", "/", &s, b""), &f.net, NOW)
                    .is_ok()
            );
        }
        let s = sign(&f, "GET", "/", b"", 2, NOW);
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b""), &f.net, NOW),
            Err(Reject::Reattest)
        );
    }

    #[test]
    fn get_with_body_is_malformed() {
        let f = fixture();
        let s = sign(&f, "GET", "/", b"", 0, NOW);
        assert_eq!(
            f.verifier
                .verify(&request("GET", "/", &s, b"x"), &f.net, NOW),
            Err(Reject::Malformed)
        );
    }
}
