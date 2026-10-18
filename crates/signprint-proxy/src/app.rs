//! Everything the proxy decides about a request, kept free of Pingora types so
//! it can be tested on any platform. The Pingora glue in `server.rs` just
//! collects an [`Incoming`] and carries out the [`Decision`].

use std::net::IpAddr;
use std::sync::Arc;

use signprint_core::issue::{self, Attested, Issuer, IssuerConfig, PowConfig};
use signprint_core::network::{ForwardedTrusted, Network};
use signprint_core::store::MemoryStore;
use signprint_core::verdict::{self, Action, Mode, Verdict};
use signprint_core::verify::{self, Reject, Verifier};
use signprint_rules::{RuleSet, Signals, Value};
use signprint_wire::b64;
use signprint_wire::keys::KeyRing;

use crate::config::{Config, Require, RouteConfig};

pub const WELL_KNOWN: &str = "/.well-known/signprint/v1/";

#[derive(Debug, Clone)]
pub struct Route {
    prefix: String,
    methods: Vec<String>,
    require: Require,
}

impl From<&RouteConfig> for Route {
    fn from(r: &RouteConfig) -> Self {
        Self {
            prefix: r.path_prefix.clone(),
            methods: r.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
            require: r.require,
        }
    }
}

/// Longest matching prefix wins; a route with no methods matches any method.
pub fn match_route<'a>(routes: &'a [Route], method: &str, path: &str) -> Option<&'a Route> {
    routes
        .iter()
        .filter(|r| path.starts_with(&r.prefix))
        .filter(|r| r.methods.is_empty() || r.methods.iter().any(|m| m == method))
        .max_by_key(|r| r.prefix.len())
}

/// What we know about an incoming request.
#[derive(Debug, Clone, Default)]
pub struct Incoming<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub https: bool,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub signature_input: Option<&'a str>,
    pub signature: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    /// JA4 header from the previous hop (middleware mode only).
    pub forwarded_ja4: Option<&'a str>,
    pub peer_ip: Option<IpAddr>,
    /// ja4n we computed ourselves from the ClientHello.
    pub ja4n: Option<String>,
    pub user_agent: Option<&'a str>,
    pub sec_ch_ua: Option<&'a str>,
    /// `signprint-calibrate` header, for the calibration endpoint.
    pub calibrate_token: Option<&'a str>,
    pub body: &'a [u8],
    /// The body went past `max_body` and we stopped reading it.
    pub body_too_large: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Forward { verdict: String },
    Reject { status: u16, code: &'static str },
}

/// A response we answer ourselves (well-known endpoints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Reply {
    fn json(status: u16, v: serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: v.to_string(),
        }
    }

    fn error(status: u16, code: &str) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: reject_body(code),
        }
    }
}

pub struct App {
    verifier: Verifier<Arc<MemoryStore>>,
    issuer: Issuer,
    store: Arc<MemoryStore>,
    routes: Vec<Route>,
    mode: Mode,
    upstream_key: [u8; 32],
    log_root: [u8; 32],
    forwarded: Option<ForwardedTrusted>,
    max_body: usize,
    calibrate_token: Option<String>,
}

impl App {
    pub fn new(
        cfg: &Config,
        ring: KeyRing,
        rules: RuleSet,
        canvas: Option<signprint_core::canvas::Canvas>,
        calibrate_token: Option<String>,
        upstream_key: [u8; 32],
        log_root: [u8; 32],
    ) -> Self {
        let trusted = cfg.trusted_upstreams();
        let store = Arc::new(MemoryStore::default());
        let issuer = Issuer::new(
            ring.clone(),
            IssuerConfig {
                challenge_ttl_secs: cfg.session.challenge_ttl_secs,
                session_ttl_secs: cfg.session.ttl_secs,
                absolute_ttl_secs: cfg.session.absolute_ttl_secs,
                bands: cfg.rules.bands,
                pow: cfg.pow.enabled.then(|| PowConfig {
                    stepup_band: cfg.pow.stepup_band,
                    memory_kib: cfg.pow.memory_kib,
                    iterations: cfg.pow.iterations,
                    puzzles: cfg.pow.puzzles,
                    bits: cfg.pow.bits,
                    ..PowConfig::default()
                }),
            },
            rules,
        );
        let issuer = match canvas {
            Some(c) => issuer.with_canvas(c),
            None => issuer,
        };
        Self {
            issuer,
            calibrate_token: calibrate_token.filter(|t| !t.is_empty()),
            store: store.clone(),
            verifier: Verifier::new(
                ring,
                store,
                verify::Config {
                    skew_secs: cfg.session.skew_secs,
                    max_requests: cfg.session.max_requests,
                },
            ),
            routes: cfg.routes.iter().map(Route::from).collect(),
            mode: cfg.mode.into(),
            upstream_key,
            log_root,
            forwarded: (!trusted.is_empty()).then_some(ForwardedTrusted { trusted }),
            max_body: cfg.session.max_body_bytes,
        }
    }

    pub fn max_body(&self) -> usize {
        self.max_body
    }

    /// Whether we need the request body before deciding. Only signed routes
    /// look at it; everything else streams straight through.
    pub fn needs_body(&self, method: &str, path: &str) -> bool {
        matches!(
            match_route(&self.routes, method, path).map(|r| r.require),
            Some(Require::Signed)
        )
    }

    /// Whether this path is one of ours and how much body it may carry.
    pub fn well_known_body_limit(&self, method: &str, path: &str) -> Option<usize> {
        let rest = path.strip_prefix(WELL_KNOWN)?;
        Some(
            if method == "POST" && matches!(rest, "attest" | "refresh" | "pow" | "calibrate") {
                issue::MAX_ATTEST_BODY
            } else {
                0
            },
        )
    }

    /// Handles `/.well-known/signprint/v1/*`. `ja4` is the raw (not
    /// normalised) JA4, only used by `whoami`.
    pub fn well_known(
        &self,
        req: &Incoming<'_>,
        attest_mac: Option<&str>,
        ja4: Option<&str>,
        now: u64,
    ) -> Reply {
        let rest = req.path.strip_prefix(WELL_KNOWN).unwrap_or("");
        let net = self.network(req);
        match (req.method, rest) {
            ("GET", "whoami") => Reply {
                status: 200,
                content_type: "application/json",
                body: whoami_body(&net, ja4),
            },
            ("GET", "challenge") => {
                let offer = self.issuer.challenge(&net, req.user_agent, now);
                Reply::json(
                    200,
                    serde_json::json!({
                        "cid": offer.cid,
                        "probe_key": offer.probe_key,
                        "ephemeral_public": b64::encode_url(&offer.ephemeral_public),
                        "program": format!("{WELL_KNOWN}c/{}.js", offer.cid),
                        "signals": self.issuer.wanted_signals(),
                        "canvas": offer.canvas.map(|t| serde_json::json!({
                            "seed": t.seed,
                            "rounds": t.rounds,
                            "size": t.size,
                            "pattern_seed": t.pattern_seed,
                        })),
                        "expires_at": offer.expires_at,
                        "server_time": now,
                    }),
                )
            }
            ("GET", r) if r.starts_with("c/") && r.ends_with(".js") => {
                let cid = &r[2..r.len() - 3];
                match self.issuer.program(cid, now) {
                    Ok(p) => Reply {
                        status: 200,
                        content_type: "text/javascript",
                        body: p.source,
                    },
                    Err(e) => Reply::error(e.status(), e.code()),
                }
            }
            ("POST", "attest") => {
                let server = server_signals(req, &net);
                match self
                    .issuer
                    .attest(&self.store, req.body, attest_mac, &net, &server, now)
                {
                    Ok(Attested::Session(issued)) => {
                        log::info!(
                            "session issued: band {} score {} rules [{}]",
                            issued.band,
                            issued.score,
                            issued.hits.join(", ")
                        );
                        Reply::json(
                            200,
                            serde_json::json!({
                                "token": issued.token,
                                "expires_at": issued.expires_at,
                                "server_time": now,
                            }),
                        )
                    }
                    Ok(Attested::StepUp(up)) => {
                        log::info!(
                            "step-up required: band {} score {} rules [{}]",
                            up.band,
                            up.score,
                            up.hits.join(", ")
                        );
                        Reply::json(
                            200,
                            serde_json::json!({
                                "pow": {
                                    "ticket": up.ticket,
                                    "id": b64::encode_url(&up.id),
                                    "memory_kib": up.params.memory_kib,
                                    "iterations": up.params.iterations,
                                    "puzzles": up.params.puzzles,
                                    "bits": up.params.bits,
                                    "expires_at": up.expires_at,
                                },
                                "server_time": now,
                            }),
                        )
                    }
                    Err(e) => Reply::error(e.status(), e.code()),
                }
            }
            ("POST", "refresh") => {
                let vreq = verify::Request {
                    method: req.method,
                    authority: req.authority,
                    https: req.https,
                    path: req.path,
                    query: req.query,
                    signature_input: req.signature_input,
                    signature: req.signature,
                    content_digest: req.content_digest,
                    body: req.body,
                };
                let verified = match self.verifier.verify_with(&vreq, &net, now, false) {
                    Ok(v) => v,
                    Err(r) => return Reply::error(r.status(), r.code()),
                };
                match self.issuer.refresh(&verified, req.body, &net, now) {
                    Ok(r) => Reply::json(
                        200,
                        serde_json::json!({
                            "token": r.token,
                            "ephemeral_public": b64::encode_url(&r.ephemeral_public),
                            "expires_at": r.expires_at,
                            "server_time": now,
                        }),
                    ),
                    Err(e) => Reply::error(e.status(), e.code()),
                }
            }
            ("POST", "pow") => {
                #[derive(serde::Deserialize)]
                struct Solution {
                    ticket: String,
                    nonces: Vec<u32>,
                }
                let Ok(sol) = serde_json::from_slice::<Solution>(req.body) else {
                    return Reply::error(400, "sp_malformed");
                };
                match self
                    .issuer
                    .redeem(&self.store, &sol.ticket, &sol.nonces, now)
                {
                    Ok(issued) => Reply::json(
                        200,
                        serde_json::json!({
                            "token": issued.token,
                            "expires_at": issued.expires_at,
                            "server_time": now,
                        }),
                    ),
                    Err(e) => Reply::error(e.status(), e.code()),
                }
            }
            (_, "calibrate") => self.calibrate(req),
            _ => Reply::error(404, "sp_not_found"),
        }
    }

    /// Operator-only: `GET` lists the seed pool to render, `POST` records the
    /// answers for the class this browser's User-Agent claims.
    fn calibrate(&self, req: &Incoming<'_>) -> Reply {
        let (Some(canvas), Some(expected)) = (self.issuer.canvas(), &self.calibrate_token) else {
            return Reply::error(404, "sp_not_found");
        };
        let ok = req.calibrate_token.is_some_and(|t| {
            use subtle::ConstantTimeEq;
            t.len() == expected.len() && bool::from(t.as_bytes().ct_eq(expected.as_bytes()))
        });
        if !ok {
            return Reply::error(401, "sp_auth");
        }
        if req.method == "GET" {
            return Reply::json(
                200,
                serde_json::json!({
                    "seeds": canvas.pool(),
                    "rounds": canvas.shape().0,
                    "size": canvas.shape().1,
                    "classes": canvas.summary(),
                }),
            );
        }

        #[derive(serde::Deserialize)]
        struct Run {
            device: String,
            answers: Vec<(u32, String)>,
        }
        let Ok(run) = serde_json::from_slice::<Run>(req.body) else {
            return Reply::error(400, "sp_malformed");
        };
        if run.device.is_empty()
            || run.device.len() > 64
            || run.answers.iter().any(|(_, a)| a.len() > 64)
        {
            return Reply::error(400, "sp_malformed");
        }
        match canvas.calibrate(req.user_agent.unwrap_or(""), &run.device, &run.answers) {
            Ok((class, added)) => {
                log::info!(
                    "calibration: {class} from device {} added {added} answers",
                    run.device
                );
                Reply::json(
                    200,
                    serde_json::json!({ "class": class.to_string(), "added": added }),
                )
            }
            Err(e) => {
                log::warn!("calibration failed: {e}");
                Reply::error(400, "sp_malformed")
            }
        }
    }

    /// Network evidence for this request, honouring middleware mode.
    pub fn network(&self, req: &Incoming<'_>) -> Network {
        let peer = req.peer_ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        match &self.forwarded {
            Some(f) => f.network(peer, req.forwarded_ja4),
            None => Network::direct(peer, req.ja4n.clone()),
        }
    }

    pub fn decide(&self, req: &Incoming<'_>, now: u64, request_id: u64) -> Decision {
        let mut v = Verdict {
            action: Action::Skip,
            mode: self.mode,
            reason: None,
            band: 0,
            flags: 0,
            sid: None,
            request_id,
            ts: now,
            request_hash: verdict::request_hash(req.method, req.authority, req.path, req.query),
        };

        let route = match_route(&self.routes, req.method, req.path);
        if !matches!(route.map(|r| r.require), Some(Require::Signed)) {
            return Decision::Forward {
                verdict: v.encode(&self.upstream_key),
            };
        }

        let outcome = if req.body_too_large || req.body.len() > self.max_body {
            Err(Reject::Malformed)
        } else {
            let vreq = verify::Request {
                method: req.method,
                authority: req.authority,
                https: req.https,
                path: req.path,
                query: req.query,
                signature_input: req.signature_input,
                signature: req.signature,
                content_digest: req.content_digest,
                body: req.body,
            };
            self.verifier.verify(&vreq, &self.network(req), now)
        };

        match outcome {
            Ok(ok) => {
                v.action = Action::Allow;
                v.band = ok.band;
                v.flags = ok.flags.0;
                v.sid = Some(verdict::sid_hash(
                    &verdict::day_key(&self.log_root, now / 86_400),
                    &ok.sid,
                ));
            }
            Err(r) if self.mode == Mode::Enforce => {
                return Decision::Reject {
                    status: r.status(),
                    code: r.code(),
                };
            }
            Err(r) => {
                v.action = Action::Deny;
                v.reason = Some(r.code().to_owned());
            }
        }
        Decision::Forward {
            verdict: v.encode(&self.upstream_key),
        }
    }
}

/// What the proxy saw itself. These always win over anything the client
/// reports under the same name.
fn server_signals(req: &Incoming<'_>, net: &Network) -> Signals {
    let mut s = Signals::new();
    if let Some(ua) = req.user_agent {
        s.insert("http.ua".into(), Value::Str(ua.into()));
    }
    if let Some(ch) = req.sec_ch_ua {
        s.insert("http.sec_ch_ua".into(), Value::Str(ch.into()));
    }
    let provenance = format!("{:?}", net.provenance).to_lowercase();
    s.insert("net.provenance".into(), Value::Str(provenance));
    s
}

/// Body for rejected requests. Fixed and minimal on purpose.
pub fn reject_body(code: &str) -> String {
    format!("{{\"error\":\"{code}\"}}")
}

/// `GET /.well-known/signprint/v1/whoami`: what we saw of the caller's TLS.
/// Handy when setting things up (e.g. to check a CDN isn't eating the JA4).
pub fn whoami_body(net: &Network, ja4: Option<&str>) -> String {
    serde_json::json!({
        "ja4": ja4,
        "ja4n": net.ja4n,
        "provenance": format!("{:?}", net.provenance).to_lowercase(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use signprint_wire::bind;
    use signprint_wire::digest;
    use signprint_wire::nonce::RequestNonce;
    use signprint_wire::sig;
    use signprint_wire::token::{Flags, SessionToken};

    const NOW: u64 = 1_760_716_800;
    const UPSTREAM: [u8; 32] = [3; 32];

    fn config(mode: &str) -> Config {
        toml::from_str(&format!(
            r#"
            mode = "{mode}"
            [listen]
            plain = "127.0.0.1:8080"
            [upstream]
            addr = "127.0.0.1:3000"
            [keys]
            keyring = "k.json"
            upstream_secret_env = "A"
            log_root_env = "B"
            [pow]
            memory_kib = 64
            [[route]]
            path_prefix = "/api/"
            require = "signed"
            [[route]]
            path_prefix = "/api/public/"
            require = "none"
            "#
        ))
        .unwrap()
    }

    fn app(mode: &str) -> (App, String) {
        let ring = KeyRing::new(1, 1, &[(1, [9; 32])]).unwrap();
        let bind_key = ring.current().bind;
        let token = SessionToken {
            sid: [4; 16],
            issued_at: NOW as u32,
            expires_at: NOW as u32 + 600,
            epoch: 0,
            mac_key: [0x42; 32],
            client_key_hash: [0; 16],
            bind_ja4: [0; 8],
            bind_net: bind::tag(
                &bind_key,
                "net",
                &bind::ip_prefix("192.0.2.9".parse().unwrap()),
            ),
            fp_digest: [0; 8],
            band: 1,
            flags: Flags::default().with(Flags::NET_ABSENT),
            policy: 0,
        }
        .seal(&ring, [0; 24]);
        let rules = crate::config::load_rules(&Default::default()).unwrap();
        (
            App::new(&config(mode), ring, rules, None, None, UPSTREAM, [5; 32]),
            token,
        )
    }

    fn signed_headers(token: &str, path: &str, body: &[u8]) -> (String, String, Option<String>) {
        let digest = (!body.is_empty()).then(|| digest::content_digest(body));
        let params = sig::Params {
            created: NOW,
            keyid: token.into(),
            nonce: RequestNonce { tab: 1, ctr: 0 },
        };
        let base = sig::signature_base(
            &sig::Components {
                method: "POST",
                authority: "shop.example",
                path,
                query: "?",
                content_digest: digest.as_deref(),
            },
            &params,
        );
        let (i, s) = sig::header_values(&params, digest.is_some(), &sig::mac(&[0x42; 32], &base));
        (i, s, digest)
    }

    fn incoming<'a>(
        path: &'a str,
        h: &'a (String, String, Option<String>),
        body: &'a [u8],
    ) -> Incoming<'a> {
        Incoming {
            method: "POST",
            authority: "shop.example",
            https: true,
            path,
            signature_input: Some(&h.0),
            signature: Some(&h.1),
            content_digest: h.2.as_deref(),
            peer_ip: Some("192.0.2.9".parse().unwrap()),
            body,
            ..Default::default()
        }
    }

    fn parse_verdict(d: &Decision, path: &str) -> Verdict {
        let Decision::Forward { verdict } = d else {
            panic!("expected forward, got {d:?}")
        };
        Verdict::verify(
            Some(verdict),
            &UPSTREAM,
            &verdict::request_hash("POST", "shop.example", path, None),
            NOW,
            5,
        )
        .unwrap()
    }

    #[test]
    fn routing() {
        let routes: Vec<Route> = config("observe").routes.iter().map(Route::from).collect();
        assert_eq!(
            match_route(&routes, "POST", "/api/x").unwrap().require,
            Require::Signed
        );
        assert_eq!(
            match_route(&routes, "GET", "/api/public/x")
                .unwrap()
                .require,
            Require::None
        );
        assert!(match_route(&routes, "GET", "/index.html").is_none());
    }

    #[test]
    fn signed_request_is_allowed() {
        let (app, token) = app("enforce");
        let h = signed_headers(&token, "/api/cart", b"{}");
        let d = app.decide(&incoming("/api/cart", &h, b"{}"), NOW, 1);
        let v = parse_verdict(&d, "/api/cart");
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.band, 1);
        assert!(v.sid.is_some());
    }

    #[test]
    fn enforce_rejects_and_observe_reports() {
        let h = (String::new(), String::new(), None);
        let mut req = incoming("/api/cart", &h, b"");
        req.signature_input = None;
        req.signature = None;

        let (enforce, _) = app("enforce");
        assert_eq!(
            enforce.decide(&req, NOW, 1),
            Decision::Reject {
                status: 401,
                code: "sp_required"
            }
        );

        let (observe, _) = app("observe");
        let v = parse_verdict(&observe.decide(&req, NOW, 1), "/api/cart");
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reason.as_deref(), Some("sp_required"));
    }

    #[test]
    fn unprotected_routes_are_skipped() {
        let (app, _) = app("enforce");
        let h = (String::new(), String::new(), None);
        let mut req = incoming("/api/public/feed", &h, b"");
        req.signature_input = None;
        assert!(!app.needs_body("POST", "/api/public/feed"));
        let v = parse_verdict(&app.decide(&req, NOW, 1), "/api/public/feed");
        assert_eq!(v.action, Action::Skip);
    }

    #[test]
    fn oversized_body_is_rejected() {
        let (app, token) = app("enforce");
        let body = vec![b'x'; 65 * 1024];
        let h = signed_headers(&token, "/api/upload", &body);
        assert!(matches!(
            app.decide(&incoming("/api/upload", &h, &body), NOW, 1),
            Decision::Reject { status: 400, .. }
        ));
    }

    /// The whole thing in-process: challenge, probe, attest, then a signed
    /// request with the issued session. Plays the browser with p256 + hmac.
    #[test]
    fn challenge_attest_then_signed_request() {
        use hmac::{Hmac, KeyInit, Mac};
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha2::Sha256;

        fn get(path: &str) -> Incoming<'_> {
            Incoming {
                method: "GET",
                authority: "shop.example",
                https: true,
                path,
                peer_ip: Some("192.0.2.9".parse().unwrap()),
                ..Default::default()
            }
        }

        let (app, _) = app("enforce");
        let peer: IpAddr = "192.0.2.9".parse().unwrap();

        let r = app.well_known(&get("/.well-known/signprint/v1/challenge"), None, None, NOW);
        assert_eq!(r.status, 200);
        let offer: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let cid = offer["cid"].as_str().unwrap();

        // fetch the probe program; the answer is what a browser would compute
        let r = app.well_known(&get(offer["program"].as_str().unwrap()), None, None, NOW);
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/javascript");
        let probe = app.issuer.program(cid, NOW).unwrap();

        let client = p256::SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let eph = p256::PublicKey::from_sec1_bytes(
            &b64::decode_url(offer["ephemeral_public"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let k: [u8; 32] = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        let body = serde_json::json!({
            "cid": cid,
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "probe": { probe.field: probe.answer },
        })
        .to_string();
        let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        m.update(issue::ATTEST_DOMAIN);
        m.update(body.as_bytes());
        let mac = b64::encode_std(&m.finalize().into_bytes());

        let attest = Incoming {
            method: "POST",
            path: "/.well-known/signprint/v1/attest",
            body: body.as_bytes(),
            ..get("")
        };
        let r = app.well_known(&attest, Some(&mac), None, NOW);
        assert_eq!(r.status, 200, "{}", r.body);
        let session: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let token = session["token"].as_str().unwrap();

        // now a signed request with that token and k
        let params = sig::Params {
            created: NOW,
            keyid: token.into(),
            nonce: RequestNonce { tab: 7, ctr: 0 },
        };
        let digest = digest::content_digest(b"{}");
        let base = sig::signature_base(
            &sig::Components {
                method: "POST",
                authority: "shop.example",
                path: "/api/cart",
                query: "?",
                content_digest: Some(&digest),
            },
            &params,
        );
        let (input, signature) = sig::header_values(&params, true, &sig::mac(&k, &base));
        let req = Incoming {
            method: "POST",
            authority: "shop.example",
            https: true,
            path: "/api/cart",
            signature_input: Some(&input),
            signature: Some(&signature),
            content_digest: Some(&digest),
            peer_ip: Some(peer),
            body: b"{}",
            ..Default::default()
        };
        let v = parse_verdict(&app.decide(&req, NOW, 1), "/api/cart");
        assert_eq!(v.action, Action::Allow);

        // the same attestation can't be used twice
        let r = app.well_known(&attest, Some(&mac), None, NOW);
        assert_eq!(r.status, 401);

        // refresh: a signed request to the refresh endpoint, from a new network
        let refresh_body = serde_json::json!({
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "fp": {},
        })
        .to_string();
        let refresh_path = "/.well-known/signprint/v1/refresh";
        let digest = digest::content_digest(refresh_body.as_bytes());
        let params = sig::Params {
            created: NOW + 100,
            keyid: token.into(),
            nonce: RequestNonce { tab: 7, ctr: 1 },
        };
        let base = sig::signature_base(
            &sig::Components {
                method: "POST",
                authority: "shop.example",
                path: refresh_path,
                query: "?",
                content_digest: Some(&digest),
            },
            &params,
        );
        let (input, signature) = sig::header_values(&params, true, &sig::mac(&k, &base));
        let moved: IpAddr = "198.51.100.77".parse().unwrap();
        let refresh = Incoming {
            method: "POST",
            authority: "shop.example",
            https: true,
            path: refresh_path,
            signature_input: Some(&input),
            signature: Some(&signature),
            content_digest: Some(&digest),
            peer_ip: Some(moved),
            body: refresh_body.as_bytes(),
            ..Default::default()
        };
        let r = app.well_known(&refresh, None, None, NOW + 100);
        assert_eq!(r.status, 200, "{}", r.body);
        let refreshed: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let eph2 = p256::PublicKey::from_sec1_bytes(
            &b64::decode_url(refreshed["ephemeral_public"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let k2: [u8; 32] = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph2.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        assert_ne!(k2, k);

        // the refreshed session is bound to the new network and signs with k2
        let token2 = refreshed["token"].as_str().unwrap();
        let params = sig::Params {
            created: NOW + 101,
            keyid: token2.into(),
            nonce: RequestNonce { tab: 7, ctr: 2 },
        };
        let base = sig::signature_base(
            &sig::Components {
                method: "GET",
                authority: "shop.example",
                path: "/api/items",
                query: "?",
                content_digest: None,
            },
            &params,
        );
        let (input, signature) = sig::header_values(&params, false, &sig::mac(&k2, &base));
        let req = Incoming {
            method: "GET",
            authority: "shop.example",
            https: true,
            path: "/api/items",
            signature_input: Some(&input),
            signature: Some(&signature),
            peer_ip: Some(moved),
            ..Default::default()
        };
        let d = app.decide(&req, NOW + 101, 2);
        let Decision::Forward { verdict } = d else {
            panic!("expected forward, got {d:?}")
        };
        let v = Verdict::verify(
            Some(&verdict),
            &UPSTREAM,
            &verdict::request_hash("GET", "shop.example", "/api/items", None),
            NOW + 101,
            5,
        )
        .unwrap();
        assert_eq!(v.action, Action::Allow);
    }

    /// A flagged attestation gets a puzzle instead of a session; solving it
    /// releases the session.
    #[test]
    fn high_band_attestation_steps_up() {
        use hmac::{Hmac, KeyInit, Mac};
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha2::Sha256;
        use signprint_core::pow::{self, PowParams};

        let (app, _) = app("enforce");
        let base = Incoming {
            method: "GET",
            authority: "shop.example",
            https: true,
            path: "/.well-known/signprint/v1/challenge",
            peer_ip: Some("192.0.2.9".parse().unwrap()),
            ..Default::default()
        };
        let offer: serde_json::Value =
            serde_json::from_str(&app.well_known(&base, None, None, NOW).body).unwrap();
        let cid = offer["cid"].as_str().unwrap();
        let probe = app.issuer.program(cid, NOW).unwrap();

        let client = p256::SecretKey::from_slice(&[0x33; 32]).unwrap();
        let eph = p256::PublicKey::from_sec1_bytes(
            &b64::decode_url(offer["ephemeral_public"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let k: [u8; 32] = p256::ecdh::diffie_hellman(client.to_nonzero_scalar(), eph.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        // navigator.webdriver = true is worth 60, which is band 2
        let body = serde_json::json!({
            "cid": cid,
            "client_public": b64::encode_url(client.public_key().to_sec1_point(false).as_bytes()),
            "probe": { probe.field: probe.answer },
            "signals": { "js.webdriver": true },
        })
        .to_string();
        let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        m.update(issue::ATTEST_DOMAIN);
        m.update(body.as_bytes());
        let mac = b64::encode_std(&m.finalize().into_bytes());
        let attest = Incoming {
            method: "POST",
            path: "/.well-known/signprint/v1/attest",
            body: body.as_bytes(),
            ..base.clone()
        };
        let r = app.well_known(&attest, Some(&mac), None, NOW);
        assert_eq!(r.status, 200, "{}", r.body);
        let reply: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert!(reply.get("token").is_none(), "no session before the puzzle");
        let pow_offer = &reply["pow"];

        let params = PowParams {
            memory_kib: pow_offer["memory_kib"].as_u64().unwrap() as u32,
            iterations: pow_offer["iterations"].as_u64().unwrap() as u8,
            puzzles: pow_offer["puzzles"].as_u64().unwrap() as u8,
            bits: pow_offer["bits"].as_u64().unwrap() as u8,
        };
        let ticket = pow_offer["ticket"].as_str().unwrap();
        let ring = KeyRing::new(1, 1, &[(1, [9; 32])]).unwrap();
        let id: [u8; 16] = b64::decode_url(pow_offer["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let solution =
            serde_json::json!({ "ticket": ticket, "nonces": pow::solve(&params, &id) }).to_string();
        let redeem = Incoming {
            method: "POST",
            path: "/.well-known/signprint/v1/pow",
            body: solution.as_bytes(),
            ..base.clone()
        };
        let r = app.well_known(&redeem, None, None, NOW + 1);
        assert_eq!(r.status, 200, "{}", r.body);
        let session: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let token = SessionToken::open(&ring, session["token"].as_str().unwrap()).unwrap();
        assert_eq!(token.band, 2);
        assert!(token.flags.has(Flags::POW_PASSED));
        assert_eq!(token.mac_key, k);
    }

    #[test]
    fn unknown_well_known_path() {
        let (app, _) = app("enforce");
        let req = Incoming {
            method: "GET",
            path: "/.well-known/signprint/v1/nope",
            ..Default::default()
        };
        assert_eq!(app.well_known(&req, None, None, NOW).status, 404);
        assert_eq!(
            app.well_known_body_limit("POST", "/.well-known/signprint/v1/attest"),
            Some(16 * 1024)
        );
        assert_eq!(app.well_known_body_limit("GET", "/api/x"), None);
    }

    #[test]
    fn whoami_shape() {
        let net = Network::direct("192.0.2.1".parse().unwrap(), Some("t13d_x_y".into()));
        let v: serde_json::Value =
            serde_json::from_str(&whoami_body(&net, Some("t13d_x_z"))).unwrap();
        assert_eq!(v["ja4n"], "t13d_x_y");
        assert_eq!(v["provenance"], "direct");
    }
}
