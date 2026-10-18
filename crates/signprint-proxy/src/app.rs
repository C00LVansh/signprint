//! Everything the proxy decides about a request, kept free of Pingora types so
//! it can be tested on any platform. The Pingora glue in `server.rs` just
//! collects an [`Incoming`] and carries out the [`Decision`].

use std::net::IpAddr;

use signprint_core::network::{ForwardedTrusted, Network};
use signprint_core::store::MemoryStore;
use signprint_core::verdict::{self, Action, Mode, Verdict};
use signprint_core::verify::{self, Reject, Verifier};
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
    pub body: &'a [u8],
    /// The body went past `max_body` and we stopped reading it.
    pub body_too_large: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Forward { verdict: String },
    Reject { status: u16, code: &'static str },
}

pub struct App {
    verifier: Verifier<MemoryStore>,
    routes: Vec<Route>,
    mode: Mode,
    upstream_key: [u8; 32],
    log_root: [u8; 32],
    forwarded: Option<ForwardedTrusted>,
    max_body: usize,
}

impl App {
    pub fn new(cfg: &Config, ring: KeyRing, upstream_key: [u8; 32], log_root: [u8; 32]) -> Self {
        let trusted = cfg.trusted_upstreams();
        Self {
            verifier: Verifier::new(
                ring,
                MemoryStore::default(),
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
        (App::new(&config(mode), ring, UPSTREAM, [5; 32]), token)
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

    #[test]
    fn whoami_shape() {
        let net = Network::direct("192.0.2.1".parse().unwrap(), Some("t13d_x_y".into()));
        let v: serde_json::Value =
            serde_json::from_str(&whoami_body(&net, Some("t13d_x_z"))).unwrap();
        assert_eq!(v["ja4n"], "t13d_x_y");
        assert_eq!(v["provenance"], "direct");
    }
}
