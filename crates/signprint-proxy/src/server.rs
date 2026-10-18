//! Pingora glue. Collects what [`App`] needs from the connection and the
//! request, then forwards or rejects. All the actual decisions live in
//! `app.rs`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Result;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::PreTlsProcess;
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::{GetProxyDigest, Peek};
use pingora::proxy::{ProxyHttp, Session, http_proxy_service};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use signprint_core::verdict;
use signprint_netfp::{Peek as HelloPeek, hello, ja4, ja4n};

use crate::app::{App, Decision, Incoming, reject_body};
use crate::config::Config;

/// JA4 for one connection, attached in the pre-TLS hook and read back per request.
#[derive(Debug, Clone)]
struct ConnFingerprint {
    ja4: String,
    ja4n: String,
}

/// Peeks the ClientHello before rustls sees it. Never fails the connection:
/// if anything about the hello is odd we just don't have a fingerprint.
struct Ja4Peek;

#[async_trait]
impl PreTlsProcess for Ja4Peek {
    async fn process(&self, stream: &mut L4Stream) -> Result<()> {
        let peeked = tokio::time::timeout(Duration::from_secs(2), async {
            let mut want = 5;
            loop {
                let mut buf = vec![0u8; want];
                if !stream.try_peek(&mut buf).await.unwrap_or(false) {
                    return None;
                }
                match hello::peek(&buf) {
                    HelloPeek::Complete(_) => return hello::parse(&buf),
                    HelloPeek::NeedMore(n) if n > want => want = n,
                    _ => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();

        if let Some(h) = peeked {
            let fp = ConnFingerprint {
                ja4: ja4(&h),
                ja4n: ja4n(&h),
            };
            // ProxyDigest is meant for CONNECT proxies, but its user_data slot
            // is the one piece of per-connection state that pingora carries
            // from the raw stream through TLS to the HTTP session.
            let placeholder = ResponseHeader::build(200, None)?;
            stream.set_proxy_digest(ProxyDigest::new(Box::new(placeholder), Some(Box::new(fp))));
        }
        Ok(())
    }
}

pub struct Proxy {
    app: App,
    upstream: Upstream,
    ja4_header: String,
}

struct Upstream {
    addr: String,
    tls: bool,
    sni: String,
}

#[derive(Default)]
pub struct Ctx {
    verdict: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn request_id() -> u64 {
    let mut b = [0u8; 8];
    // a failed RNG read just means a less unique id; not worth failing a request
    let _ = getrandom::fill(&mut b);
    u64::from_be_bytes(b)
}

fn header<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

fn fingerprint(session: &Session) -> Option<ConnFingerprint> {
    let digest = session.digest()?;
    let proxy = digest.proxy_digest.as_ref()?;
    proxy
        .user_data
        .as_ref()?
        .downcast_ref::<ConnFingerprint>()
        .cloned()
}

async fn respond_json(session: &mut Session, status: u16, body: String) -> Result<()> {
    respond(session, status, "application/json", body).await
}

async fn respond(
    session: &mut Session,
    status: u16,
    content_type: &str,
    body: String,
) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(3))?;
    resp.insert_header("content-type", content_type)?;
    resp.insert_header("cache-control", "no-store")?;
    resp.insert_header("content-length", body.len().to_string())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let fp = fingerprint(session);
        let https = session.digest().is_some_and(|d| d.ssl_digest.is_some());
        let peer_ip = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip());

        let req = session.req_header();
        let method = req.method.as_str().to_owned();
        let path = req.uri.path().to_owned();

        // Our own endpoints: challenge, probe program, attest, whoami.
        if let Some(limit) = self.app.well_known_body_limit(&method, &path) {
            let mut body = Vec::new();
            if limit > 0 {
                while let Some(chunk) = session.read_request_body().await? {
                    if body.len() + chunk.len() > limit {
                        respond_json(session, 413, reject_body("sp_malformed")).await?;
                        return Ok(true);
                    }
                    body.extend_from_slice(&chunk);
                }
            }
            let req = session.req_header();
            let incoming = Incoming {
                method: &method,
                path: &path,
                peer_ip,
                ja4n: fp.as_ref().map(|f| f.ja4n.clone()),
                forwarded_ja4: header(req, &self.ja4_header),
                user_agent: header(req, "user-agent"),
                sec_ch_ua: header(req, "sec-ch-ua"),
                body: &body,
                ..Default::default()
            };
            let reply = self.app.well_known(
                &incoming,
                header(req, "signprint-attest"),
                fp.as_ref().map(|f| f.ja4.as_str()),
                now_secs(),
            );
            respond(session, reply.status, reply.content_type, reply.body).await?;
            return Ok(true);
        }

        // Read the body up front for signed routes. With retry buffering on,
        // pingora keeps what we read and replays it to the upstream.
        let mut body = Vec::new();
        let mut body_too_large = false;
        if self.app.needs_body(&method, &path) {
            session.enable_retry_buffering();
            while let Some(chunk) = session.read_request_body().await? {
                if body.len() + chunk.len() > self.app.max_body() {
                    body_too_large = true;
                    break;
                }
                body.extend_from_slice(&chunk);
            }
        }

        let req = session.req_header();
        let authority = req
            .uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| header(req, "host"))
            .unwrap_or("");
        let incoming = Incoming {
            method: &method,
            authority,
            https,
            path: &path,
            query: req.uri.query(),
            signature_input: header(req, "signature-input"),
            signature: header(req, "signature"),
            content_digest: header(req, "content-digest"),
            forwarded_ja4: header(req, &self.ja4_header),
            peer_ip,
            ja4n: fp.map(|f| f.ja4n),
            body: &body,
            body_too_large,
        };

        match self.app.decide(&incoming, now_secs(), request_id()) {
            Decision::Forward { verdict } => {
                ctx.verdict = Some(verdict);
                Ok(false)
            }
            Decision::Reject { status, code } => {
                respond_json(session, status, reject_body(code)).await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.upstream.addr.as_str(),
            self.upstream.tls,
            self.upstream.sni.clone(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // Whatever the client sent under our header names never reaches the app.
        let names: Vec<String> = upstream_request
            .headers
            .keys()
            .map(|k| k.as_str().to_owned())
            .filter(|k| k.starts_with("signprint-") || *k == self.ja4_header)
            .collect();
        for n in names {
            upstream_request.remove_header(&n);
        }
        if let Some(v) = ctx.verdict.take() {
            upstream_request.insert_header(verdict::HEADER, v)?;
        }
        Ok(())
    }
}

pub fn run(cfg: Config, app: App) -> ! {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut server = Server::new(None).expect("creating pingora server");
    server.bootstrap();

    let proxy = Proxy {
        app,
        upstream: Upstream {
            addr: cfg.upstream.addr.clone(),
            tls: cfg.upstream.tls,
            sni: cfg.upstream.sni.clone(),
        },
        ja4_header: cfg.network.ja4_header.to_ascii_lowercase(),
    };
    let mut service = http_proxy_service(&server.configuration, proxy);

    if let Some(addr) = &cfg.listen.plain {
        service.add_tcp(addr);
        log::warn!("plain HTTP listener on {addr}: no TLS, so no JA4; use for local testing only");
    }
    if let (Some(addr), Some(tls)) = (&cfg.listen.tls, &cfg.tls) {
        service.endpoints().set_pre_tls_callback(Arc::new(Ja4Peek));
        let mut settings = TlsSettings::intermediate(
            tls.cert.to_str().expect("cert path is utf-8"),
            tls.key.to_str().expect("key path is utf-8"),
        )
        .expect("loading TLS certificate");
        settings.enable_h2();
        service.add_tls_with_settings(addr, None, settings);
        log::info!("TLS listener on {addr}");
    }

    log::info!("mode: {:?}, upstream: {}", cfg.mode, cfg.upstream.addr);
    server.add_service(service);
    server.run_forever()
}
