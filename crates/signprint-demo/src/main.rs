//! The app the public demo protects. It only trusts requests that carry a
//! valid signprint verdict, so it's meant to be reachable only through the
//! proxy.
//!
//! Environment:
//!   LISTEN                      address to bind (default 0.0.0.0:3000)
//!   SIGNPRINT_UPSTREAM_SECRET   the same secret the proxy signs verdicts with
//!   STATIC_DIR                  directory containing signprint.js (the client bundle)

mod board;
mod pages;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use serde::Deserialize;
use serde_json::json;
use signprint_core::verdict::{self, Action, Verdict};
use signprint_wire::b64;

use board::Board;

pub const PRODUCTS: u32 = 1000;
pub const PAGE_SIZE: u32 = 20;
const VERDICT_MAX_AGE: u64 = 30;
const POW_PASSED: u8 = 1 << 1;

struct AppState {
    upstream_key: [u8; 32],
    static_dir: PathBuf,
    board: Mutex<Board>,
}

type Shared = Arc<AppState>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the API handlers learn from a checked verdict.
#[derive(Debug, Clone)]
struct Checked {
    sid: String,
    band: u8,
    pow: bool,
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Every /api request must carry an allow verdict from the proxy, made for
/// this exact request.
async fn require_verdict(
    State(st): State<Shared>,
    mut req: Request,
    next: middleware::Next,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let rh = verdict::request_hash(
        req.method().as_str(),
        &host,
        req.uri().path(),
        req.uri().query(),
    );
    let raw = req
        .headers()
        .get(verdict::HEADER)
        .and_then(|v| v.to_str().ok());
    let checked = match Verdict::verify(raw, &st.upstream_key, &rh, now(), VERDICT_MAX_AGE) {
        Ok(v) if v.action == Action::Allow => Checked {
            sid: v.sid.map(|s| b64::encode_url(&s)).unwrap_or_default(),
            band: v.band,
            pow: v.flags & POW_PASSED != 0,
        },
        _ => {
            st.board
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .totals
                .rejected_without_verdict += 1;
            return error(
                StatusCode::FORBIDDEN,
                "no valid signprint verdict; requests have to go through the proxy",
            );
        }
    };
    req.extensions_mut().insert(checked);
    next.run(req).await
}

#[derive(Deserialize)]
struct PageQuery {
    page: Option<u32>,
}

async fn products(
    State(st): State<Shared>,
    axum::Extension(c): axum::Extension<Checked>,
    Query(q): Query<PageQuery>,
) -> Response {
    let pages = PRODUCTS / PAGE_SIZE;
    let page = q.page.unwrap_or(1).clamp(1, pages);
    let first = (page - 1) * PAGE_SIZE + 1;
    let items: Vec<_> = (first..first + PAGE_SIZE).map(pages::product).collect();

    let mut board = st.board.lock().unwrap_or_else(|p| p.into_inner());
    let s = board.session(&c.sid, c.band, c.pow, now());
    s.products += PAGE_SIZE as u64;
    s.pages.insert(page);
    board.totals.products_served += PAGE_SIZE as u64;
    if c.band >= 2 {
        board.totals.products_to_high_bands += PAGE_SIZE as u64;
    }
    drop(board);

    Json(json!({
        "page": page,
        "pages": pages,
        "items": items,
        "you": { "band": c.band, "pow": c.pow },
    }))
    .into_response()
}

#[derive(Deserialize)]
struct Login {
    user: String,
    pass: String,
}

async fn login(
    State(st): State<Shared>,
    axum::Extension(c): axum::Extension<Checked>,
    Json(body): Json<Login>,
) -> Response {
    let mut board = st.board.lock().unwrap_or_else(|p| p.into_inner());
    let s = board.session(&c.sid, c.band, c.pow, now());
    // what a real app might do with the band: let clean sessions straight
    // in, ask for more from the rest
    if c.band >= 2 {
        s.logins_blocked += 1;
        return error(
            StatusCode::FORBIDDEN,
            &format!(
                "this session looks automated (band {}); a real site would ask for a second factor here",
                c.band
            ),
        );
    }
    if body.user == "demo" && body.pass == "demo" {
        s.logins_ok += 1;
        Json(json!({ "ok": true, "band": c.band })).into_response()
    } else {
        error(
            StatusCode::UNAUTHORIZED,
            "wrong username or password (try demo / demo)",
        )
    }
}

async fn scoreboard_json(State(st): State<Shared>) -> Response {
    let board = st.board.lock().unwrap_or_else(|p| p.into_inner());
    let top: Vec<_> = board
        .top(50)
        .into_iter()
        .map(|s| {
            json!({
                "session": s.sid,
                "band": s.band,
                "pow": s.pow,
                "pages": s.pages.len(),
                "products": s.products,
                "requests": s.requests,
                "logins_ok": s.logins_ok,
                "logins_blocked": s.logins_blocked,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            })
        })
        .collect();
    let mut res = Json(
        json!({ "totals": board.totals, "sessions": top, "catalogue_pages": PRODUCTS / PAGE_SIZE }),
    )
    .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}

async fn client_bundle(State(st): State<Shared>) -> Response {
    match tokio::fs::read(st.static_dir.join("signprint.js")).await {
        Ok(body) => (
            [
                (header::CONTENT_TYPE, "text/javascript"),
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            body,
        )
            .into_response(),
        Err(_) => error(
            StatusCode::NOT_FOUND,
            "client bundle not found; set STATIC_DIR",
        ),
    }
}

fn app(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/products", get(products))
        .route("/api/login", post(login))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_verdict,
        ));
    Router::new()
        .route("/", get(|| async { Html(pages::INDEX) }))
        .route("/scoreboard", get(|| async { Html(pages::SCOREBOARD) }))
        .route("/scoreboard.json", get(scoreboard_json))
        .route("/static/signprint.js", get(client_bundle))
        .merge(api)
        .with_state(state)
}

fn upstream_key() -> Result<[u8; 32], String> {
    let v = std::env::var("SIGNPRINT_UPSTREAM_SECRET")
        .map_err(|_| "SIGNPRINT_UPSTREAM_SECRET not set")?;
    b64::decode_url(v.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| "SIGNPRINT_UPSTREAM_SECRET must be 32 bytes of base64url".into())
}

#[tokio::main]
async fn main() {
    let key = match upstream_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("signprint-demo: {e}");
            std::process::exit(1);
        }
    };
    let state = Arc::new(AppState {
        upstream_key: key,
        static_dir: std::env::var("STATIC_DIR")
            .unwrap_or_else(|_| "static".into())
            .into(),
        board: Mutex::new(Board::default()),
    });
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .expect("binding LISTEN");
    eprintln!("signprint-demo listening on {listen}");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use signprint_core::verdict::Mode;

    const KEY: [u8; 32] = [7; 32];

    fn state() -> Shared {
        Arc::new(AppState {
            upstream_key: KEY,
            static_dir: "nonexistent".into(),
            board: Mutex::new(Board::default()),
        })
    }

    fn verdict_for(method: &str, path: &str, query: Option<&str>, band: u8) -> String {
        Verdict {
            action: Action::Allow,
            mode: Mode::Enforce,
            reason: None,
            band,
            flags: 0,
            sid: Some([1, 2, 3, 4]),
            request_id: 1,
            ts: now(),
            request_hash: verdict::request_hash(method, "demo.example", path, query),
        }
        .encode(&KEY)
    }

    async fn call(req: Request<Body>) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let res = app(state()).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn api_needs_a_verdict() {
        let req = Request::get("/api/products?page=2")
            .header("host", "demo.example")
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn products_with_a_verdict() {
        let req = Request::get("/api/products?page=2")
            .header("host", "demo.example")
            .header(
                verdict::HEADER,
                verdict_for("GET", "/api/products", Some("page=2"), 0),
            )
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["page"], 2);
        assert_eq!(body["items"].as_array().unwrap().len(), PAGE_SIZE as usize);
    }

    #[tokio::test]
    async fn verdict_for_another_request_is_refused() {
        let req = Request::get("/api/products?page=3")
            .header("host", "demo.example")
            .header(
                verdict::HEADER,
                verdict_for("GET", "/api/products", Some("page=2"), 0),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(req).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn high_band_login_is_held_back() {
        let req = |band| {
            Request::post("/api/login")
                .header("host", "demo.example")
                .header("content-type", "application/json")
                .header(
                    verdict::HEADER,
                    verdict_for("POST", "/api/login", None, band),
                )
                .body(Body::from(r#"{"user":"demo","pass":"demo"}"#))
                .unwrap()
        };
        assert_eq!(call(req(0)).await.0, StatusCode::OK);
        assert_eq!(call(req(2)).await.0, StatusCode::FORBIDDEN);
    }
}
