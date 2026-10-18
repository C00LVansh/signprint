# signprint

Self-hosted bot protection for websites and APIs. Every request to a protected route has to prove it came from a real, consistent browser session.

The rough idea:

1. When a user starts a protected action (login, signup, checkout…), the page fetches a fresh challenge from the server.
2. The browser answers it: a server-chosen canvas drawing, a few generated probes, sometimes a small proof of work.
3. If the answers line up, the server and browser agree on a short-lived session key over ECDH. The key is non-extractable, so page scripts never see it.
4. From then on, every API call is signed (RFC 9421 HTTP Message Signatures), and a Pingora-based proxy checks the signature before the request reaches your backend.

Reverse-engineering the client doesn't help much, because the key that matters only exists after the server hands out a fresh challenge, and it expires in minutes.

## Status

Early. The wire format, the TS signer and the proxy's verification path work and are tested end to end, but there's no session issuance yet, so nothing can actually get a session. That's next.

- [x] `signprint-wire`: token/challenge formats, RFC 9421 profile, test vectors
- [x] TypeScript signer (`client/`), tested against the same vectors and in Chromium/Firefox/WebKit
- [x] Pingora proxy: TLS, JA4 capture, signed-request verification, verdict header, observe/enforce
- [ ] proxy: TLS cert reload, Redis store for multiple instances
- [ ] session issuance + scoring
- [ ] canvas challenge
- [ ] Argon2id fallback
- [ ] demo you can try to break

## Layout

```
crates/        Rust workspace (wire formats, core verification, JA4, proxy)
client/        browser client (TypeScript)
testvectors/   shared vectors the Rust and TS sides both test against
```

## Running the proxy

Linux or macOS (Pingora doesn't support Windows).

```sh
cargo build --release -p signprint-proxy
./target/release/signprint-proxy keygen > keys.txt     # keyring + two secrets
cp crates/signprint-proxy/signprint.example.toml signprint.toml   # edit paths and routes
./target/release/signprint-proxy check signprint.toml
./target/release/signprint-proxy run signprint.toml
```

`GET /.well-known/signprint/v1/whoami` shows the JA4 the proxy sees for your connection, which is a quick way to check nothing in front of it is terminating TLS.

Your app receives a `signprint-verdict` header on every proxied request. Check it with `signprint_core::verdict::Verdict::verify` and treat a missing or invalid one as a failure; the app should only be reachable through the proxy.

## Development

```sh
cargo test --workspace

cd client
npm ci
npm test               # node, against testvectors/
npm run test:browser   # chromium, firefox, webkit (npx playwright install first)

# linux/macos: real binary, TLS, curl
cargo build -p signprint-proxy && crates/signprint-proxy/tests/e2e/run.sh
```

## License

Apache-2.0
