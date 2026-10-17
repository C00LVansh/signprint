# signprint

Self-hosted bot protection for websites and APIs. Every request to a protected route has to prove it came from a real, consistent browser session.

The rough idea:

1. When a user starts a protected action (login, signup, checkout…), the page fetches a fresh challenge from the server.
2. The browser answers it: a server-chosen canvas drawing, a few generated probes, sometimes a small proof of work.
3. If the answers line up, the server and browser agree on a short-lived session key over ECDH. The key is non-extractable, so page scripts never see it.
4. From then on, every API call is signed (RFC 9421 HTTP Message Signatures), and a Pingora-based proxy checks the signature before the request reaches your backend.

Reverse-engineering the client doesn't help much, because the key that matters only exists after the server hands out a fresh challenge, and it expires in minutes.

## Status

Very early. Nothing here is usable yet. The wire format and signer are in; the proxy is next.

- [x] `signprint-wire`: token/challenge formats, RFC 9421 profile, test vectors
- [x] TypeScript signer (`client/`), tested against the same vectors and in Chromium/Firefox/WebKit
- [ ] Pingora proxy
- [ ] session issuance + scoring
- [ ] canvas challenge
- [ ] Argon2id fallback
- [ ] demo you can try to break

## Layout

```
crates/        Rust workspace
client/        browser client (TypeScript)
testvectors/   shared vectors the Rust and TS sides both test against
```

## Development

```sh
cargo test --workspace

cd client
npm ci
npm test               # node, against testvectors/
npm run test:browser   # chromium, firefox, webkit (npx playwright install first)
```

## License

Apache-2.0
