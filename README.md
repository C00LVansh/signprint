# signprint

Self-hosted bot protection for websites and APIs. Every request to a protected route has to prove it came from a real, consistent browser session.

The rough idea:

1. When a user starts a protected action (login, signup, checkout…), the page fetches a fresh challenge from the server.
2. The browser answers it: a server-chosen canvas drawing, a few generated probes, sometimes a small proof of work.
3. If the answers line up, the server and browser agree on a short-lived session key over ECDH. The key is non-extractable, so page scripts never see it.
4. From then on, every API call is signed (RFC 9421 HTTP Message Signatures), and a Pingora-based proxy checks the signature before the request reaches your backend.

Reverse-engineering the client doesn't help much, because the key that matters only exists after the server hands out a fresh challenge, and it expires in minutes.

## Status

Early, but the core loop works: a browser can get a session from the proxy and make signed requests, and CI runs that end to end in Chromium, Firefox and WebKit against the real proxy binary. Sessions are scored with rule packs and carry a band (0 to 3) into every verdict; high bands have to earn their session with an Argon2id proof of work, and the canvas challenge checks a browser renders like the device it claims to be. The public demo is next.

- [x] `signprint-wire`: token/challenge formats, RFC 9421 profile, test vectors
- [x] TypeScript signer (`client/`), tested against the same vectors and in Chromium/Firefox/WebKit
- [x] Pingora proxy: TLS, JA4 capture, signed-request verification, verdict header, observe/enforce
- [ ] proxy: TLS cert reload, Redis store for multiple instances
- [x] session issuance: challenge, per-challenge probe program, ECDH attestation, `SignprintClient`
- [x] session refresh with a mid-session fingerprint re-check; sessions persist across page loads
- [x] scoring with rule packs (`rulepacks/core` is built in)
- [x] canvas challenge: known-answer noise check, Picasso-style render, calibration
- [x] Argon2id proof-of-work step-up for high bands
- [ ] demo you can try to break

## Layout

```
crates/        Rust workspace (wire formats, verification, rules, JA4, proxy)
rulepacks/     the public core rule pack
client/        browser client (TypeScript)
testvectors/   shared vectors the Rust and TS sides both test against
```

## Using it from the browser

```js
import { SignprintClient } from "@signprint/client";
// or, without a bundler: import { SignprintClient } from "/path/to/signprint.js";

const sp = new SignprintClient();
const res = await sp.fetch("/api/cart", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ qty: 1 }),
});
```

The first protected call runs the challenge (or call `sp.ready()` yourself, e.g. when a login form gets focus). After that, requests are signed with the session key.

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

### Scoring

Each attestation is scored by the loaded rule packs and the session gets a band: 0 (clean), 1, 2 or 3. The band is in every verdict, so your app decides what to do with it, e.g. extra verification on login for band 2 and up. The public `core` pack is built in; add your own:

```toml
[rules]
packs = ["/etc/signprint/my-rules.toml"]
bands = [0, 30, 70]   # score upper bounds for bands 0, 1, 2
```

Rules are a few lines of TOML each; see `rulepacks/core/core.toml` for the format.

### Canvas challenge

Every challenge asks the browser to draw a seeded scene (curves, text, gradients, shadows) and a simple known-answer pattern. Different browser, OS and GPU stacks draw the scene slightly differently, so the answer says something about what the device really is, and a seed from your own private pool can't be precomputed.

Answers are compared with ones from **calibrated** devices: real machines you trust that you run the calibration on. Until a class (engine, major version, OS) has enough calibrated devices, its answers aren't judged. The known-answer pattern works without calibration and catches canvas noise injection.

```toml
[canvas]
kb_path = "/var/lib/signprint/canvas.json"
min_devices = 3
calibrate_token_env = "SIGNPRINT_CALIBRATE"
```

Then, on each device you want to calibrate, open your site and run in the console:

```js
await new SignprintClient().calibrate("<the token>")
```

The answer database is built from your own devices on purpose: learning it from live traffic would let a bot farm teach it its own answers.

### Proof of work

Sessions at band 2 or above get an Argon2id puzzle before their session (about a second of browser time at band 2, a few seconds at band 3, on a desktop). It doesn't detect anything, it just makes each suspicious session cost something. Tune or turn it off:

```toml
[pow]
enabled = true
stepup_band = 2
memory_kib = 16384
bits = [4, 6]   # difficulty for band 2 and band 3
```

Pass `onPowProgress` to `SignprintClient` if you want to show a progress bar while it runs.

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
