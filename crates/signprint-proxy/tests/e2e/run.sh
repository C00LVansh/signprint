#!/usr/bin/env bash
# End-to-end check of the real proxy binary: TLS termination, JA4 capture,
# enforce-mode rejection and the verdict header reaching the upstream.
# Linux/macOS only. Needs curl, openssl, python3 and jq.
set -euo pipefail

BIN=${1:-target/debug/signprint-proxy}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT
HERE=$(cd "$(dirname "$0")" && pwd)

fail() { echo "FAIL: $*" >&2; exit 1; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null

"$BIN" keygen 1 > "$WORK/keys.txt"
sed -n '/^{/,/^}/p' "$WORK/keys.txt" > "$WORK/keyring.json"
export SIGNPRINT_UPSTREAM_SECRET=$(grep '^SIGNPRINT_UPSTREAM_SECRET=' "$WORK/keys.txt" | cut -d= -f2)
export SIGNPRINT_LOG_ROOT=$(grep '^SIGNPRINT_LOG_ROOT=' "$WORK/keys.txt" | cut -d= -f2)

cat > "$WORK/signprint.toml" <<TOML
mode = "enforce"

[listen]
tls = "127.0.0.1:18443"

[tls]
cert = "$WORK/cert.pem"
key = "$WORK/key.pem"

[upstream]
addr = "127.0.0.1:18080"

[keys]
keyring = "$WORK/keyring.json"
upstream_secret_env = "SIGNPRINT_UPSTREAM_SECRET"
log_root_env = "SIGNPRINT_LOG_ROOT"

[[route]]
path_prefix = "/api/"
require = "signed"
TOML

"$BIN" check "$WORK/signprint.toml" >/dev/null || fail "config check"

python3 "$HERE/upstream.py" 18080 &
"$BIN" run "$WORK/signprint.toml" > "$WORK/proxy.log" 2>&1 &

for _ in $(seq 50); do
  curl -sk -o /dev/null https://localhost:18443/ && break
  sleep 0.2
done

CURL=(curl -sk --resolve localhost:18443:127.0.0.1)

echo "-- whoami reports a JA4 for our TLS connection"
who=$("${CURL[@]}" https://localhost:18443/.well-known/signprint/v1/whoami)
echo "$who"
echo "$who" | jq -e '.ja4 | test("^t1[23]d[0-9]{4}")' >/dev/null || fail "no ja4 in whoami"
echo "$who" | jq -e '.provenance == "direct"' >/dev/null || fail "provenance not direct"

echo "-- unsigned request to a signed route is rejected in enforce mode"
code=$("${CURL[@]}" -o "$WORK/body" -w '%{http_code}' -X POST https://localhost:18443/api/cart -d '{}')
[ "$code" = 401 ] || fail "expected 401, got $code"
jq -e '.error == "sp_required"' "$WORK/body" >/dev/null || fail "wrong error body: $(cat "$WORK/body")"

echo "-- garbage signature is malformed, not a crash"
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' https://localhost:18443/api/x \
  -H 'signature-input: sp=("@method");created=1' -H 'signature: sp=:AAAA:')
[ "$code" = 400 ] || fail "expected 400, got $code"

echo "-- unprotected route reaches the upstream with a verdict, spoofed headers stripped"
echoed=$("${CURL[@]}" https://localhost:18443/index.html -H 'signprint-verdict: v=1;act=allow;forged' -H 'x-signprint-ja4: fake')
echo "$echoed" | jq .
echo "$echoed" | jq -e '.headers["signprint-verdict"] | startswith("v=1;act=skip;mode=enforce;")' >/dev/null \
  || fail "verdict missing or client's forged one leaked through"
echo "$echoed" | jq -e '.headers["x-signprint-ja4"] == null' >/dev/null || fail "forwarded-ja4 header not stripped"

echo "-- http/2 works too"
proto=$("${CURL[@]}" --http2 -o /dev/null -w '%{http_version}' https://localhost:18443/index.html)
[ "$proto" = 2 ] || fail "expected h2, got $proto"

echo "all e2e checks passed"
