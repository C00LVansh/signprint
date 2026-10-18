#!/usr/bin/env bash
# End-to-end check of the real proxy binary: TLS termination, JA4 capture,
# enforce-mode rejection and the verdict header reaching the upstream.
# Linux/macOS only. Needs curl, openssl, python3 and jq.
source "$(dirname "$0")/lib.sh"
[ $# -gt 0 ] && BIN=$1
start_stack enforce

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
