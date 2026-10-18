# Shared setup for the e2e scripts: keys, a self-signed cert, the echo
# upstream and the proxy itself. Source it, then call start_stack <mode>.
set -euo pipefail

E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$E2E_DIR/../../../.." && pwd)
BIN=${BIN:-$REPO/target/debug/signprint-proxy}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; [ -f "$WORK/proxy.log" ] && tail -20 "$WORK/proxy.log" >&2; exit 1; }

start_stack() {
  local mode=$1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" 2>/dev/null

  "$BIN" keygen 1 > "$WORK/keys.txt"
  sed -n '/^{/,/^}/p' "$WORK/keys.txt" > "$WORK/keyring.json"
  export SIGNPRINT_UPSTREAM_SECRET=$(grep '^SIGNPRINT_UPSTREAM_SECRET=' "$WORK/keys.txt" | cut -d= -f2)
  export SIGNPRINT_LOG_ROOT=$(grep '^SIGNPRINT_LOG_ROOT=' "$WORK/keys.txt" | cut -d= -f2)

  cat > "$WORK/signprint.toml" <<TOML
mode = "$mode"

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
  python3 "$E2E_DIR/upstream.py" 18080 "$REPO/client/dist" &
  "$BIN" run "$WORK/signprint.toml" > "$WORK/proxy.log" 2>&1 &

  for _ in $(seq 50); do
    curl -sk -o /dev/null https://localhost:18443/ && return 0
    sleep 0.2
  done
  fail "proxy didn't come up"
}
