#!/usr/bin/env bash
# Real browsers against the real proxy: each engine loads a page through the
# proxy, runs the challenge, gets a session and makes signed API calls.
# Needs the client built (npm run build in client/) and playwright browsers.
source "$(dirname "$0")/lib.sh"
[ $# -gt 0 ] && BIN=$1
start_stack enforce
cd "$REPO/client"
npx playwright test -c playwright.e2e.config.ts

# each engine calibrated itself and then attested again; its canvas answer
# should have matched its own calibration
matches=$(grep -c 'core.canvas_match' "$WORK/proxy.log" || true)
echo "canvas matches after calibration: $matches"
[ "$matches" -ge 3 ] || fail "expected a calibrated canvas match from each engine"

# WebGL is judged against the GPU each browser reports; at least one engine
# in CI has working WebGL
gl=$(grep -c 'core.webgl_match' "$WORK/proxy.log" || true)
echo "webgl matches after calibration: $gl"
[ "$gl" -ge 1 ] || fail "expected a calibrated webgl match"
