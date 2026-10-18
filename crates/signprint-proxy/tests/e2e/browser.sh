#!/usr/bin/env bash
# Real browsers against the real proxy: each engine loads a page through the
# proxy, runs the challenge, gets a session and makes signed API calls.
# Needs the client built (npm run build in client/) and playwright browsers.
source "$(dirname "$0")/lib.sh"
[ $# -gt 0 ] && BIN=$1
start_stack enforce
cd "$REPO/client"
npx playwright test -c playwright.e2e.config.ts
