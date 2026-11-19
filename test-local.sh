#!/usr/bin/env bash
# Local end-to-end check for the forge.
#
# Builds the binary, boots it on an ephemeral port, runs the kit's
# conformance suite (with the benchmark workloads) against it, and
# prints the score columns. Exits 0 only when all 120 checks pass.
#
# The viewer login is read from the kit's scenario BEFORE the server
# starts, because the server needs its token at boot and the token
# IS the viewer login (contract section 1): the same value is both
# MAKEFUN_SHOP_TOKEN for the forge and --token for the suite.
set -euo pipefail

cd "$(dirname "$0")"

NODE_BIN="$HOME/workspace/tools/node-v22.21.0-linux-x64/bin/node"
KIT="$HOME/workspace/makefun/kits/github-core-clone-01-kit-new/github-core-clone-01-kit"

# Build first; a failed build stops the script here.
./build.sh

LOGIN=$("$NODE_BIN" --experimental-strip-types -e "import('$KIT/sdk/conformance/wire.ts').then((m) => console.log(m.buildScenario().viewer.login))")
if [[ -z "$LOGIN" ]]; then
  echo "could not read the viewer login from the kit scenario" >&2
  exit 1
fi

WORK=$(mktemp -d)
SERVER_LOG="$WORK/forge.log"
RESULT_JSON="$WORK/result.json"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

MAKEFUN_SHOP_TOKEN="$LOGIN" ./forge-bin > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait up to 10 s for the forge to print its PORT= line.
PORT=""
DEADLINE=$((SECONDS + 10))
while [[ -z "$PORT" ]]; do
  if [[ -s "$SERVER_LOG" ]] && grep -q '^PORT=[0-9][0-9]*$' "$SERVER_LOG"; then
    PORT=$(grep -o '^PORT=[0-9][0-9]*$' "$SERVER_LOG" | head -n 1 | cut -d= -f2)
  fi
  if [[ -n "$PORT" ]]; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "forge-bin exited before printing PORT=; its log:" >&2
    cat "$SERVER_LOG" >&2
    exit 1
  fi
  if [[ $SECONDS -ge $DEADLINE ]]; then
    echo "timed out after 10 s waiting for PORT=; the forge log:" >&2
    cat "$SERVER_LOG" >&2
    exit 1
  fi
  sleep 0.1
done

echo "forge up on port $PORT (login $LOGIN)"

"$NODE_BIN" --experimental-strip-types "$KIT/sdk/run.ts" \
  --url "http://127.0.0.1:$PORT" \
  --token "$LOGIN" --perf --json \
  > "$RESULT_JSON" 2> "$WORK/run.stderr" || true

if ! SUMMARY=$("$NODE_BIN" -e 'const fs = require("node:fs"); const run = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); const c = run.columns; console.log(`checks: ${run.counts.passed}/${run.counts.manifest_total} passed; feature ${c.feature}; agent ${c.agent}; perf ${c.perf}; score ${c.score}; working ${c.working}`); if (run.perf && Array.isArray(run.perf.workloads)) { for (const w of run.perf.workloads) console.log(`benchmark ${w.name}: p50 ${w.p50_ms} ms`); } else { console.log("benchmark: not run"); } console.log(`PASSED=${run.counts.passed}`);' "$RESULT_JSON" 2> "$WORK/summary.stderr"); then
  echo "could not read the suite result as JSON:" >&2
  cat "$WORK/summary.stderr" >&2
  echo "--- suite stderr ---" >&2
  cat "$WORK/run.stderr" >&2
  exit 1
fi

printf '%s\n' "$SUMMARY" | grep -v '^PASSED=' || true
PASSED=$(printf '%s\n' "$SUMMARY" | sed -n 's/^PASSED=//p')

if [[ "$PASSED" -eq 120 ]]; then
  exit 0
fi
echo "test-local: $PASSED/120 checks passed (need 120)" >&2
exit 1
