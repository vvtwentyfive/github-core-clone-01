#!/bin/sh
# Build the binary, start it, run the kit conformance suite against it, and
# print the score columns. The server is always killed on exit.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
KIT_DIR="${KIT_DIR:-$HOME/workspace/makefun/kits/github-core-clone-01-kit}"
NODE_BIN="${NODE_BIN:-$HOME/workspace/tools/node-v22.21.0-linux-x64/bin}"

"$ROOT/build.sh"

LOG="$(mktemp)"
RESULT="$(mktemp)"
SUITE_ERR="$(mktemp)"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$LOG" "$RESULT" "$SUITE_ERR"
}
trap cleanup EXIT INT TERM

MAKEFUN_SHOP_TOKEN=test-token "$ROOT/forge-bin" >"$LOG" 2>&1 &
SERVER_PID=$!

# Wait for the PORT= startup line (up to 10 s).
PORT=""
i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^PORT=' "$LOG" 2>/dev/null; then
    PORT="$(sed -n 's/^PORT=//p' "$LOG" | head -n1)"
    break
  fi
  sleep 0.1
  i=$((i + 1))
done
if [ -z "$PORT" ]; then
  echo "test-local.sh: server did not print PORT=" >&2
  cat "$LOG" >&2
  exit 1
fi

# Wait for /healthz (up to 5 s).
i=0
while [ "$i" -lt 50 ]; do
  if "$NODE_BIN/node" -e "fetch('http://127.0.0.1:$PORT/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then
    break
  fi
  sleep 0.1
  i=$((i + 1))
done

NODE_VERSION="$("$NODE_BIN/node" --version)"
if [ "$NODE_VERSION" != "v22.21.0" ]; then
  echo "test-local.sh: expected node v22.21.0, got $NODE_VERSION" >&2
  exit 1
fi

cd "$KIT_DIR"
set +e
PATH="$NODE_BIN:$PATH" node --experimental-strip-types sdk/run.ts \
  --url "http://127.0.0.1:$PORT" --token test-token --json >"$RESULT" 2>"$SUITE_ERR"
RC=$?
set -e

# Print the columns line from the JSON result (fall back to raw output).
"$NODE_BIN/node" -e "
const fs = require('node:fs');
const raw = fs.readFileSync(process.argv[1], 'utf8');
const start = raw.indexOf('{');
try {
  const r = JSON.parse(start >= 0 ? raw.slice(start) : raw);
  const cols = r.columns || r.scores || r;
  const passed = r.counts?.passed ?? r.passed ?? cols.passed;
  const total = r.counts?.registered ?? r.counts?.total ?? r.total ?? cols.total;
  console.log('checks: ' + passed + '/' + total + ' passed; feature ' + cols.feature + '; agent ' + cols.agent + '; perf ' + cols.perf + '; score ' + cols.score + '; working ' + cols.working);
} catch {
  console.log(raw);
}
" "$RESULT"
if [ "$RC" -ne 0 ]; then
  echo '--- suite stderr ---' >&2
  cat "$SUITE_ERR" >&2
fi

exit "$RC"
