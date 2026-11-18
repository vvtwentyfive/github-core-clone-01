#!/bin/sh
# Build the static forge binary into ./forge-bin and enforce the size caps:
# at most 8 MiB for the binary, at most 16 MiB for the whole tree.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [ -x "$HOME/workspace/tools/go/bin/go" ]; then
  GO="$HOME/workspace/tools/go/bin/go"
else
  GO="go"
fi
"$GO" version

export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
"$GO" build -trimpath -ldflags "-s -w" -o forge-bin .

BIN_SIZE="$(stat -c%s forge-bin)"
if [ "$BIN_SIZE" -gt 8388608 ]; then
  echo "build.sh: forge-bin is $BIN_SIZE bytes, over the 8 MiB cap" >&2
  exit 1
fi

TREE_SIZE="$(find . -path ./.git -prune -o -type f -print0 | xargs -0 stat -c%s | awk '{s+=$1} END {print s+0}')"
if [ "$TREE_SIZE" -gt 16777216 ]; then
  echo "build.sh: tree is $TREE_SIZE bytes, over the 16 MiB cap" >&2
  exit 1
fi

echo "built forge-bin ($BIN_SIZE bytes); tree $TREE_SIZE bytes"
