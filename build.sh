#!/usr/bin/env bash
# Build the forge binary from the Go sources in this directory.
#
# The binary is rebuilt from source on every run; nothing is
# carried over as a blob. The script prints the binary size and
# the size of the whole tree (excluding .git) so the 16 MiB tree
# cap can be eyeballed at a glance.
set -euo pipefail

cd "$(dirname "$0")"

GO_BIN="$HOME/workspace/tools/go/bin/go"

CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags "-s -w" -o forge-bin .

BIN_BYTES=$(stat -c %s forge-bin)
TREE_BYTES=$(du -sb --exclude=.git . | cut -f1)

echo "built forge-bin ($BIN_BYTES bytes); tree $TREE_BYTES bytes"
