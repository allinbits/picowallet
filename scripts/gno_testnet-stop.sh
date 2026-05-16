#!/usr/bin/env bash
# Stop the gno testnet brought up by scripts/gno_testnet.sh.
set -euo pipefail
TESTNET_DIR="${TESTNET_DIR:-$HOME/.picowallet-gno-testnet}"

for pidfile in "$TESTNET_DIR"/gnoland.pid; do
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" && echo "stopped pid $pid ($(basename "$pidfile"))"
    else
        echo "stale: pid $pid ($(basename "$pidfile")) -- already dead"
    fi
    rm -f "$pidfile"
done
