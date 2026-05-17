#!/usr/bin/env bash
#
# Bring up a 4-validator cosmos-sdk testnet where one validator
# (node3) uses the picowallet as its remote signer.
#
# Topology (Mac side):
#   node0  p2p :26656   rpc :26657   local file signer
#   node1  p2p :26666   rpc :26667   local file signer
#   node2  p2p :26676   rpc :26677   local file signer
#   node3  p2p :26686   rpc :26687   priv_validator_laddr = tcp://0.0.0.0:26690
#                                    consensus pubkey     = picowallet's m/0'
#
# The picowallet must be built in dialer mode and flashed before running:
#
#   cmake -S firmware -B firmware/build -DCOSMOS_SC_DIAL_HOST=192.168.7.2 \
#                                       -DCOSMOS_SC_DIAL_PORT=26690
#   cmake --build firmware/build
#   # then flash firmware/build/picowallet.uf2 and boot to PrivVal mode.
#
# Prerequisites: go, git. simd is built on demand from cosmos-sdk.

set -euo pipefail

# --- Configuration ------------------------------------------------------------

# Chain ID is timestamped by default so the device's per-chain HWM (persisted
# in flash) doesn't see this run as a double-sign of an earlier one. Override
# CHAIN_ID to pin a specific name.
CHAIN_ID="${CHAIN_ID:-picowallet-testnet-$(date +%s)}"
TESTNET_DIR="${TESTNET_DIR:-$HOME/.picowallet-testnet}"

PICOWALLET_HOST="${PICOWALLET_HOST:-192.168.7.1}"
PICOWALLET_SC_PORT="${PICOWALLET_SC_PORT:-26660}"

COSMOS_SDK_PATH="${COSMOS_SDK_PATH:-/Volumes/Tendermint/cosmos-sdk}"
SIMD_BIN="${SIMD_BIN:-$COSMOS_SDK_PATH/build/simd}"
SIMD_BRANCH="${SIMD_BRANCH:-release/v0.50.x}"

# Per-node port offset. Default 28xxx so we don't clash with any other
# cometbft chain on the host (raspberry / gaiad / etc).
P2P_BASE="${P2P_BASE:-28656}"
# PRIVVAL_BASE must match what the device's dialer firmware was built with
# (COSMOS_SC_DIAL_PORT). Default 26690 matches the README's example flash.
PRIVVAL_BASE="${PRIVVAL_BASE:-26690}"
port_for() { echo $((P2P_BASE + $1 * 10 + $2)); }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[36m[testnet]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[testnet] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- Step 1: ensure simd is built --------------------------------------------

if [ ! -x "$SIMD_BIN" ]; then
    log "simd not found at $SIMD_BIN; building from cosmos-sdk source"
    if [ ! -d "$COSMOS_SDK_PATH" ]; then
        mkdir -p "$(dirname "$COSMOS_SDK_PATH")"
        log "cloning cosmos-sdk into $COSMOS_SDK_PATH"
        git clone --depth 1 --branch "$SIMD_BRANCH" \
            https://github.com/cosmos/cosmos-sdk "$COSMOS_SDK_PATH"
    fi
    (cd "$COSMOS_SDK_PATH" && make build) \
        || fail "simd build failed (try CC=gcc make build)"
fi
log "simd: $SIMD_BIN"
"$SIMD_BIN" version 2>&1 | head -1 | sed 's/^/         /'

# --- Step 2: confirm picowallet pubkey ---------------------------------------
#
# The cosmos driver is dialer-only -- the device dials cometbft, never the
# other way around -- so pwctl can't query it for the pubkey. The operator
# must supply PICOWALLET_PUBKEY_HEX via env var. Read it off the e-paper
# splash screen, or get it once from TMKMS mode via `os.pubkey ed25519 m/0'`.

[ -n "${PICOWALLET_PUBKEY_HEX:-}" ] \
    || fail "PICOWALLET_PUBKEY_HEX env var required (see scripts/README.md)"
log "picowallet pubkey: $PICOWALLET_PUBKEY_HEX"

# Cosmos pub-key JSON uses base64.
PICOWALLET_PUBKEY_B64=$(echo -n "$PICOWALLET_PUBKEY_HEX" | xxd -r -p | base64)
PICOWALLET_PUBKEY_JSON=$(printf '{"@type":"/cosmos.crypto.ed25519.PubKey","key":"%s"}' "$PICOWALLET_PUBKEY_B64")

# --- Step 3: clean state ------------------------------------------------------

log "wiping $TESTNET_DIR"
rm -rf "$TESTNET_DIR"
mkdir -p "$TESTNET_DIR/logs"

# --- Step 4: init all 4 nodes ------------------------------------------------

for i in 0 1 2 3; do
    "$SIMD_BIN" init "node$i" --chain-id "$CHAIN_ID" \
        --home "$TESTNET_DIR/node$i" \
        > "$TESTNET_DIR/logs/node$i-init.log" 2>&1
done

# --- Step 5: generate operator keys for each validator -----------------------

for i in 0 1 2 3; do
    "$SIMD_BIN" keys add validator --keyring-backend test \
        --home "$TESTNET_DIR/node$i" \
        > "$TESTNET_DIR/logs/node$i-keys.log" 2>&1
done

# --- Step 6: build node0's genesis with all 4 funded accounts ----------------

for i in 0 1 2 3; do
    ADDR=$("$SIMD_BIN" keys show validator -a --keyring-backend test \
                       --home "$TESTNET_DIR/node$i")
    "$SIMD_BIN" genesis add-genesis-account "$ADDR" 100000000000000stake \
        --home "$TESTNET_DIR/node0" \
        > /dev/null
done

# Propagate node0's seeded genesis to the others (so their gentx step works).
for i in 1 2 3; do
    cp "$TESTNET_DIR/node0/config/genesis.json" \
       "$TESTNET_DIR/node$i/config/genesis.json"
done

# --- Step 7: each node generates its gentx -----------------------------------

for i in 0 1 2; do
    "$SIMD_BIN" genesis gentx validator 1000000000stake \
        --chain-id "$CHAIN_ID" --keyring-backend test \
        --home "$TESTNET_DIR/node$i" \
        > "$TESTNET_DIR/logs/node$i-gentx.log" 2>&1
done

# Node 3: same gentx, but with the picowallet pubkey for consensus.
"$SIMD_BIN" genesis gentx validator 1000000000stake \
    --chain-id "$CHAIN_ID" --keyring-backend test \
    --pubkey "$PICOWALLET_PUBKEY_JSON" \
    --home "$TESTNET_DIR/node3" \
    > "$TESTNET_DIR/logs/node3-gentx.log" 2>&1

# --- Step 8: collect all gentxs into node0, finalize, distribute -------------

for i in 1 2 3; do
    cp "$TESTNET_DIR/node$i/config/gentx/"*.json "$TESTNET_DIR/node0/config/gentx/"
done
"$SIMD_BIN" genesis collect-gentxs --home "$TESTNET_DIR/node0" \
    > "$TESTNET_DIR/logs/collect-gentxs.log" 2>&1

for i in 1 2 3; do
    cp "$TESTNET_DIR/node0/config/genesis.json" \
       "$TESTNET_DIR/node$i/config/genesis.json"
done

# --- Step 9: rewrite each node's ports + persistent peers --------------------

for i in 0 1 2 3; do
    NODE_DIR="$TESTNET_DIR/node$i"
    P2P=$(port_for $i 0)     # +0 = p2p
    RPC=$(port_for $i 1)     # +1 = rpc
    GRPC=$((9090 + i * 10))  # cosmos gRPC
    API=$((1317 + i * 10))   # cosmos REST

    # config.toml: cometbft ports + loopback-friendly P2P settings.
    # On a single-host testnet all peers share 127.0.0.1, which cometbft
    # rejects by default (`allow_duplicate_ip = false`) and treats as a
    # non-routable address (`addr_book_strict = true`). Flip both off.
    sed -i.bak \
        -e "s|^laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://127.0.0.1:$RPC\"|" \
        -e "s|^laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://0.0.0.0:$P2P\"|" \
        -e "s|^prometheus_listen_addr = \":26660\"|prometheus_listen_addr = \":$((26660 + i*10))\"|" \
        -e "s|^allow_duplicate_ip = false|allow_duplicate_ip = true|" \
        -e "s|^addr_book_strict = true|addr_book_strict = false|" \
        "$NODE_DIR/config/config.toml"

    # app.toml: cosmos-sdk gRPC + REST
    sed -i.bak \
        -e "s|^address = \"tcp://localhost:1317\"|address = \"tcp://localhost:$API\"|" \
        -e "s|^address = \"localhost:9090\"|address = \"localhost:$GRPC\"|" \
        -e "s|^address = \"localhost:9091\"|address = \"localhost:$((GRPC + 1))\"|" \
        "$NODE_DIR/config/app.toml"
done

# Compute persistent_peers (after ports are set, so node IDs reflect node_key.json)
PEERS=""
for i in 0 1 2 3; do
    NODE_ID=$("$SIMD_BIN" cometbft show-node-id --home "$TESTNET_DIR/node$i")
    [ -n "$PEERS" ] && PEERS="$PEERS,"
    PEERS="$PEERS$NODE_ID@127.0.0.1:$(port_for $i 0)"
done
for i in 0 1 2 3; do
    # Unconditional replace -- `simd genesis collect-gentxs` populates
    # persistent_peers using each gentx's auto-detected --ip (the Mac's LAN
    # IP) on the default :26656 port, which is wrong for our local-loopback
    # testnet. Match any pre-existing value.
    sed -i.bak \
        "s|^persistent_peers = .*|persistent_peers = \"$PEERS\"|" \
        "$TESTNET_DIR/node$i/config/config.toml"
done

# --- Step 10: node 3 -> remote signer ---------------------------------------

sed -i.bak \
    "s|^priv_validator_laddr = \"\"|priv_validator_laddr = \"tcp://0.0.0.0:$PRIVVAL_BASE\"|" \
    "$TESTNET_DIR/node3/config/config.toml"

# --- Step 11: optionally launch the picowallet bridge -----------------------
#
# Default: the device runs in dialer-mode firmware and connects to cometbft
# directly, so no bridge is needed.
#
# Fallback: if the device is running listener-mode firmware (both ends are
# servers), set USE_BRIDGE=1 to launch scripts/picowallet-bridge.py, which
# dials both endpoints and pipes bytes between them. The bridge keeps
# retrying cometbft until node3 is up -- which gets us under cometbft's
# 3-second accept timeout for the signer.

if [ "${USE_BRIDGE:-0}" = "1" ]; then
    log "starting picowallet <-> cometbft bridge (USE_BRIDGE=1)"
    python3 "$REPO_ROOT/scripts/picowallet-bridge.py" \
            --cometbft-host 127.0.0.1 --cometbft-port "$PRIVVAL_BASE" \
            --picowallet-host "$PICOWALLET_HOST" --picowallet-port "$PICOWALLET_SC_PORT" \
            > "$TESTNET_DIR/logs/bridge.log" 2>&1 &
    echo "$!" > "$TESTNET_DIR/bridge.pid"
fi

log "starting 4 cometbft nodes; logs in $TESTNET_DIR/logs/"
for i in 0 1 2 3; do
    NODE_DIR="$TESTNET_DIR/node$i"
    "$SIMD_BIN" start --home "$NODE_DIR" \
        > "$TESTNET_DIR/logs/node$i.log" 2>&1 &
    echo "$!" > "$TESTNET_DIR/node$i.pid"
done
sleep 1

log "Testnet up. Useful commands:"
echo
echo "  tail -f $TESTNET_DIR/logs/node0.log    # follow node0 (local signer)"
echo "  tail -f $TESTNET_DIR/logs/node3.log    # follow node3 (picowallet signer)"
echo
echo "  curl -s http://127.0.0.1:$(port_for 0 1)/status | jq .result.sync_info"
echo "                                                 # check tip + sync status"
echo
echo "  scripts/testnet-stop.sh                        # stop the testnet"
echo
echo "Node 3 is listening for the picowallet remote signer on tcp://0.0.0.0:$PRIVVAL_BASE."
echo "If the device is in PrivVal mode + dialer build, it should connect within"
echo "a few seconds and node3 will start producing blocks alongside the others."
