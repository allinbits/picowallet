#!/usr/bin/env bash
#
# Bring up a 4-validator gnoland testnet where node3's consensus signer is
# the picowallet. The other three nodes use ordinary file-backed keys.
#
# Topology:
#
#   ┌──────────────┐                        ┌──────────────┐
#   │ gnoland 0    │                        │ gnoland 1    │
#   │ p2p :29656   │ <─── persistent ────>  │ p2p :29666   │
#   │ rpc :29657   │       peers mesh       │ rpc :29667   │
#   └──────────────┘                        └──────────────┘
#                       ▲              ▲
#                       │              │
#                       v              v
#   ┌──────────────┐                        ┌──────────────┐
#   │ gnoland 2    │                        │ gnoland 3    │  TCP + SC (HKDF/amino)
#   │ p2p :29676   │ <─── persistent ────>  │ p2p :29686   │ <─────────────────────┐
#   │ rpc :29677   │                        │ rpc :29687   │                       v
#   └──────────────┘                        └──────────────┘             ┌─────────────────┐
#                                                                         │ picowallet      │
#                                                                         │ listener mode   │
#                                                                         │ :26659          │
#                                                                         └─────────────────┘
#
# Polarity: gnoland's validator DIALS the signer (opposite of cometbft). So the
# device's existing listener-mode firmware (default build, no extra flags)
# works as-is. The same firmware can also do cosmos-style outbound dialing,
# so a single dialer-flashed firmware handles cosmos + gno simultaneously.
#
# Why 4 validators: parity with the cosmos testnet. gnoland has no built-in
# multi-validator init flow (no `gentx` / `collect-gentxs` equivalent), so we
# initialize each node's secrets separately, hand-assemble a genesis.json
# containing all four validator pubkeys, and distribute it.
#
# Prerequisites:
#   * gnoland built from /Volumes/Tendermint/gnolang/gno master.
#   * picowallet flashed and booted to PrivVal mode.
#   * Device-side TMKMS REPL: os.chain.wipe + os.hwm.wipe, then
#     os.gno.chain.add <label> <chain_id> <port> [<pubkey_hex>] for this run.

set -euo pipefail

# --- Configuration ----------------------------------------------------------

CHAIN_ID="${CHAIN_ID:-picowallet-gno-$(date +%s)}"
TESTNET_DIR="${TESTNET_DIR:-$HOME/.picowallet-gno-testnet}"

PICOWALLET_HOST="${PICOWALLET_HOST:-192.168.7.1}"
PICOWALLET_GNO_PORT="${PICOWALLET_GNO_PORT:-26659}"

GNOLAND_BIN="${GNOLAND_BIN:-$HOME/go/bin/gnoland}"
GNOROOT_DIR="${GNOROOT_DIR:-/Volumes/Tendermint/gnolang/gno}"

# Per-node port offset.
P2P_BASE="${P2P_BASE:-29656}"
RPC_BASE="${RPC_BASE:-29657}"
p2p_port() { echo $((P2P_BASE + $1 * 10)); }
rpc_port() { echo $((RPC_BASE + $1 * 10)); }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[36m[gno-testnet]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[gno-testnet] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- Step 1: prereqs --------------------------------------------------------

[ -x "$GNOLAND_BIN" ] || fail "gnoland binary not found at $GNOLAND_BIN -- set GNOLAND_BIN=..."
[ -n "${PICOWALLET_PUBKEY_HEX:-}" ] || \
    fail "set PICOWALLET_PUBKEY_HEX=<64-hex-chars> (device's m/0' Ed25519 pubkey)"

log "chain id: $CHAIN_ID"
log "testnet dir: $TESTNET_DIR"
log "picowallet pubkey: $PICOWALLET_PUBKEY_HEX"

PICOWALLET_PUBKEY_B64=$(echo -n "$PICOWALLET_PUBKEY_HEX" | xxd -r -p | base64)

# --- Step 2: clean state + init per-node secrets ----------------------------

log "wiping $TESTNET_DIR"
rm -rf "$TESTNET_DIR"
mkdir -p "$TESTNET_DIR/logs"
touch "$TESTNET_DIR/empty-txs.jsonl"

for i in 0 1 2 3; do
    NODE_DIR="$TESTNET_DIR/node$i"
    mkdir -p "$NODE_DIR/data/config" "$NODE_DIR/data/secrets"

    "$GNOLAND_BIN" secrets init \
        -data-dir "$NODE_DIR/data/secrets" \
        > "$TESTNET_DIR/logs/node$i-secrets.log" 2>&1
    "$GNOLAND_BIN" config init \
        -config-path "$NODE_DIR/data/config/config.toml" \
        > "$TESTNET_DIR/logs/node$i-config.log" 2>&1
done

# --- Step 3: bootstrap a template genesis via node0's lazy init --------------
#
# We need gnoland's app_state (balances, params, ...) which is too complex to
# hand-roll. Easiest: run `start -lazy` briefly against node0 to get a
# default genesis, then patch in the 4 validators.

log "bootstrapping template genesis (via node0 -lazy)"
"$GNOLAND_BIN" start -lazy \
    -data-dir "$TESTNET_DIR/node0/data" \
    -genesis "$TESTNET_DIR/template-genesis.json" \
    -genesis-txs-file "$TESTNET_DIR/empty-txs.jsonl" \
    -gnoroot-dir "$GNOROOT_DIR" \
    -chainid "$CHAIN_ID" \
    -skip-failing-genesis-txs=true \
    -skip-genesis-sig-verification=true \
    > "$TESTNET_DIR/logs/bootstrap.log" 2>&1 &
BOOT_PID=$!
for _ in $(seq 1 30); do
    [ -f "$TESTNET_DIR/template-genesis.json" ] && break
    sleep 0.2
done
sleep 1
kill "$BOOT_PID" 2>/dev/null || true
wait "$BOOT_PID" 2>/dev/null || true
[ -f "$TESTNET_DIR/template-genesis.json" ] || fail "bootstrap didn't produce template-genesis.json"

# --- Step 4: collect all 4 validator pubkeys --------------------------------

declare -a PUBKEYS
for i in 0 1 2 3; do
    PUBKEYS[$i]=$(jq -r '.pub_key.value' "$TESTNET_DIR/node$i/data/secrets/priv_validator_key.json")
done
# Node 3 uses the picowallet's pubkey (override local).
PUBKEYS[3]="$PICOWALLET_PUBKEY_B64"

log "validator pubkeys (base64):"
for i in 0 1 2 3; do
    log "  node$i: ${PUBKEYS[$i]}"
done

# --- Step 5: build the 4-validator genesis ---------------------------------

log "assembling 4-validator genesis"
jq --arg pk0 "${PUBKEYS[0]}" \
   --arg pk1 "${PUBKEYS[1]}" \
   --arg pk2 "${PUBKEYS[2]}" \
   --arg pk3 "${PUBKEYS[3]}" \
   '.validators = [
        {address:"", pub_key:{"@type":"/tm.PubKeyEd25519", value:$pk0}, power:"10", name:"node0"},
        {address:"", pub_key:{"@type":"/tm.PubKeyEd25519", value:$pk1}, power:"10", name:"node1"},
        {address:"", pub_key:{"@type":"/tm.PubKeyEd25519", value:$pk2}, power:"10", name:"node2"},
        {address:"", pub_key:{"@type":"/tm.PubKeyEd25519", value:$pk3}, power:"10", name:"node3"}
    ]' \
   "$TESTNET_DIR/template-genesis.json" > "$TESTNET_DIR/genesis.json"

# Distribute the same genesis to every node.
for i in 0 1 2 3; do
    cp "$TESTNET_DIR/genesis.json" "$TESTNET_DIR/node$i/data/genesis.json"
done

# --- Step 6: collect node IDs for persistent_peers --------------------------

declare -a NODE_IDS
for i in 0 1 2 3; do
    # gno node IDs are bech32 ("g1...") -- the secrets-get JSON-encodes
    # the string with surrounding quotes, so strip them.
    NODE_IDS[$i]=$("$GNOLAND_BIN" secrets get node_id.id \
        -data-dir "$TESTNET_DIR/node$i/data/secrets" 2>/dev/null |
        tr -d '"' | head -c 256)
    [ -n "${NODE_IDS[$i]}" ] || fail "couldn't read node$i ID"
done

PEERS=""
for i in 0 1 2 3; do
    [ -n "$PEERS" ] && PEERS="$PEERS,"
    PEERS="$PEERS${NODE_IDS[$i]}@127.0.0.1:$(p2p_port $i)"
done

log "persistent peers: $PEERS"

# --- Step 7: rewrite each config.toml ---------------------------------------

for i in 0 1 2 3; do
    NODE_DIR="$TESTNET_DIR/node$i"
    P2P=$(p2p_port $i)
    RPC=$(rpc_port $i)

    sed -i.bak \
        -e "s|tcp://0.0.0.0:26656|tcp://0.0.0.0:$P2P|" \
        -e "s|tcp://127.0.0.1:26657|tcp://127.0.0.1:$RPC|" \
        -e "s|^persistent_peers = .*|persistent_peers = \"$PEERS\"|" \
        -e "s|^allow_duplicate_ip = false|allow_duplicate_ip = true|" \
        -e "s|^addr_book_strict = true|addr_book_strict = false|" \
        "$NODE_DIR/data/config/config.toml"
done

# Node 3 only: point at the picowallet for signing.
sed -i.bak \
    -e "s|server_address = \"\"|server_address = \"tcp://$PICOWALLET_HOST:$PICOWALLET_GNO_PORT\"|" \
    "$TESTNET_DIR/node3/data/config/config.toml"

# Clear stale state left by node0's bootstrap pass.
rm -rf "$TESTNET_DIR/node0/data/wal" "$TESTNET_DIR/node0/data/db"
for i in 0 1 2 3; do
    echo '{"height":"0","round":"0","step":0}' \
        > "$TESTNET_DIR/node$i/data/secrets/priv_validator_state.json"
done

# --- Step 8: launch all 4 ---------------------------------------------------

log "launching 4 gnoland nodes"
for i in 0 1 2 3; do
    NODE_DIR="$TESTNET_DIR/node$i"
    "$GNOLAND_BIN" start \
        -data-dir "$NODE_DIR/data" \
        -genesis "$NODE_DIR/data/genesis.json" \
        -genesis-txs-file "$TESTNET_DIR/empty-txs.jsonl" \
        -gnoroot-dir "$GNOROOT_DIR" \
        -chainid "$CHAIN_ID" \
        -skip-failing-genesis-txs=true \
        -skip-genesis-sig-verification=true \
        > "$TESTNET_DIR/logs/node$i.log" 2>&1 &
    echo "$!" > "$TESTNET_DIR/node$i.pid"
done
sleep 1

log "gnoland testnet up. Useful commands:"
echo
echo "  tail -f $TESTNET_DIR/logs/node0.log"
echo "  curl -s http://127.0.0.1:$(rpc_port 0)/status | jq .result.sync_info"
echo "  curl -s 'http://127.0.0.1:$(rpc_port 0)/block?height=5' \\"
echo "    | jq '.result.block.last_commit.precommits | length'"
echo
echo "  scripts/gno_testnet-stop.sh"
