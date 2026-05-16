#!/usr/bin/env bash
#
# Bring up a single-validator gnoland testnet where the validator is signed
# by the picowallet via gno's remote-signer client.
#
# Topology:
#
#   ┌──────────────┐  TCP + SecretConnection (HKDF/amino)  ┌──────────────────┐
#   │ gnoland      │ ──────────────────────────────────>   │ picowallet       │
#   │ p2p :29656   │     remote_signer.server_address      │ (Pico 2)         │
#   │ rpc :29657   │   = tcp://192.168.7.1:26659           │ listener mode    │
#   └──────────────┘                                       │ via USB-Ethernet │
#                                                          └──────────────────┘
#
# Polarity: gno's validator DIALS the signer (opposite of cometbft). So the
# device's existing listener-mode firmware (default build, no extra flags)
# works as-is -- no firmware reflash needed between cosmos and gno tests.
#
# Why one validator: gno's tooling has no built-in multi-validator init flow
# (no `gentx` / `collect-gentxs` equivalent), and a single validator is enough
# to verify the device end-to-end on a live chain.
#
# Prerequisites:
#   * gnoland built from /Volumes/Tendermint/gnolang/gno master and on $PATH
#     or at /Users/clockwork/go/bin/gnoland (auto-detected).
#   * picowallet flashed with the default LISTENER firmware:
#       cmake -S firmware -B firmware/build && cmake --build firmware/build
#     and booted into PrivVal mode.
#   * Device-side state reset via TMKMS REPL between iterations:
#       os.auth_clear
#       os.hwm_wipe

set -euo pipefail

# --- Configuration ----------------------------------------------------------

CHAIN_ID="${CHAIN_ID:-picowallet-gno-$(date +%s)}"
TESTNET_DIR="${TESTNET_DIR:-$HOME/.picowallet-gno-testnet}"

PICOWALLET_HOST="${PICOWALLET_HOST:-192.168.7.1}"
PICOWALLET_GNO_PORT="${PICOWALLET_GNO_PORT:-26659}"

GNOLAND_BIN="${GNOLAND_BIN:-$HOME/go/bin/gnoland}"
GNOROOT_DIR="${GNOROOT_DIR:-/Volumes/Tendermint/gnolang/gno}"

# Non-default ports so this doesn't clash with anything listening on 26656/57.
P2P_PORT="${P2P_PORT:-29656}"
RPC_PORT="${RPC_PORT:-29657}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[36m[gno-testnet]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[gno-testnet] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- Step 1: verify prerequisites -------------------------------------------

[ -x "$GNOLAND_BIN" ] || fail "gnoland binary not found at $GNOLAND_BIN -- set GNOLAND_BIN=..."

if [ -z "${PICOWALLET_PUBKEY_HEX:-}" ]; then
    fail "set PICOWALLET_PUBKEY_HEX=<64-hex-chars> (the device's m/0' Ed25519 pubkey; read it off the e-paper console after booting to PrivVal mode)"
fi

log "chain id: $CHAIN_ID"
log "testnet dir: $TESTNET_DIR"
log "picowallet pubkey: $PICOWALLET_PUBKEY_HEX"

# Convert hex pubkey to base64 (gno's genesis.json format).
PICOWALLET_PUBKEY_B64=$(echo -n "$PICOWALLET_PUBKEY_HEX" | xxd -r -p | base64)

# --- Step 2: wipe + bootstrap -----------------------------------------------

log "wiping $TESTNET_DIR"
rm -rf "$TESTNET_DIR"
mkdir -p "$TESTNET_DIR/logs"
touch "$TESTNET_DIR/empty-txs.jsonl"

log "bootstrapping gnoland data dir (local signer for init; will swap to remote)"
"$GNOLAND_BIN" start -lazy \
    -data-dir "$TESTNET_DIR/data" \
    -genesis "$TESTNET_DIR/data/genesis.json" \
    -genesis-txs-file "$TESTNET_DIR/empty-txs.jsonl" \
    -gnoroot-dir "$GNOROOT_DIR" \
    -chainid "$CHAIN_ID" \
    -skip-failing-genesis-txs=true \
    -skip-genesis-sig-verification=true \
    > "$TESTNET_DIR/logs/bootstrap.log" 2>&1 &
BOOT_PID=$!

# Wait for genesis.json to appear, then kill -- we just needed the files.
for _ in $(seq 1 30); do
    [ -f "$TESTNET_DIR/data/genesis.json" ] && break
    sleep 0.2
done
sleep 1   # let config.toml settle
kill "$BOOT_PID" 2>/dev/null || true
wait "$BOOT_PID" 2>/dev/null || true

[ -f "$TESTNET_DIR/data/genesis.json" ] || fail "bootstrap didn't produce genesis.json -- see $TESTNET_DIR/logs/bootstrap.log"

# --- Step 3: patch genesis + config -----------------------------------------

log "swapping validator pubkey -> picowallet"
# Set address to empty string. gno's Address.UnmarshalJSON treats "" as a
# zero address, which GenesisDoc.ValidateAndComplete then fills in from the
# pubkey. (Address is bech32 "g1..." in gno's JSON, NOT hex -- a hex
# placeholder would fail to parse with "invalid separator index -1".)
jq --arg pk "$PICOWALLET_PUBKEY_B64" \
   '.validators[0].pub_key.value = $pk
    | .validators[0].address = ""' \
   "$TESTNET_DIR/data/genesis.json" > "$TESTNET_DIR/data/genesis.json.new"
mv "$TESTNET_DIR/data/genesis.json.new" "$TESTNET_DIR/data/genesis.json"

log "rewriting config.toml: ports + remote_signer + relaxed peering"
sed -i.bak \
    -e "s|tcp://0.0.0.0:26656|tcp://0.0.0.0:$P2P_PORT|" \
    -e "s|tcp://127.0.0.1:26657|tcp://127.0.0.1:$RPC_PORT|" \
    -e "s|server_address = \"\"|server_address = \"tcp://$PICOWALLET_HOST:$PICOWALLET_GNO_PORT\"|" \
    "$TESTNET_DIR/data/config/config.toml"

# Wipe any state files written during bootstrap so the chain starts clean.
# (Bootstrap used the local signer, so priv_validator_state.json is stale.)
rm -rf "$TESTNET_DIR/data/wal" "$TESTNET_DIR/data/db"
echo '{"height":"0","round":"0","step":0}' \
    > "$TESTNET_DIR/data/secrets/priv_validator_state.json"

# --- Step 4: launch for real ------------------------------------------------

log "starting gnoland with picowallet as remote signer"
"$GNOLAND_BIN" start \
    -data-dir "$TESTNET_DIR/data" \
    -genesis "$TESTNET_DIR/data/genesis.json" \
    -genesis-txs-file "$TESTNET_DIR/empty-txs.jsonl" \
    -gnoroot-dir "$GNOROOT_DIR" \
    -chainid "$CHAIN_ID" \
    -skip-failing-genesis-txs=true \
    -skip-genesis-sig-verification=true \
    > "$TESTNET_DIR/logs/gnoland.log" 2>&1 &
echo $! > "$TESTNET_DIR/gnoland.pid"
sleep 1

log "gnoland up (pid $(cat "$TESTNET_DIR/gnoland.pid")). Useful commands:"
echo
echo "  tail -f $TESTNET_DIR/logs/gnoland.log"
echo "  curl -s http://127.0.0.1:$RPC_PORT/status | jq .result.sync_info"
echo "  curl -s http://127.0.0.1:$RPC_PORT/block?height=5 | jq .result.block.last_commit"
echo
echo "  scripts/gno_testnet-stop.sh                  # stop"
echo
echo "Once the device dials in (or rather: gets dialed by gnoland), you should"
echo "see blocks advance and the device's e-paper console log 'gno-sc: signed ...'"
echo "lines for each vote and proposal."
