# scripts/

## testnet.sh — 4-validator cosmos-sdk testnet with picowallet as remote signer

Brings up a 4-validator local cosmos-sdk testnet on the Mac. Three nodes use
ordinary file-backed consensus keys; node3 uses the picowallet as its
consensus signer via cometbft's TCP remote-signer protocol. The device
initiates the connection to cometbft (cometbft is the server).

```
  ┌──────────────┐  TCP + SecretConnection (Merlin)  ┌─────────────────────┐
  │ cometbft     │ <─────────────────────────────────│ picowallet (Pico 2) │
  │ node3        │     :26690 (priv_validator_laddr) │ dialer firmware     │
  │ p2p :28686   │                                   │ via USB-Ethernet    │
  │ rpc :28687   │                                   │ host = 192.168.7.2  │
  └──────────────┘                                   └─────────────────────┘
```

### One-time prerequisites

1. **Go toolchain** (`go version` should work).
2. **`xxd`** (preinstalled on macOS / Debian / Fedora).
3. **simd** built from `/Volumes/Tendermint/cosmos-sdk` at `v0.50.15`.
   `testnet.sh` will build it on demand if missing. Override path with
   `COSMOS_SDK_PATH=...`.

### Per-run workflow

#### 1. Build + flash the firmware

```
make build
# BOOTSEL + drag firmware/build/picowallet.uf2 to RPI-RP2
```

A single image; no compile-time dial target. The dial host/port comes
from the chain slot config.

#### 2. Configure the cosmos chain slot in TMKMS mode

In TMKMS mode (USB-CDC), declare the slot for this testnet's chain. The
dial target is cometbft's `priv_validator_laddr`, exposed by node3 on
192.168.7.2:26690 below.

```
os.chain.wipe                                           # clear any prior slots
os.hwm.wipe                                             # fresh testnet chain_id = fresh HWM
os.cosmos.chain.add hub <CHAIN_ID> 192.168.7.2 26690    # no pinned key (permissive)
```

`<CHAIN_ID>` must match what testnet.sh actually launches with. Either
pass `CHAIN_ID=my-chain ./scripts/testnet.sh` to fix it, or read the
timestamped default from testnet.sh's logs and provision the slot at
that exact value. Strict chain_id binding means a mismatch refuses
signing with `chain_id_mismatch` rather than silently working.

Note: cometbft generates a fresh ephemeral Ed25519 long-term key for its
privval listener on every restart, so its peer key cannot be pre-pinned.
Leave the slot's pubkey arg unset to run permissive.

#### 3. Boot device into PrivVal mode and launch the testnet

Boot in PrivVal mode. The device's e-paper will show `val: <hex>` for
the m/0' consensus pubkey and `cosmos-sc[hub]: dialing 192.168.7.2:26690`
once it starts retrying.

The device's pubkey must match what's recorded in genesis. Pass it in
via env var:

```
PICOWALLET_PUBKEY_HEX=<64-hex-chars> ./scripts/testnet.sh
```

You can read the pubkey off the e-paper, or boot to TMKMS mode once and
run `os.pubkey ed25519 m/0'` over the REPL.

`testnet.sh` will:

- Build simd if missing.
- Wipe `$HOME/.picowallet-testnet/`.
- Init 4 nodes on the 28xxx port range (28656/66/76/86 p2p, 28657/67/77/87 rpc).
- Use the picowallet pubkey for node3's gentx via `--pubkey`.
- Rewrite `persistent_peers` unconditionally (cometbft's
  `collect-gentxs` pollutes it with the host's LAN IP + default port).
- Set `allow_duplicate_ip = true` and `addr_book_strict = false` on every
  node (loopback testnet is non-routable by default).
- Set node3's `priv_validator_laddr = "tcp://0.0.0.0:26690"`.
- Start all 4 nodes in the background; logs in `$TESTNET_DIR/logs/`.

Within a few seconds you should see node3 connect, complete the SC
handshake, and start co-signing every commit alongside nodes 0/1/2.

Confirm:

```
curl -s http://127.0.0.1:28687/status | jq .result.sync_info
# height should be advancing
curl -s "http://127.0.0.1:28687/block?height=5" | \
    jq '.result.block.last_commit.signatures | length'
# expect 4 (all validators signed)
```

### Stopping

```
./scripts/testnet-stop.sh
```

### Customization

```
TESTNET_DIR=/tmp/somewhere ./scripts/testnet.sh
CHAIN_ID=my-chain          ./scripts/testnet.sh        # disables fresh-chain default
COSMOS_SDK_PATH=...        ./scripts/testnet.sh
P2P_BASE=29000             ./scripts/testnet.sh        # port range shift
```

---

## gno_testnet.sh — 4-validator gnoland testnet with picowallet as remote signer

Same shape as the cosmos demo, but for gnoland. The validator polarity is
inverted: gnoland DIALS the signer instead of the signer dialing gnoland.
So the device's gno slot owns a listen port; gnoland's
`remote_signer.server_address` points at it. Cosmos outbound + gno listener
coexist in the same image without any rebuild between demos.

```
  ┌──────────────┐                           ┌──────────────┐
  │ gnoland 0    │ <── persistent peers ──>  │ gnoland 1    │
  │ p2p :29656   │     (loopback mesh,       │ p2p :29666   │
  │ rpc :29657   │      4 nodes total)       │ rpc :29667   │
  └──────────────┘                           └──────────────┘
              │                               │
              v                               v
  ┌──────────────┐                           ┌──────────────┐
  │ gnoland 2    │                           │ gnoland 3    │  remote_signer
  │ p2p :29676   │                           │ p2p :29686   │ ───────────────┐
  │ rpc :29677   │                           │ rpc :29687   │                v
  └──────────────┘                           └──────────────┘     ┌──────────────────┐
                                                                  │ picowallet       │
                                                                  │ listener :26659  │
                                                                  │ USB-Ethernet     │
                                                                  └──────────────────┘
```

### One-time prerequisites

1. **gnoland built from /Volumes/Tendermint/gnolang/gno master**:
   ```
   cd /Volumes/Tendermint/gnolang/gno/gno.land
   go build -o ~/go/bin/gnoland ./cmd/gnoland
   ```
2. **picowallet flashed** (single firmware drives both cosmos and gno
   chain slots; no per-chain build flags).

### Per-run workflow

1. Boot the device into TMKMS mode and configure a gno slot:
   ```
   os.chain.wipe                                # clear any prior slots
   os.hwm.wipe                                  # fresh chain_id -> fresh HWM
   os.gno.chain.add test <CHAIN_ID> 26659       # no pinned key (permissive)
   ```
   `<CHAIN_ID>` must match what gno_testnet.sh generates (set
   `CHAIN_ID=...` env var or read the timestamped default from its logs).
2. Boot back into PrivVal mode. Confirm `val: <hex>` matches your
   `PICOWALLET_PUBKEY_HEX` env var.
3. Run:
   ```
   PICOWALLET_PUBKEY_HEX=<64-hex-chars> ./scripts/gno_testnet.sh
   ```
   This:
   - Initializes 4 nodes' secrets and configs.
   - Bootstraps a template genesis once with `gnoland start -lazy` (using
     empty genesis txs + skip flags to bypass gno.land's pre-baked
     manfred-signed bootstrap transactions).
   - Hand-assembles a 4-validator genesis (node0/1/2 use their local
     pubkeys, node3 uses the picowallet's).
   - Distributes the genesis + wires `persistent_peers` using each node's
     bech32 node ID.
   - Flips `allow_duplicate_ip=true` and `addr_book_strict=false` (same
     loopback gotchas as cosmos).
   - Sets node3's `consensus.priv_validator.remote_signer.server_address
     = tcp://192.168.7.1:26659`.
   - Starts all 4 nodes.

Confirm node3 is co-signing every block:
```
curl -s 'http://127.0.0.1:29657/block?height=5' | \
    jq '.result.block.last_commit.precommits | map(select(.signature != null)) | length'
# expect 4
```

### Stopping

```
./scripts/gno_testnet-stop.sh
```

---

## Running both demos simultaneously

The cosmos and gno demos use disjoint ports (28xxx vs 29xxx for cometbft
P2P/RPC; 26690 for the cosmos node3 priv-validator listener that the
device dials, 26659 for the gno chain slot the device listens on). One
firmware image handles both at the same time -- the device dials its
cosmos slot's target while listening on its gno slot's port:

```
PICOWALLET_PUBKEY_HEX=... ./scripts/testnet.sh         # cosmos
PICOWALLET_PUBKEY_HEX=... ./scripts/gno_testnet.sh     # gno
```

Each chain gets its own HWM slot on the device (one per `chain_id`).
