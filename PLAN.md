# PicoWallet — Plan & Status

A hardware validator-signing device for Tendermint-class blockchains
(cosmos-sdk and gno.land today; extensible to others). Conceptually in the
**TMKMS + YubiHSM** class — continuous machine-speed signing, no per-tx UX —
not a consumer hardware wallet.

This document is the single source of truth for design intent, hardware, and
milestone status. Update it when scope shifts.

---

## 1. Overview

**Purpose.** Hold the validator's consensus key (Ed25519) in tamper-resistant
hardware and respond to a validator daemon's signing requests over USB, with
strict double-signing protection.

**Targets.**
- Cosmos-SDK / CometBFT chains (cosmoshub-4, osmosis-1, …)
- Gno.land's tm2 fork
- Future Tendermint-derived chains slot in as new `apps/<chain>/`

**Comparable to.** TMKMS daemon + a YubiHSM-2, or Ledger's app-validator
mode. The device is the signer. The validator daemon dials in over a
USB-Ethernet link and speaks each chain's native privval wire protocol.

**Non-goals.**
- Per-transaction confirmation UX (validators sign thousands of messages an
  hour; no human in the loop)
- secp256k1 or user-wallet workflows (Ed25519 only)
- amino-JSON `SignDoc` parsing (consensus messages are canonical binary)

---

## 2. Hardware

### 2.1 Bill of materials

| # | Item | Notes |
|---|---|---|
| 1 | Raspberry Pi Pico 2 (RP2350) — **headerless variant** | 4 MB QSPI flash, 520 KB SRAM, Cortex-M33 @ 150 MHz, hardware SHA-256 + TRNG |
| 2 | Waveshare 3.7" e-Paper HAT — **SKU 20123, V1.0 driver** | 480×280 px; 1-bit mode only (4-Gray broken on this revision) |
| 3 | 2× momentary tactile push-button switches | Any 6 mm or 12 mm THT switch |
| 4 | Solderless breadboard or perfboard + jumper wires | For prototyping |
| 5 | USB-C cable | Power + data |

### 2.2 Pin connections

**Pico 2 ↔ Waveshare 3.7" e-Paper (SPI1):**

| Pico pin | Pico GPIO | Function | ePaper signal |
|---|---|---|---|
| 11 | GP8 | GPIO out | DC |
| 12 | GP9 | SPI1 CSn | CS |
| 14 | GP10 | SPI1 SCK | CLK |
| 15 | GP11 | SPI1 TX (MOSI) | DIN |
| 16 | GP12 | GPIO out | RST |
| 17 | GP13 | GPIO in | BUSY |
| 36 | 3V3 OUT | Power | VCC |
| 38 | GND | Ground | GND |

**Pico 2 ↔ buttons** (each switch connects GPIO → GND; internal pull-up enabled in firmware so unpressed = HIGH):

| Pico pin | Pico GPIO | Function |
|---|---|---|
| 21 | GP16 | LEFT button |
| 22 | GP17 | RIGHT button |

The onboard LED is used for liveness blink (driven by `PICO_DEFAULT_LED_PIN`).

USB is the standard onboard USB-C; no extra wiring.

### 2.3 Boot-mode selection

At power-on the firmware shows a mode prompt for ~4.5 s. The button pressed
during that window selects the operating mode:

| Held button | Mode | USB | Use |
|---|---|---|---|
| LEFT | **TMKMS** | CDC serial REPL | Admin: provision allowlist, query state |
| RIGHT | **PrivVal** | CDC-ECM (USB-Ethernet) | Signing: validator daemon dials in over TCP |

Modes are mutually exclusive because they expose different USB descriptors.
Reboot to switch.

---

## 3. Architecture

### 3.1 Layered stack

```
              ┌───────────────────────────────────────────┐
              │  Per-chain apps                            │
              │   apps/cosmos/   apps/gnoland/   …         │
              │   • privval protocol (proto / amino)       │
              │   • canonical sign-bytes parser            │
              │   • per-chain HWM extraction               │
              └────────────────────┬───────────────────────┘
                                   │
              ┌────────────────────┴───────────────────────┐
              │  Shared transports                         │
              │   • SecretConnection frame layer (AEAD)    │
              │   • Plain TCP (cosmos privval today)       │
              │   • USB CDC REPL (TMKMS mode)              │
              └────────────────────┬───────────────────────┘
                                   │
              ┌────────────────────┴───────────────────────┐
              │  OS                                        │
              │   • mode select + app registry             │
              │   • keystore (Ed25519 SLIP-10)             │
              │   • HWM ring buffer (per-chain, flash)     │
              │   • peer allowlist (flash)                 │
              │   • SHA-256 / HMAC / HKDF (HW-accel)       │
              │   • display + buttons + LED                │
              └────────────────────────────────────────────┘
```

### 3.2 Key principles

- **One device, one validator key, multi-chain.** A single Ed25519 keypair
  signs for multiple chains. The OS owns the key (`os_crypto_sign(path, …)`);
  apps never see the private material.
- **Per-chain HWM.** Double-sign protection is keyed by
  `(validator_key, chain_id, height, round, type)`. Signing height H on
  chain A does not block height H on chain B.
- **Per-app sign-bytes parsing.** Each app implements its own canonical
  format decoder before passing height/round/type into the shared
  `hwm_advance`. The device never signs bytes whose structure it cannot
  parse and account for.
- **Authenticated peer required for encrypted channels.** Where the wire
  protocol supports peer authentication (SecretConnection), the OS provides
  a flash-persisted allowlist of peer pubkeys. Empty list = permissive
  (logs a warning); any entry switches to strict matching.
- **Admin operations need physical access.** All trust-changing operations
  (add/remove pinned key, factory reset) live in TMKMS mode, which is
  reachable only by pressing a button at boot. The PrivVal-mode network
  channel never accepts admin commands.

### 3.3 Persistent storage layout (4 MB QSPI flash)

```
0x000000  ┌──────────────────────────────────────┐
          │  Firmware image (≈170 KB today)       │
          │   bootloader + .text + .rodata + …    │
          ├──────────────────────────────────────┤
          │  Unused / growth                      │
0x2FF000  ├──────────────────────────────────────┤
          │  Peer allowlist  (4 KB sector)        │
0x300000  ├──────────────────────────────────────┤
          │  HWM rolling log (1 MB / 256 sectors) │
          │   • 16 records × 256 B per sector     │
          │   • each record: chain_id + h/r/t     │
          │   • compaction-on-wrap, sector-rolls  │
0x400000  └──────────────────────────────────────┘
```

`firmware/src/os/storage/flash_layout.h` keeps the offsets in one place.

---

## 4. Milestone status

Phase ✓ = completed (verified end-to-end). Phase ◯ = open.

### ✓ M0 — Hardware bringup

- Pico 2 hello-world, USB CDC echo
- Waveshare 3.7" e-Paper hello-world (1-bit mode confirmed; 4-Gray broken on
  SKU 20123 V1.0)
- 2-button input with debounce + internal pull-ups

### ✓ M1 — OS scaffold

- App registry (`os_register_app`, `os.apps` REPL command)
- Host protocol REPL (`os.info`, `os.pubkey`, `os.sign`, `os.refresh`, …)
- E-paper console with word-wrap, scrollback, dirty-flag refresh
- Splash screen with multi-pass refresh into main screen
- LED liveness blink

### ✓ M2 — Validator pivot + Ed25519 keystore

- **Project pivot 2026-05-14** from "consumer wallet" to "validator signer"
- Monocypher Ed25519 (SHA-512 variant, Tendermint-compatible) + SLIP-10
  derivation
- Boot-mode selection (LEFT=TMKMS, RIGHT=PrivVal) with USB descriptor swap
- Splash + main screen integration

### ✓ M3 — USB-Ethernet transport

- TinyUSB CDC-ECM (not NCM — macOS-incompatible) + lwIP 2.2.1 (`NO_SYS=1`)
- Device IP `192.168.7.1/24`; host autoconfigures peer side
- Non-blocking `link_output_fn`; mandatory `netif_set_link_up` (silent
  failure mode for hours of debugging — documented in memory)
- 1 kHz USB pump timer so descriptor enumeration survives slow display init

### ✓ M4 — Cosmos privval (now sealed; plaintext path removed)

- Privval wire framing (uvarint length + length-delimited protobuf)
- Handlers: `PubKeyRequest`, `SignVoteRequest`, `SignProposalRequest`,
  `PingRequest`
- Canonical-vote / proposal encoder (sfixed64 for height/round)
- HWM enforcement + flash persistence
- Originally exposed via a plaintext TCP listener on port 26658, with a
  bench of 1000 sign-votes at ~57 signs/sec (p50 16 ms). Cometbft only
  speaks SecretConnection over TCP, so the plaintext listener could only
  ever serve dev tooling and has been removed. Privval is now driven by
  the cosmos SC channel via a sink callback (see M6); through SC the
  100-sign bench reports ~31 signs/sec, p50 18 ms.

### ✓ M5a — Gno.land SecretConnection + privval

- SecretConnection HKDF variant (no Merlin):
  - X25519 ephemeral exchange (TRNG-backed)
  - HKDF-SHA-256 key derivation (hardware SHA-256 peripheral)
  - Ed25519 mutual auth over derived challenge
  - IETF ChaCha20-Poly1305 frame layer (1024 B chunks, seq-as-nonce)
- amino-encoded privval:
  - Wire format reverse-engineered from gno tm2 source
    (`tm.remotesigner.{PubKey,Sign}{Request,Response}`)
  - Canonical sign-bytes parser (extracts chain_id from field 6 in Vote,
    field 7 in Proposal — disambiguated by `Type`)
- HWM enforcement: same `hwm_advance` as cosmos (one shared invariant)
- Listens on port 26659 alongside cosmos's 26658

### ✓ M5b — Per-chain HWM + multi-sector wear leveling

- HWM keyed by `(chain_id, …)` instead of global per-key
- 256-sector rolling-log flash storage (1 MB)
- Compaction on sector advance; no separate sector-pointer record needed
  (boot scan finds active sector via max seq)
- Lifetime at flash spec minimum:
  - 1 chain: ~35 years
  - 8 chains: ~2.3 years
  - Real-world flash typically 2–5× the spec → multiply accordingly

### ✓ M5c — Peer pubkey allowlist

- RAM + flash-persisted (single 4 KB sector, erase-and-rewrite)
- Strict-or-permissive: empty list = permissive with WARN log; any entry =
  strict matching
- TMKMS-mode REPL admin: `os.auth_list`, `os.auth_add <hex>`,
  `os.auth_clear`
- Verified end-to-end: allowed peer succeeds, mismatching peer is closed
  immediately after handshake completes

### ◐ M6 — Cosmos SecretConnection (Merlin variant)

Current cometbft (v0.38+ and v2) uses **Merlin transcripts** (STROBE-128
over Keccak-f1600) for challenge derivation in the SecretConnection
handshake. Our shared frame layer already works; need to add the Merlin
path so the cosmos app can interop with stock cometbft over an encrypted
channel.

Subtasks:
- ✓ Implement Keccak-f1600 permutation — `firmware/src/os/crypto/keccak.{h,c}`,
  validated against SHA3-256("") via `make test-keccak`
- ✓ Implement STROBE-128 (AD/META_AD/PRF subset) —
  `firmware/src/os/crypto/strobe.{h,c}`, translated from oasisprotocol/curve25519-voi
- ✓ Implement Merlin labeled transcripts — `firmware/src/os/crypto/merlin.{h,c}`,
  validated bit-for-bit against curve25519-voi `TestSimpleTranscript`
  (`d5a21972d0d5fe32...`) and `TestComplexTranscript`
  (`a8c933f54fae76e3...`) via `make test-merlin`
- ✓ Add `apps/cosmos/secret_connection_cosmos.{h,c}` — handshake state
  machine with Merlin challenge derivation + protobuf-delimited wire
  (ephemeral via `BytesValue`, auth-sig via `AuthSigMessage` with pubkey
  oneof). Outer wire: 35B ephemeral + 103B AuthSigMessage.
- ✓ Add `apps/cosmos/sc_driver_cosmos.{h,c}` — TCP listener on port 26660;
  shared `secret_connection.c` frame layer (AEAD + HKDF identical to gno).
  Auth-keys allowlist check applies (same OS-level pinning as gno).
- ✓ Pure-Python Merlin in `tools/merlin.py`, byte-for-byte matched to the
  C implementation (same test vectors pass both sides).
- ✓ `pwctl.py cosmos-sc-handshake` — full handshake driver using the Python
  Merlin + protobuf-delimited wire. Awaiting device flash for integration
  verification.
- ✓ Wire the existing protobuf privval state machine through the encrypted
  frame layer. `apps/cosmos/privval.c` was refactored to take a `privval_sink_t`
  (write/flush callback) instead of a `tcp_pcb` directly; `sc_driver_cosmos.c`
  buffers each response frame then seals it. Plaintext listener on 26658
  removed in the same commit. pwctl pubkey/sign-vote/sign-proposal/replay/bench
  all run over SC now. Verified end-to-end against the device.
- ◯ Integration test against a stock cometbft v0.38 validator listener.

### ◯ M7 — TrustZone split

Pico 2's Cortex-M33 supports TrustZone. Goal: move keystore + HWM + AEAD
into the secure world; non-secure world owns USB / lwIP / display / apps.

Subtasks:
- Define secure-gateway ABI (the shared functions in `os/api.h` become
  cross-world calls)
- Linker scripts for secure / non-secure split
- ITCM/DTCM allocation for secure code
- MPU configuration
- Verify HWM, keystore, allowlist all live in secure world
- Re-test the whole stack

### ◯ M8 — Signed firmware + OTP fuse

- Firmware image signed by a build-time key
- Verification in bootloader; reject unsigned updates
- Burn OTP fuses to lock the verification key + enable secure boot
- Provisioning flow for the OTP step (one-shot, irreversible)

### ◯ M9 — HID transport (production parity)

Swap USB CDC → HID for the TMKMS-mode admin channel, matching Ledger's
production transport. CDC stays available behind a build flag for
development.

### ◯ Cross-cutting open items

| | Subject | Notes |
|---|---|---|
| | PIN unlock + key-at-rest encryption | Currently the keystore is at-rest in flash with no PIN gate |
| | Multi-validator key selection | Hardcoded `m/0'` path; real product needs named keys + selection UX |
| | Console paging / longer history | Console buffer is small; long logs lose old lines |
| | Proper SignedMsgType ordering for HWM | Current code treats type as monotonic; that's correct for vote-only validators but wrong for proposer-validators (Proposal=32 → Prevote=1 would be rejected). Map types to steps |
| | Operational metrics over TMKMS REPL | Sign counter, HWM per chain, last error, etc. |
| | Factory reset UX | `hwm_flash_wipe` exists; needs a long-press button confirmation flow |

---

## 5. Codebase layout

```
picowallet/
├── PLAN.md                  this document
├── README.md                build + flash instructions
├── splash.png               source artwork for splash_image.h
├── firmware/
│   ├── CMakeLists.txt
│   ├── pico_sdk_import.cmake
│   └── src/
│       ├── os/
│       │   ├── main.c                  boot flow + mode dispatch
│       │   ├── api.{h,c}               secure-gateway-style API for apps
│       │   ├── app_registry.{h,c}
│       │   ├── mode.{h,c}              TMKMS / PrivVal enum
│       │   ├── bench.{h,c}             on-device microbenchmarks
│       │   ├── crypto/
│       │   │   ├── monocypher{,-ed25519}.{h,c}   X25519 / Ed25519 / AEAD
│       │   │   ├── sha256.{h,c}                  HW-accel SHA, HMAC, HKDF
│       │   │   └── keystore.{h,c}                SLIP-10 derivation
│       │   ├── storage/
│       │   │   ├── flash_layout.h                single source for offsets
│       │   │   ├── hwm_flash.{h,c}               per-chain HWM
│       │   │   └── auth_keys.{h,c}               peer allowlist
│       │   ├── transport/
│       │   │   ├── eth.{h,c}                     USB-ECM + lwIP netif
│       │   │   ├── usb{,_descriptors}.c
│       │   │   ├── host_protocol.{h,c}           TMKMS REPL
│       │   │   ├── secret_connection.{h,c}       shared SC frame layer
│       │   │   ├── tusb_config.h
│       │   │   └── lwipopts.h
│       │   ├── hal/                              display, input, usb_console
│       │   └── ui/                               console, splash, mode_select, confirm
│       └── apps/
│           ├── cosmos/
│           │   ├── app.{h,c}
│           │   └── privval.{h,c}                 protobuf privval (plaintext today)
│           └── gnoland/
│               ├── app.{h,c}
│               ├── secret_connection_gno.{h,c}   HKDF-only handshake
│               ├── sc_driver.{h,c}               TCP driver
│               └── gno_privval.{h,c}             amino privval over SC
├── tools/
│   ├── pwctl.py             host-side test harness (cosmos + gno paths)
│   └── png_to_header.py     splash.png → splash_image.h
└── third_party/
    ├── pico-sdk/            submodule @ 2.2.0
    └── Pico_ePaper_Code/    submodule @ c9bcd84 (Waveshare)
```

---

## 6. Build & flash

See [README.md](README.md). Short version:

```
git clone <this-repo>
cd picowallet
git submodule update --init --recursive
cmake -S firmware -B firmware/build
cmake --build firmware/build
# then BOOTSEL + drag firmware/build/picowallet.uf2 to RPI-RP2
```

---

## 7. Host-side test harness

`tools/pwctl.py` exercises every signing path end-to-end against the device
in PrivVal mode. Requires `pip install pynacl cryptography`.

| Subcommand | Exercises |
|---|---|
| `pubkey` | Cosmos privval `PubKeyRequest`; prints + verifies the validator pubkey |
| `sign-vote --height H --chain-id CID` | Full cosmos `SignVoteRequest` → response → signature verify |
| `sign-proposal --height H` | Same for `SignProposalRequest` (incl. POLRound) |
| `replay --height H` | Replays a vote at the same (h,r,t) to confirm HWM rejection |
| `bench --count N --start-height H` | Throughput / latency of N back-to-back sign-votes |
| `gno-sc-handshake --sign-height H --signing-seed HEX` | Full gno path: SC handshake → PubKeyRequest → SignRequest → replay-rejection |
