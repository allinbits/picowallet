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
| LEFT | **TMKMS** | CDC serial REPL | Admin: provision per-chain config, query state |
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
              │   • USB CDC REPL (TMKMS mode)              │
              └────────────────────┬───────────────────────┘
                                   │
              ┌────────────────────┴───────────────────────┐
              │  OS                                        │
              │   • mode select + app registry             │
              │   • keystore (Ed25519 SLIP-10)             │
              │   • HWM (per-slot regions, flash)          │
              │   • chain config + per-slot pinning (flash)│
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
- **Per-chain isolation.** The operator declares one slot per chain in
  TMKMS mode (up to 8 cosmos slots + 8 gno slots). Cosmos slots own a
  dial target (host + port + optional pinned peer pubkey); gno slots own
  a listen port (+ optional pinned peer pubkey). 0 cosmos slots = no
  dialers launched. 0 gno slots = no listeners bound. Each slot has its
  own SC state and runs independently so a slow peer on one chain cannot
  queue signing for another.
- **Strict chain_id binding.** Every slot records its expected chain_id.
  A sign request whose canonical bytes claim a different chain_id is
  refused with a `chain_id_mismatch` remote-signer error -- even if the
  peer authenticated successfully.
- **Per-slot peer pinning (optional).** If a slot's `pinned_key` is set,
  only that exact SecretConnection long-term pubkey authenticates to
  that slot. Unset = permissive (logs a warning).
- **Admin operations need physical access.** All trust-changing operations
  (add/remove chain slot, factory reset) live in TMKMS mode, which is
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
          │  Chain config   (4 KB sector)         │
          │   • cosmos[8] + gno[8] slots          │
          │   • label / chain_id / host / port    │
          │   • optional pinned peer pubkey       │
0x300000  ├──────────────────────────────────────┤
          │  HWM (1 MB) — 16 per-chain regions    │
          │   • 16 contiguous sectors per slot    │
          │   • 64 records × 64 B per sector      │
          │   • rolling log within each region    │
          │   • no compaction (chain_id implicit) │
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
- Originally a shared 256-sector rolling log (1 MB) with compaction on
  sector advance. Redesigned in M8 into 16 dedicated per-slot regions
  (see §M8 last bullet).

### ✓ M5c — Peer pubkey allowlist (superseded by M8 per-chain pinning)

- Flat allowlist replaced by per-slot pinning in M8. Original behavior:
  RAM + flash-persisted single 4 KB sector, strict-or-permissive, REPL
  via `os.auth_{list,add,clear}`. All gone now.

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
- ✓ Add `apps/cosmos/sc_driver_cosmos.{h,c}` — initially a TCP listener
  on port 26660; shared `secret_connection.c` frame layer (AEAD + HKDF
  identical to gno). The driver was later rewritten to a per-chain
  dialer in M8 (cometbft expects the signer to dial in).
- ✓ Pure-Python Merlin (`tools/merlin.py`) + `pwctl.py cosmos-sc-handshake`
  drove the host-side handshake during M6 development, byte-for-byte
  matched to the C implementation. Both were removed in e7ed4e8 once
  cosmos became dialer-only and pwctl had no listener to dial into.
- ✓ Wire the existing protobuf privval state machine through the encrypted
  frame layer. `apps/cosmos/privval.c` was refactored to take a `privval_sink_t`
  (write/flush callback) instead of a `tcp_pcb` directly; `sc_driver_cosmos.c`
  buffers each response frame then seals it. Plaintext listener on 26658
  removed in the same commit. Verified end-to-end against the device.
- ◯ Integration test against a stock cometbft v0.38 validator listener.

### ✓ M7 — Testnet integration against real validators

- `scripts/testnet.sh`: 4-validator cosmos-sdk testnet (v0.50.15) where
  node3 uses the picowallet as its consensus signer via cometbft's TCP
  remote-signer protocol. Device runs as the dialer.
- `scripts/gno_testnet.sh`: same shape for a 4-validator gnoland testnet;
  node3's `remote_signer.server_address` points at the device's gno
  listener (gno's polarity is inverted).

### ✓ M8 — Per-chain multitenancy

Goal: validate multiple chains on one device with full isolation -- a
slow or compromised peer on chain A cannot block or coerce signing for
chain B.

- ✓ `os/storage/chains.{h,c}`: per-family table (cosmos[8] + gno[8])
  with label, chain_id, dial host / listen port, optional pinned key.
  Flash-persisted in the same 4 KB sector that used to hold the
  allowlist. New TMKMS REPL: `os.{cosmos,gno}.chain.{add,remove,list}`
  and `os.chain.wipe`.
- ✓ Per-connection SC state lives in a pool attached to each pcb via
  `tcp_arg`; the privval parser is caller-owned. No file-scope conn
  state.
- ✓ Multi-slot dialers + listeners. Cosmos slots each own an independent
  dial FSM; gno slots each bind their own `tcp_listen`. 0 slots in a
  family = no dialers / listeners. Compile-time `COSMOS_SC_DIAL_HOST`
  flag retired.
- ✓ Strict chain_id binding: sign requests are refused with
  `chain_id_mismatch` if the canonical bytes don't match the slot's
  chain_id, even with a successful SC handshake.
- ✓ Per-slot peer pinning replaces the flat allowlist (M5c).
- ✓ HWM rearchitected to per-slot dedicated regions. 1 MB partitioned
  into 16 × 64 KB regions (one per chain slot, mapped via
  `chains_hwm_slot_idx`). 64-byte records (4 per flash page via
  sub-page programming), 64 records per sector, 16 sectors per region.
  No compaction (chain_id is implicit by region; an 8-byte hash field
  rides along as a sanity check). Wear is isolated per chain.
  `chains_add` wipes the region before assigning a slot to a new
  chain_id. Endurance at spec-min 100K cycles: 100K × 16 sectors × 64
  records = 102M signs per chain → ~9.3 years at 0.35 signs/sec,
  regardless of how many other chains are configured (real flash 2-5×
  → 20-45y in practice).

### ◯ M9 — TrustZone-M split

Goal: hold the seed and Ed25519 signing in the Secure world so a full
compromise of USB / lwIP / parser code in the Non-Secure world cannot
extract the validator's private key. Everything else (transport,
parsing, UI, even most of the OS) stays Non-Secure.

#### M9.1 — Boundary design

**Secure world (small):**
- The seed (`firmware/src/os/crypto/keystore.c`'s `TEST_SEED` today;
  PIN-unwrapped flash in a later milestone)
- SLIP-10 derivation
- Ed25519 sign + the SHA-512 it needs (`monocypher-ed25519.c` subset)
- HWM strict-advance check and append (`hwm_flash.c`) — see below
- The flash-erase / flash-program ROM calls touched by the above

**Non-secure world (everything else):**
- USB stack, lwIP, ECM netif (already designed assuming flat memory)
- SC handshake (X25519, ChaCha20-Poly1305, HKDF, Ed25519 *verify*)
- chains config table + REPL
- privval parsers (cosmos protobuf, gno amino)
- canonical sign-bytes extraction
- UI, console, display, factory reset

The boundary is enforced by ACCESSCTRL + SAU. The Non-Secure side gets
its own copy of Monocypher (X25519, ChaCha20-Poly1305, Ed25519 verify);
the Ed25519 *sign* path is only in the Secure copy.

**Secure-callable veneer (the only entries into Secure):**

```
int  s_get_pubkey(uint8_t curve, const char *path,
                  uint8_t *out_pubkey, size_t out_size, size_t *out_len);

int  s_sign_and_advance(uint8_t curve, const char *path,
                        uint8_t hwm_slot_idx, int32_t type,
                        int64_t height, int32_t round,
                        const uint8_t *data, size_t data_len,
                        uint8_t out_sig[64]);

const char *s_status_str(int status);  // optional convenience
```

`s_sign_and_advance` is the key change versus today's `os_crypto_sign`:
it takes the slot index + (type, height, round) tuple and *atomically*
advances the HWM before signing. Non-Secure code cannot bypass the
double-sign check by skipping a `hwm_advance` call. Non-Secure can lie
about (h, r, t) but only to push the HWM forward -- the seed never
leaks, and the worst attacker outcome is bricking the validator (HWM
permanently advanced past usable heights), which is much weaker than
key extraction.

`os_crypto_sign` and `hwm_advance` on the Non-Secure side become thin
wrappers around `s_sign_and_advance`. The current call-site shape is
preserved.

#### M9.2 — Implementation plan (phased)

`pico-sdk` 2.2.0 ships SAU + ACCESSCTRL register definitions and the
Cortex-M33 CMSIS core header, but *no* middleware: no NSC veneer
helpers, no S/NS linker script template, no example apps. The split is
expected to be built from scratch on top of those primitives.

- **Phase 0 — Boundary hygiene (this milestone, partly done already).**
  Confirm that no app/transport code reaches into the keystore or
  Monocypher signing functions outside of `os_crypto_*`. (Currently:
  only `bench.c` calls `crypto_ed25519_*` directly with a local seed --
  fine, since the seed is a local fixture, not the real keystore.)
  Document the secure-callable veneer signatures above as the M9
  ABI.
- **Phase 1 — Linker + memory layout.** Carve flash into S / NSC / NS
  regions; carve SRAM the same way. Configure SAU on boot from the
  Secure side, then `BLXNS` to the Non-Secure entry point.
- **Phase 2 — Veneer entries.** Write `s_get_pubkey`,
  `s_sign_and_advance`, `s_status_str` as `cmse_nonsecure_entry`
  functions in the Secure image. Validate buffer pointers on entry
  using ARM's `cmse_check_pointed_object` helpers.
- **Phase 3 — Build system.** Split the CMake build into two static
  libraries + two link steps + a final UF2 that packs both images.
- **Phase 4 — ACCESSCTRL.** Configure ACCESSCTRL to:
  - Allow Non-Secure access to USB / GPIO / SPI (for display) / lwIP-
    relevant peripherals + the host CDC.
  - Restrict TRNG access to Secure-only (default already; verify).
  - Hardware SHA-256 stays accessible from both worlds (it's used by
    the SC HKDF path on the NS side).
- **Phase 5 — TinyUSB + lwIP audit.** Both assume a flat memory map.
  Confirm their DMA descriptors and pbuf pools live entirely in NS
  memory and don't try to reach into S regions; refactor if needed.
- **Phase 6 — End-to-end revalidation.** Re-run `make test` (gno
  handshake) and both testnet scripts. Add a negative test: NS code
  attempting to read the seed region should fault.

#### M9.3 — Risks / open questions

- **bench.c.** Currently calls Monocypher directly. Will need to use
  the NS copy of Monocypher (same library, different link unit), or be
  removed -- it's a microbenchmark, not load-bearing.
- **pico_sha256, pico_rand.** TRNG defaults to Secure-Privileged-only;
  the NS-side SC handshake uses `pico_rand_get_bytes` for ephemerals
  via the existing TRNG-backed PRNG. Either expose TRNG to NS via
  ACCESSCTRL NSP bit, or have the NS side dual-source entropy from
  Secure via a small veneer (`s_random(out, n)`).
- **Memory cost.** Two copies of Monocypher's X25519 + SHA + AEAD (one
  per world). Code size impact ~5-10 KB doubled = acceptable on 4 MB
  flash.
- **Build complexity.** Two ELFs, dual link, UF2 packaging. Manual
  scaffold required; no SDK helper.
- **First-time bringup risk.** SAU misconfiguration on boot is a hard-
  fault-on-every-instruction class problem. Plan to keep an "escape
  hatch" build flag during development that disables the split.

### ◯ M10 — Signed firmware + OTP fuse

- Firmware image signed by a build-time key
- Verification in bootloader; reject unsigned updates
- Burn OTP fuses to lock the verification key + enable secure boot
- Provisioning flow for the OTP step (one-shot, irreversible)

### ◯ M11 — HID transport (production parity)

Swap USB CDC → HID for the TMKMS-mode admin channel, matching Ledger's
production transport. CDC stays available behind a build flag for
development.

### ◯ Cross-cutting open items

| | Subject | Notes |
|---|---|---|
| | PIN unlock + key-at-rest encryption | Currently the keystore is at-rest in flash with no PIN gate |
| | Multi-validator key selection | Hardcoded `m/0'` path; real product needs named keys + selection UX |
| | Console paging / longer history | Console buffer is small; long logs lose old lines |
| | Operational metrics over TMKMS REPL | Sign counter, HWM per chain (the latter is now exposed via `os.hwm.list`); sign counter / last error still TODO |
| ✓ | Factory reset UX | Hold both buttons for 5 s in TMKMS mode (or `os.factory_reset` REPL command) → confirm screen → chain config + HWM wiped. Validator key not touched. |

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
│       │   │   └── chains.{h,c}                  per-chain config table
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
│           │   ├── privval.{h,c}                 protobuf privval over SC
│           │   ├── secret_connection_cosmos.{h,c} Merlin handshake
│           │   └── sc_driver_cosmos.{h,c}        per-chain dialers
│           └── gnoland/
│               ├── app.{h,c}
│               ├── secret_connection_gno.{h,c}   HKDF-only handshake
│               ├── sc_driver.{h,c}               per-chain listeners
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

`tools/pwctl.py` exercises the gno signing path end-to-end against the
device in PrivVal mode. Requires `pip install pynacl cryptography` and at
least one configured gno chain slot whose port matches what pwctl dials.

| Subcommand | Exercises |
|---|---|
| `gno-sc-handshake --sign-height H --signing-seed HEX` | Full gno path: SC handshake → PubKeyRequest → SignRequest → replay-rejection |

Cosmos paths are exercised end-to-end via `scripts/testnet.sh` (real
4-validator cosmos-sdk testnet with node3 using the device as its
remote signer). The cosmos client-mode pwctl subcommands (`pubkey`,
`sign-vote`, `sign-proposal`, `replay`, `bench`, `cosmos-sc-handshake`)
were deleted in e7ed4e8 once cosmos went dialer-only; reviving any of
them would require adding a fake-cometbft listener mode to pwctl.
