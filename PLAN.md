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
          │  Secure image (≈140 KB, M9 stub +    │
          │   crypto + storage + UI + veneers)    │
          ├──────────────────────────────────────┤
          │  NSC veneer page (4 KB at 0x07F000)   │
          │   • SG-instruction stubs for every    │
          │     cmse_nonsecure_entry              │
0x080000  ├──────────────────────────────────────┤
          │  Non-Secure image (≈400 KB)           │
          │   bootloader + .text + .rodata + …    │
          ├──────────────────────────────────────┤
          │  Unused / growth                      │
0x2EE000  ├──────────────────────────────────────┤
          │  SLOT_SEEDS (64 KB)                   │
          │   • 16 × 4 KB sectors, one per slot   │
          │   • each holds an AEAD-sealed slot    │
          │     seed override (MNEMONIC or       │
          │     RAW_KEY); blank ⇒ DERIVED         │
0x2FE000  ├──────────────────────────────────────┤
          │  SEED (4 KB sector)                   │
          │   • page 0: magic + version +        │
          │     m9_sealed_seed_t (master)         │
          │   • pages 1..10: PIN attempt counter  │
          │     (thermometer encoding)            │
0x2FF000  ├──────────────────────────────────────┤
          │  Chain config (4 KB sector)           │
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
All four persistent regions (SEED, SLOT_SEEDS, CHAINS, HWM) are erased
by `m9_factory_wipe_all` on factory reset.

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

### ✓ M9 — TrustZone-M split (Ledger-style)

Goal: hold the seed, all destructive state mutations, and the
user-consent path (display + buttons) in the Secure world so a full
compromise of TinyUSB / lwIP / parsers / SC handshake in the
Non-Secure world cannot extract the seed, spoof prompts, or tamper
with persistent state. NS becomes the "I/O processor": it parses
untrusted bytes off USB/Ethernet and asks Secure to make every
security-relevant decision.

#### M9.0 — Threat model

| # | Attacker capability | M9 mitigation |
|---|---|---|
| 1 | Network attacker dialing PrivVal port | Out of scope of M9. Covered by SC handshake + HWM + chain_id binding (already shipped). |
| 2 | MITM on USB-Ethernet link | Out of scope. Covered by per-chain pinned peer keys. |
| 3 | Compromised peer that knows a valid SC long-term key | Out of scope. HWM, chain_id binding, and strict-advance bound damage to DoS-on-this-chain. |
| 4 | **Runtime exploit in NS code** (TinyUSB / lwIP / privval parser / SC handshake) | **The primary thing M9 addresses.** NS cannot read the seed, cannot draw on the prompt region of the display, cannot modify chain config or HWM in flash, cannot inject button events into a Secure confirm flow. |
| 5 | Logic bug in Secure code | Only mitigation is keeping Secure TCB small + reviewing it carefully. Veneer-validated pointers (`cmse_check_pointed_object`) catch shape-of-call mistakes; semantic bugs are on us. |
| 6 | Physical adversary dumps QSPI flash externally | **Not addressed by M9.** Addressed by §M9.5 (encryption-at-rest + PIN). |
| 7 | Physical adversary attaches SWD | ACCESSCTRL restricts DEBUG to NS world; M10 OTP fuse disables SWD entirely. M9 closes the SWD-into-Secure-memory path. |
| 8 | Voltage / clock / EM glitching | Out of scope. |
| 9 | Power / timing side channel | Monocypher is constant-time; specialised side-channel hardening is out of scope. |

#### M9.1 — Boundary (as shipped)

| | Secure | Non-Secure |
|---|---|---|
| Seed (master) + SLIP-10 + Ed25519 *sign* + SHA-512 | ✓ | |
| Per-slot seed override (mnemonic / raw-key) | ✓ — sealed under PIN-derived KEK; see M9.5 | |
| HWM table — **writes** + reads (cache) | ✓ | NS shim forwards writes via flash veneers |
| Chain config table — **writes** + reads (cache) | ✓ | NS shim forwards writes via flash veneers |
| Flash program/erase | ✓ — bootrom flash ops + ACCESSCTRL lockdown of the storage region | |
| Display SPI peripheral + e-paper driver + framebuffer + Pico_ePaper library | ✓ — SPI1 locked Secure-only; GPIO_NSMASK bits 8..13 cleared from NS | |
| Trusted UI screens (splash, mode-select, console, confirm, PIN entry, mnemonic display + restore, factory-reset countdown) | ✓ — Secure-rendered + Secure-polled buttons | |
| Button GPIO reads | ✓ — `s_input_pressed` direct SIO read; NS shim forwards | NS sees button state only through the veneer |
| TRNG, hardware SHA-256 peripheral, OTP, POWMAN, WATCHDOG, CLOCKS / XOSC / ROSC / PLLs | ✓ — ACCESSCTRL Secure-only after Phase 4 | NS gets entropy via `s_random()`, HKDF via `s_hkdf_*`, clock freqs via `s_clock_get_hz` |
| DMA channel 0 | ✓ — SECCFG_CH0 S=1 + LOCK=1 | NS uses channels 1..15 |
| LED (liveness blink) | | ✓ (cosmetic only) |
| TinyUSB + CDC-ECM/CDC-ACM | | ✓ |
| lwIP + ECM netif | | ✓ (LWIP_RAND routed through `s_random`; no NS pico_rand path) |
| SC handshake (X25519, ChaCha20-Poly1305, HKDF *via veneer*, Ed25519 *verify*) | | ✓ |
| Privval parsers (cosmos protobuf, gno amino) + canonical sign-bytes extraction | | ✓ |
| REPL line dispatcher | | ✓ — state-changing commands route through Secure veneers |
| Console history buffer (text content) | ✓ — stored Secure-side; rendered Secure-side | NS pushes lines via `s_console_log` |

NS keeps its own copy of Monocypher (X25519, ChaCha20-Poly1305,
Ed25519 verify, SHA-256). Ed25519 *sign* + SHA-512 only exist in the
Secure copy. Code-size cost of the duplicated subset: ~5-10 KB; on a
4 MB flash this is irrelevant.

The display panel is shared in time, not in space: the Secure side
owns the SPI peripheral and the rendering primitives. The console
("here's a text line, please draw it") is a low-trust veneer NS calls.
Trusted prompts are drawn exclusively by Secure into a reserved
top-of-screen region; NS cannot influence what's shown during a
Secure prompt and cannot drive the display peripheral itself.

#### M9.2 — Secure-callable veneer (NSC ABI, as shipped)

Authoritative declarations live in `firmware/src/os/secure_api.h`.
Summary (NS-callable, all in the `.gnu.sgstubs` section in Secure flash):

```c
// --- Crypto + signing -----------------------------------------------------
int  s_get_pubkey(uint8_t curve, const char *path, uint8_t out_pubkey[32]);

// Length-locked at 32B so it can't be turned into a generic oracle.
int  s_sign_sc_challenge(uint8_t curve, const char *path,
                         const uint8_t challenge[32], uint8_t out_sig[64]);

// Atomic HWM-check + sign. Args packed into a struct because
// cmse_nonsecure_entry caps at 4 register-sized parameters. Secure
// looks up the slot's chain_id internally; NS cannot lie about it.
int  s_sign_and_advance(const s_sign_and_advance_args_t *args);

// --- TRNG + HKDF (M9 Phase 4 narrowing) ----------------------------------
int  s_random(uint8_t *out, size_t n);
int  s_hkdf_extract(const s_hkdf_extract_args_t *args);
int  s_hkdf_expand (const s_hkdf_expand_args_t  *args);

// --- Flash writes (Secure-only on RP2350; NS shims forward here) ---------
int  s_flash_write_chains_page (const void *page, size_t len);
int  s_flash_write_hwm_page    (uint8_t slot_idx, uint16_t page_in_slot,
                                const void *page, size_t len);
int  s_flash_erase_hwm_slot    (uint8_t slot_idx);
int  s_flash_erase_hwm_sector  (uint8_t slot_idx, uint8_t sector_in_slot);
int  s_flash_erase_hwm_all     (void);

// --- Trusted UI / display / input -----------------------------------------
void s_display_init     (void);
void s_splash_render    (void);
void s_console_init     (void);
void s_console_log      (const char *line, size_t len);
void s_console_clear_history(void);
void s_console_render   (void);          // fast LUT
void s_console_render_clean(void);       // multi-pass clean
bool s_console_is_dirty (void);
uint8_t s_mode_select_prompt(void);      // returns os_mode_t
bool s_factory_reset_with_consent(void); // 5s-hold + 3s countdown
bool s_input_pressed    (uint8_t btn);   // 0 = LEFT, 1 = RIGHT

// --- M9.5: PIN / per-slot seed override ----------------------------------
int     s_pin_setup     (void);   // Secure-driven UI; no NS args
int     s_pin_unlock    (void);
bool    s_pin_is_initialized(void);
uint8_t s_pin_attempts  (void);

uint8_t s_slot_seed_source(uint8_t slot_idx);   // 0=DERIVED, 1=MNEMONIC, 2=RAW_KEY
int     s_slot_setup_mnemonic(uint8_t slot_idx);
int     s_slot_import_raw_key(uint8_t slot_idx, const uint8_t priv32[32]);
int     s_slot_clear_override(uint8_t slot_idx);

uint32_t s_clock_get_hz(uint8_t clock_idx);     // NS skips runtime_init_clocks
```

`os_crypto_sign` is a thin NS shim. The non-fused path (`s_sign_privval`)
that existed in early Phase 2 was retired in Phase 5: NS-side
`os_crypto_sign` accepts only 32-byte data (the SC challenge), and
privval canonical sign-bytes must go through `s_sign_and_advance`
directly. `s_chains_*` veneers were planned but never shipped — NS's
chain-config writes go through the page-level `s_flash_write_chains_page`
veneer, with chain validation living in NS's own (read-only)
`chains_add` / `chains_remove` callers. The Secure side keeps its own
chain + HWM cache for the signing dispatch path and re-reads from
flash on boot.

#### M9.3 — Implementation phases (as shipped)

`pico-sdk` 2.2.0 ships SAU + ACCESSCTRL register definitions and the
Cortex-M33 CMSIS core header, but *no* middleware: no NSC veneer
helpers, no S/NS linker script template, no example apps. The split
is built from scratch on top of those primitives. Six phases landed:

- **Phase 1 — Secure-owned bring-up + minimal NS runtime.** Dual-ELF
  build (`picowallet_secure.elf` at 0x10000000, `picowallet.elf` at
  0x10080000), SAU R0..R4 programmed by the Secure stub, ACCESSCTRL
  open to NS, bootrom-state-reset + `runtime_init_*` calls all run
  Secure-side before BXNS. NS uses pico-sdk's crt0 with
  `PICO_RUNTIME_SKIP_INIT_*` for every bootrom-touching initializer.
  Empty `__init_array` on the NS side suppresses `pico_unique_id`'s
  constructor. NSACR + CPACR_NS opened for CP0 (gpioc) + CP4/CP7 (RCP).
  IRQs routed NS-side via NVIC_ITNS[0..15] = 0xFFFFFFFF.
- **Phase 2 — NSC veneer entries.** SG stubs in `.gnu.sgstubs`
  (renamed from the placeholder `.nsc` once GCC's linker requirement
  was found). Every NS pointer arg validated with
  `cmse_check_address_range`. Phase 2 covers all of the §M9.2 ABI
  except the M9.5-specific veneers, which landed in Phase 7.
- **Phase 3 — Build system.** Two-ELF CMake build, `merge_uf2.py`
  packaging, openocd-based flashing via the Pi Debug Probe, Makefile
  targets `m9-build` / `m9-attach` / `m9-attach-ns` /
  `m9-openocd` / `m9-flash-probe`.
- **Phase 4 — ACCESSCTRL + DMA + GPIO_NSMASK lockdown.** TRNG,
  SHA-256, OTP, POWMAN, WATCHDOG, CLOCKS, XOSC, ROSC, PLL_SYS,
  PLL_USB, SPI1 all narrowed to Secure-only. GPIO_NSMASK bits 8..13
  cleared from NS (e-paper pins). DMA channel 0 LOCK'd as
  Secure-only via SECCFG_CH0. NS-side adaptations: skip
  `runtime_init_clocks`, route `LWIP_RAND` through `s_random`,
  override `pico_sha256_lock` to a software no-op (bootlock at
  0x400E080C is Secure-only).
- **Phase 5 — USB/lwIP audit + transitional cleanup.** Confirmed
  TinyUSB DPRAM + endpoint FIFOs + lwIP pbuf pools all live in NS
  RAM (0x20020000..0x20081FFF). The Phase 2 `s_sign_privval` veneer
  (which would have been a generic signing oracle without HWM
  enforcement) was retired and the matching REPL command gated off
  under TZ — privval canonical sign-bytes now must use
  `s_sign_and_advance` directly.
- **Phase 6 — End-to-end revalidation + negative test.** Build-flag
  `PICOWALLET_M9_NEGATIVE_TEST` adds an NS load of
  0x10000000 at boot; expected behavior is `SecureFault.AUVIOL` ->
  Secure HardFault handler loops. Verified on hardware: `SFSR=0x48`
  (AUVIOL + LSERR), `SFAR=0x10000000`, `HFSR=0x40000000` (FORCED).
  Boundary holds.


#### M9.4 — Quirks learned in flight (kept here for future pico-sdk upgrades)

- **`bench.c`** still uses Monocypher's Ed25519 directly with a local
  test seed (its NS copy). Doesn't touch the real keystore; left
  intact.
- **pico-sdk runtime_init is essentially Secure-only.**
  `bootrom_reset`, `per_core_bootrom_reset`,
  `bootrom_locking_enable`, `early_resets`, `usb_power_down`,
  `clocks`, `post_clock_resets`, `boot_locks_reset`,
  `spin_locks_reset`, `per_core_enable_coprocessors` all run from
  Secure context; NS suppresses them via `PICO_RUNTIME_SKIP_INIT_*`.
  Any pico-sdk upgrade needs a re-audit for new bootrom-touching
  initializers.
- **Bootrom NS API surface is 8 functions.** `get_sys_info`,
  `checked_flash_op`, `flash_runtime_to_storage_addr`,
  `get_partition_table_info`, `secure_call`, `otp_access`, `reboot`,
  `get_b_partition`. Anything else NS-side lookups returns 0 → bx 0
  → fault. `rom_bootrom_state_reset(GLOBAL_STATE)` clears the
  permission bitmap, so the Secure stub re-grants the 8 NS API bits
  after the reset, before BXNS.
- **`__attribute__((constructor))` in SDK modules.** `pico_unique_id`'s
  constructor calls `GET_SYS_INFO` which faults from NS; sidestepped by
  emptying `__init_array` in the NS linker script.
- **`gpioc` coprocessor reads from NS are stale on RP2350.** Forced
  fallback to MMIO SIO reads via `PICO_USE_GPIO_COPROCESSOR=0` on the
  NS target. Secure uses the coprocessor without issue.
- **Boot SecureFault recovery escape hatch.** Secure stub bounces to
  `reset_usb_boot(0,0)` if the NS slot's MSP / reset handler are
  unset, so a bad NS flash doesn't require BOOTSEL hold to recover.
- **Console render veneer cost.** Each `s_console_render_*` is a
  cross-world transition + a multi-hundred-ms SPI write. Rendering is
  already lazy (≥10s gap in PrivVal mode); the overhead is irrelevant
  in practice.

### ✓ M9.5 — PIN unlock + at-rest encryption

The M9 boundary covers runtime exploitation of NS code. M9.5 covers
the **physical-extraction** column: master seed + per-slot overrides
are AEAD-sealed on flash, unsealable only with the operator's PIN.

Shipped in six sub-phases (commits `a1f8117` … `ac53df3`):

#### M9.5.1 — Crypto primitives + sealed-blob format

- **Argon2id** KDF (Monocypher), 64 KiB workspace, 3 passes,
  1 lane. Workspace is a Secure-BSS static (`s_argon2_work`,
  ~74 KB total Secure BSS after Phase 7) — Secure SRAM is
  128 KB so we're comfortable.
- **XChaCha20-Poly1305** AEAD. Salt 16 B, nonce 24 B, tag 16 B,
  ciphertext up to 64 B → 120 B per sealed-seed blob (88 B for
  the 32-byte raw-key variant).
- New `SEED_FLASH` region (one 4 KB sector at the QSPI tail just
  below `CHAINS`).
- `m9_seal_payload` / `m9_unseal_payload` are the generic
  primitives; `m9_seal_seed` / `m9_unseal_seed` are 64-byte
  wrappers.
- Smoke test: `s_seal_selftest` veneer round-trips a TRNG payload
  + verifies wrong-PIN rejection. Hardware-verified.

#### M9.5.2 — PIN entry + lock state machine

- 4-8 digit numeric PIN, entered on the device via the LEFT/RIGHT
  buttons (LEFT scrolls down, RIGHT scrolls up, BOTH commits the
  current selection; the wheel cycles 0..9 + DONE).
- PIN is collected entirely in Secure context; NS never sees the
  bytes.
- Attempt counter is a thermometer over 10 counter pages inside
  the `SEED_FLASH` sector. Incremented BEFORE the Argon2id
  attempt (so power-cycling can't reset the count); reset on
  successful unlock by erasing + re-programming the sector.
  10 consecutive failures triggers a full factory wipe of
  `SEED + SLOT_SEEDS + CHAINS + HWM` and the PIN-/seed-caches.
- Veneers: `s_pin_setup` (no args; Secure-driven UI runs the
  set+confirm flow), `s_pin_unlock` (no args; Secure UI prompts
  + Argon2id + unseal), `s_pin_is_initialized`, `s_pin_attempts`.
- e-paper partial-LUT refresh (`display_render_fast`, ~300 ms vs
  the full LUT's ~1 s) makes each digit scroll snappy. The first
  render of every PIN entry session is forced-full to re-baseline
  the panel.
- Boot integration in `main.c`: after splash, loop on
  `s_pin_setup` (first boot) or `s_pin_unlock` (subsequent boots)
  until `M9_PIN_OK` or `M9_PIN_ERR_WIPED` (the wipe path falls
  back to setup on the same boot).

#### M9.5.3 — BIP-39 mnemonic generate + display

- Official BIP-39 English wordlist (2048 entries, ~18 KB Secure
  rodata) shipped as `firmware/src/os/crypto/bip39_wordlist.c`.
- `bip39_generate` produces a 24-word mnemonic from 32 B of TRNG
  entropy with the 8-bit checksum (`SHA-256(entropy)[0]`).
- `bip39_to_seed` is PBKDF2-HMAC-SHA512(2048 iters) over the
  mnemonic phrase with salt `"mnemonic"` (no BIP-39 passphrase
  support yet).
- `pin_ui_show_mnemonic` walks the operator through 4 pages of
  6 words each. Pages 1–3 advance on RIGHT; page 4 requires
  BOTH-press to confirm the operator wrote it down. Each page
  uses a full-LUT render so the words are read cleanly.
- Setup flow inside `s_pin_setup`: PIN-set+confirm → operator
  picks generate-or-restore → generate runs `bip39_generate` +
  `pin_ui_show_mnemonic` + `bip39_to_seed` + seal.

#### M9.5.4 — Button-driven mnemonic restore

- `pin_ui_restore_mnemonic` collects 24 words via a prefix-narrow
  letter wheel.
- **Dynamic wheel**: only letters that actually extend the typed
  prefix into a real BIP-39 word appear in the wheel, computed
  per-prefix from the sorted wordlist. Typical wheel size 2-7
  letters instead of the static 28 (a-z + del + pick). Plus "del"
  + "pick" slots when the prefix is non-empty.
- When the typed prefix uniquely identifies a word (count == 1),
  the device auto-advances; otherwise the operator hits "pick" to
  enter candidate-scroll mode.
- BIP-39 checksum is verified after the 24th word; on mismatch the
  device shows "Bad mnemonic - retry" and loops back to word 1.

#### M9.5.5 — Per-chain-slot seed override

Each of the 16 HWM slots can opt out of master-derived signing by
carrying its own sealed seed material, supporting two override
flavors:

- **MNEMONIC**: 64-byte BIP-39 seed (same generate-or-restore
  flow as master setup). Signs via SLIP-10 over the slot's seed.
- **RAW_KEY**: 32-byte Ed25519 priv-key seed imported from the
  operator's existing `priv_validator_key.json` (REPL-typed hex
  over CDC; for migration scenarios where the validator can't
  regenerate keys without losing delegated stake). Signs the
  key directly with no SLIP-10 derivation.

Storage: new `SLOT_SEEDS_FLASH` region (16 × 4 KB sectors, one
per slot, 64 KB total). `m9_slot_seed_source(slot_idx)` returns
`DERIVED` / `MNEMONIC` / `RAW_KEY` based on the slot sector's
header. Sign-path dispatch in `s_sign_and_advance` branches on
the source after the HWM check.

PIN is cached Secure-side (`m9_pin_cache_*` in `seed_flash.c`)
after a successful unlock so per-slot unseals don't re-prompt.
Cache is cleared on factory wipe.

REPL commands: `os.slot_list`, `os.slot_source <0..15>`,
`os.slot_mnemonic <0..15>`, `os.slot_import <0..15> <64-hex>`,
`os.slot_clear <0..15>`.

#### M9.5.6 — TEST_SEED retirement

`TEST_SEED` is gone. `s_master_seed[64]` (Secure BSS) is
populated by `m9_master_seed_set` after a successful PIN
setup / unlock; `m9_factory_wipe_all` clears it. The DERIVED
signing path fails closed (`KEYSTORE_ERR_BAD_PATH`) if the
seed isn't loaded.

#### M9.5.7 — Optional OTP-binding (gated `PICOWALLET_M9_OTP_BIND`)

`firmware/m9/m9_otp.c` reads / one-time-burns a 32-byte
device secret to OTP row 2048. When the cmake option is ON, the
Argon2id input becomes `OTP_SECRET || PIN` instead of just
`PIN`, so flash-dump-alone attacks cannot brute-force the PIN
offline without ALSO extracting the OTP secret from the chip.
Default is OFF — flipping it ON is a permanent burn per device.

#### M9.5.8 — Factory reset gesture

5-second both-button hold (existing trigger) followed by a
3-second "WIPE in 3 / 2 / 1" countdown. Releasing either button
during the countdown cancels. Past the countdown:
`m9_factory_wipe_all` clears SEED + SLOT_SEEDS + CHAINS + HWM +
PIN cache + master-seed cache, then `watchdog_reboot(0, 0, 0)`
so the next boot lands on a fresh first-boot setup. The
pre-7.5 confirm screen (`os_display_confirm` + ACCEPT/DENY) was
removed under TZ because the 5-second hold IS the consent
gesture; a second screen on top of it created input-handoff
races.

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
| ✓ | PIN unlock + key-at-rest encryption | M9.5 shipped: Argon2id-derived KEK + XChaCha20-Poly1305 AEAD over a BIP-39-derived master seed; PIN attempt counter; per-slot seed overrides. |
| ✓ | Operational metrics over TMKMS REPL | `os.hwm.list`, `os.metrics`, `os.slot_list`, `os.pin_status`. Structured error counters still TODO. |
| ✓ | Factory reset UX | 5 s both-button hold + 3 s countdown → wipes SEED + SLOT_SEEDS + CHAINS + HWM + caches → watchdog_reboot into fresh setup. |
| | Per-chain BIP-44 derivation path | DERIVED slots share `m/0'`; would need per-slot `path` field in `chain_slot_t` + UI for the operator to set it. Per-slot MNEMONIC override gives chain-isolation without this, but BIP-44 hygiene still wants distinct paths. |
| | Multi-validator key selection UX | Named keys + on-device picker. The s_get_pubkey veneer takes any SLIP-10 path; there's no UI for selecting between them at sign time. |
| | Console paging / longer history | 12-line buffer; long logs lose old lines. |
| | Structured error counters | "Last error" + per-class counters reachable from `os.metrics`. |
| | Idle relock | PIN cache + master-seed cache currently persist until reboot or factory wipe. Auto-clear after N minutes of inactivity would shrink the post-unlock window. |
| | Flip `PICOWALLET_M9_OTP_BIND` ON | One-time-permanent OTP burn per device; should happen as part of the production-provisioning workflow alongside M10. |

---

## 5. Codebase layout

```
picowallet/
├── PLAN.md                  this document
├── README.md                build + flash instructions
├── splash.png               source artwork for splash_image.h
├── firmware/
│   ├── CMakeLists.txt             NS image + PICOWALLET_TRUSTZONE option
│   ├── pico_sdk_import.cmake
│   ├── m9/                         M9 TrustZone-M Secure image
│   │   ├── CMakeLists.txt
│   │   ├── layout.h                memory map (SAU regions, NSC, SRAM split)
│   │   ├── memmap_secure.ld        Secure linker script (0x10000000)
│   │   ├── memmap_nonsecure.ld     NS linker script   (0x10080000)
│   │   ├── secure_stub.c           Boot: SAU + ACCESSCTRL + runtime_init + BXNS
│   │   ├── veneers.c               cmse_nonsecure_entry bodies (all s_* fns)
│   │   ├── trng.h / trng.c         Secure-only TRNG word/byte reader
│   │   ├── m9_otp.{h,c}            Per-device OTP secret (gated)
│   │   ├── merge_uf2.py            Combine S + NS UF2s into picowallet_m9.uf2
│   │   └── README.md               LED diagnostic + flashing notes
│   └── src/
│       ├── os/
│       │   ├── main.c                  boot flow + mode dispatch
│       │   ├── secure_api.h            NS-side s_* veneer declarations
│       │   ├── api.{h,c}
│       │   ├── app_registry.{h,c}
│       │   ├── mode.{h,c}              TMKMS / PrivVal enum
│       │   ├── bench.{h,c}             on-device microbenchmarks
│       │   ├── crypto/
│       │   │   ├── monocypher{,-ed25519}.{h,c}   X25519 / Ed25519 / AEAD / Argon2
│       │   │   ├── sha256.{h,c}                  HW-accel SHA, HMAC, HKDF (Secure)
│       │   │   ├── keccak.{h,c}                  Keccak-f1600 (NS)
│       │   │   ├── strobe.{h,c}                  STROBE-128 (NS, Merlin)
│       │   │   ├── merlin.{h,c}                  Labeled transcripts (NS)
│       │   │   ├── keystore.{h,c}                SLIP-10 + master-seed cache
│       │   │   └── bip39.{h,c} + bip39_wordlist.{h,c}   BIP-39 (Secure)
│       │   ├── storage/
│       │   │   ├── flash_layout.h                single source for offsets
│       │   │   ├── seed_flash.{h,c}              Argon2id seal + master seed + PIN counter
│       │   │   ├── slot_seed.{h,c}               per-slot seed override sectors
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
│       │   └── ui/                               splash, console, mode_select,
│       │                                         confirm, factory_reset, pin_ui
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
