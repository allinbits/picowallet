# PicoWallet

A hardware **validator-signing device** for Tendermint-class chains
(cosmos-sdk, gno.land, ...). TMKMS / YubiHSM class — continuous machine-speed
signing, no per-tx UX. Built on the Raspberry Pi Pico 2 (RP2350).

The firmware is split into a Secure / Non-Secure pair via ARM
TrustZone-M (RP2350 Cortex-M33). The Secure image owns the seed, all
signing material, e-paper SPI + UI rendering, button input, and every
flash mutation; the Non-Secure image runs USB / lwIP / privval parsers
/ SecretConnection / the REPL. NS reaches Secure only through the
veneer API in `firmware/src/os/secure_api.h`. The master seed is a
BIP-39 mnemonic that the operator either generates on-device or
restores from paper; it is sealed at rest with an Argon2id-derived
KEK (PIN-based) and lives in Secure RAM only while the device is
unlocked. Per-chain slots can optionally carry their own mnemonic or
imported priv-key override.

See [`PLAN.md`](PLAN.md) for design, hardware (incl. pin map), milestone
status, threat model, and open work.

---

## 1. Development environment setup

You need: a working ARM cross-compiler, CMake, Python 3, git, and a serial
terminal program.

### macOS

```sh
# Xcode Command Line Tools — git, make, host clang
xcode-select --install

# Homebrew — https://brew.sh/
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Toolchain + build tools + Python + serial terminal
brew install --cask gcc-arm-embedded        # arm-none-eabi-{gcc,g++,ld,gdb}
brew install cmake python@3 git screen
```

`gcc-arm-embedded` is a cask (Arm's official binaries). On Apple Silicon
the cask installs into `/Applications/ARM/` and adds it to PATH; verify with
`arm-none-eabi-gcc --version`.

### Linux — Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y \
    build-essential cmake git \
    gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib \
    python3 python3-venv python3-pip \
    screen
```

> Distro toolchains lag the upstream Arm releases. If you hit C-runtime
> bugs in the resulting binary, download the official Arm GNU Toolchain
> from <https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads>
> and put `arm-none-eabi-gcc` on `PATH`.

### Linux — Fedora / RHEL

```sh
sudo dnf install -y \
    @development-tools cmake git \
    arm-none-eabi-gcc-cs arm-none-eabi-newlib \
    python3 python3-pip \
    screen
```

### Linux — Arch

```sh
sudo pacman -S --needed \
    base-devel cmake git \
    arm-none-eabi-gcc arm-none-eabi-newlib \
    python python-pip \
    screen
```

### Verify

```sh
arm-none-eabi-gcc --version   # any 12.x or newer
cmake --version               # 3.13 or newer
python3 --version             # 3.10 or newer
git --version
```

---

## 2. Clone

```sh
git clone <repo-url> picowallet
cd picowallet
```

Submodules are pulled automatically by `make build` (see below), or you can
do it once explicitly:

```sh
git submodule update --init --recursive
```

The two submodules — pico-sdk @ 2.2.0 and Pico_ePaper_Code @ c9bcd84 —
total about 250 MB on disk after init.

---

## 3. Build, flash, test

The included [`Makefile`](Makefile) wraps everything:

```sh
make help          # list available targets

# Single-image build (TrustZone OFF). Useful for development without
# the dual-image overhead.
make build         # build firmware → firmware/build/picowallet.uf2
make flash         # build + copy uf2 to a BOOTSEL-mounted Pico

# TrustZone-M dual-image build (recommended for any actual signing).
# Produces a single merged UF2 covering both Secure and NS images.
make m9-build      # → firmware/build_m9/picowallet_m9.uf2
make m9-openocd    # in one terminal: openocd via the Pi Debug Probe
make m9-attach     # in another: gdb attached to Secure ELF (faults + symbols)
make m9-attach-ns  # gdb attached with NS symbols loaded
make m9-flash-probe # picotool-based flash via SWD (requires picotool)

# Host-side test harness
make venv          # one-time: create .venv with deps
make test          # gno-sc-handshake end-to-end against a PrivVal device
make repl          # open the TMKMS-mode REPL on the device's CDC port

make clean         # wipe firmware/build
make m9-clean      # wipe firmware/build_m9
make distclean     # wipe both build dirs AND .venv
```

`make` with no target runs `make build`.

### First flash (TrustZone dual-image)

1. `make m9-build` produces `firmware/build_m9/picowallet_m9.uf2`
   (single combined UF2 with both Secure and NS images).
2. Hold BOOTSEL on the Pico while plugging it in.
3. Copy the UF2 onto the `RPI-RP2` (or `RP2350`) volume that
   appears. The Pico reboots into the new firmware automatically.

### First-boot setup (TrustZone build)

On a freshly-flashed (or factory-wiped) device, the boot path is:

1. Splash screen for ~2 s
2. **Set PIN** — wheel cycles 0..9 + DONE; LEFT scrolls down, RIGHT
   scrolls up, BOTH commits the current selection. 4–8 digits.
   After DONE, the device asks for the PIN again (Confirm PIN). A
   mismatch loops back to Set PIN.
3. **Setup mode chooser** — LEFT for RESTORE (type an existing
   24-word mnemonic), RIGHT for GENERATE (device makes a fresh one
   and shows it to you across 4 pages of 6 words; you MUST write
   them down — they're the only backup).
4. Device derives the BIP-39 seed (PBKDF2-HMAC-SHA512 × 2048), seals
   it under the PIN-derived KEK (Argon2id, 64 KiB / t=3), persists
   the sealed blob to `SEED_FLASH`, then advances to mode-select.

On subsequent boots the splash is followed by **Enter PIN**; 10
consecutive wrong PINs wipes all four persistent regions and reboots
into first-boot setup.

### Mode select

After unlock the device prompts for an operating mode:

| Hold button | Mode | USB | Use |
|---|---|---|---|
| **LEFT** | PrivVal | CDC-Ethernet (`192.168.7.1`) | Signing |
| **RIGHT** | TMKMS | CDC serial REPL | Admin: provision per-chain config, inspect state |

Reboot to switch.

### Factory reset

In any mode: hold **both buttons for 5 seconds** to arm the wipe,
then keep both held through the 3-second `WIPE in 3 / 2 / 1`
countdown shown on the e-paper. Releasing either button during the
countdown cancels. Completing the countdown erases SEED + SLOT_SEEDS
+ CHAINS + HWM + the in-RAM caches, then reboots into first-boot
setup. There is no "are you sure" screen — the long hold IS the
consent gesture.

#### TMKMS-mode admin

Before the device can sign anything, the operator declares one slot per
chain in TMKMS mode. Each cosmos slot has a dial target; each gno slot
has a listen port. Up to 8 of each.

```sh
make repl
# at the prompt:
os.info                            # firmware version + SDK version
os.pin_status                      # initialized + failed attempts
os.metrics                         # uptime, active slots, total signs

# Configure a cosmos chain: device dials cometbft's priv_validator_laddr
os.cosmos.chain.add hub cosmoshub-4 192.168.7.2 26690 [<pubkey-hex>]
os.cosmos.chain.list

# Configure a gno chain: gnoland dials the device's listener at <port>
os.gno.chain.add test test3 26659 [<pubkey-hex>]
os.gno.chain.list

# Per-chain seed overrides (M9.5 Phase 7.5) — each of the 16 slots can
# carry its own mnemonic or imported raw priv-key.
os.slot_list                       # all 16 slots with chain_id + source
os.slot_source <0..15>             # DERIVED / MNEMONIC / RAW_KEY
os.slot_mnemonic <0..15>           # set slot mnemonic via on-device UI
os.slot_import   <0..15> <64-hex>  # seal a 32B priv-key for the slot
os.slot_clear    <0..15>           # drop override → DERIVED

# Maintenance
os.cosmos.chain.remove hub
os.gno.chain.remove test
os.chain.wipe                      # both families, full reset
os.hwm.list                        # show HWM state per chain slot
os.hwm.wipe                        # erase all HWM state (fresh testnet runs)
os.factory_reset                   # → Secure-driven 3-sec countdown → wipe everything
```

Per-chain settings are flash-persisted. The optional pubkey is the peer's
SecretConnection long-term key; if set, only that exact key authenticates
to that slot (mismatches close the connection immediately after handshake).
A connection's sign requests are also strictly checked against the slot's
chain_id -- a peer cannot request signatures for a different chain.

Slots with a `MNEMONIC` override sign with a SLIP-10 derivation from
the slot's own BIP-39 seed; `RAW_KEY` slots use the imported 32-byte
Ed25519 seed directly. `DERIVED` (default) slots use the master
mnemonic + the (currently hardcoded) `m/0'` path. The slot's
effective validator pubkey changes with the source — query via
`os.pubkey ed25519 m/0'` for the master, and check the chain
operator's expected pubkey before configuring genesis.

#### PrivVal-mode tests

Boot into PrivVal mode (RIGHT) once at least one chain is configured.

```sh
# Gno SecretConnection + amino privval (uses whichever port your gno
# slot binds; defaults shown match `os.gno.chain.add test test3 26659`).
.venv/bin/python tools/pwctl.py gno-sc-handshake --sign-height 1000000

# Or, shorthand:
make test
```

Every returned signature is verified host-side against the device's
authenticated pubkey.

Cosmos paths are exercised end-to-end via the integration testnet (see
[`scripts/README.md`](scripts/README.md)); pwctl no longer has a direct
"dial the device's cosmos listener" mode since the device only dials out.

---

## 4. Layout

See [`PLAN.md`](PLAN.md) §5 for the full tree.

```
picowallet/
├── Makefile                 build/flash/test entry points
├── PLAN.md                  design, hardware, milestone status
├── README.md                this file
├── firmware/
│   ├── CMakeLists.txt       Non-Secure target (single-image OR M9 NS half)
│   ├── m9/                  Secure image (TrustZone stub + veneers)
│   ├── src/                 OS + apps (compiled into NS; some files also
│   │                        gated into the Secure target via the
│   │                        PICOWALLET_SECURE_BUILD pattern)
│   └── build_m9/            CMake artifacts for the dual-image build
├── tools/                   pwctl.py + helpers
├── splash.png               source artwork for splash_image.h
└── third_party/             pico-sdk + Waveshare e-Paper (submodules)
```

## 5. Build flags worth knowing

CMake options (all default OFF):

| Flag | Effect |
|---|---|
| `PICOWALLET_TRUSTZONE` | Dual-image M9 build (Secure stub at `0x10000000` + NS at `0x10080000`). The `m9-*` Makefile targets set this automatically. |
| `PICOWALLET_M9_NEGATIVE_TEST` | Adds an NS-deref-of-Secure-VA read at boot to verify the SAU boundary holds (expect `SecureFault.AUVIOL`). Flip OFF for normal use. |
| `PICOWALLET_M9_OTP_BIND` | **Permanent OTP burn**. Mixes a per-device 32-byte OTP-stored secret into the Argon2id KEK input so a flash-dump-alone attack can't brute-force the PIN. Only enable once you're committed to the OTP layout (M10-class production provisioning). |

---

## License

TBD. The Pico SDK is BSD-3, Monocypher is BSD-2 / CC0, the Waveshare
e-Paper driver is MIT — pick a license compatible with all three.
