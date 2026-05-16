# PicoWallet

A hardware **validator-signing device** for Tendermint-class chains
(cosmos-sdk, gno.land, ...). TMKMS / YubiHSM class — continuous machine-speed
signing, no per-tx UX. Built on the Raspberry Pi Pico 2 (RP2350).

See [`PLAN.md`](PLAN.md) for design, hardware (incl. pin map), milestone
status, and open work.

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
make build         # build firmware → firmware/build/picowallet.uf2
make flash         # build + copy uf2 to a BOOTSEL-mounted Pico
make venv          # one-time: create .venv with the host test deps
make test          # run the gno end-to-end test against a device in PrivVal mode
make repl          # open the TMKMS-mode REPL on the device's CDC port
make clean         # wipe firmware/build
make distclean     # wipe firmware/build AND .venv
```

`make` with no target runs `make build`.

### First flash

1. Hold the Pico's BOOTSEL button while plugging it in via USB.
2. Run `make flash`. The Makefile copies the `.uf2` to the `RPI-RP2`
   mass-storage volume; the Pico reboots into the new firmware
   automatically.

### Test the device

After flashing, the device shows a splash screen for ~4.5 s, then a mode
prompt:

| Hold button | Mode | USB | Use |
|---|---|---|---|
| **LEFT** | TMKMS | CDC serial REPL | Admin: provision per-chain config, inspect state |
| **RIGHT** | PrivVal | CDC-Ethernet (`192.168.7.1`) | Signing |

Reboot to switch.

#### TMKMS-mode admin

Before the device can sign anything, the operator declares one slot per
chain in TMKMS mode. Each cosmos slot has a dial target; each gno slot
has a listen port. Up to 8 of each.

```sh
make repl
# at the prompt:
os.info                            # firmware version + SDK version

# Configure a cosmos chain: device dials cometbft's priv_validator_laddr
os.cosmos.chain.add hub cosmoshub-4 192.168.7.2 26690 [<pubkey-hex>]
os.cosmos.chain.list

# Configure a gno chain: gnoland dials the device's listener at <port>
os.gno.chain.add test test3 26659 [<pubkey-hex>]
os.gno.chain.list

# Maintenance
os.cosmos.chain.remove hub
os.gno.chain.remove test
os.chain.wipe                      # both families, full reset
os.hwm_wipe                        # double-sign cache (for fresh testnet runs)
```

Per-chain settings are flash-persisted. The optional pubkey is the peer's
SecretConnection long-term key; if set, only that exact key authenticates
to that slot (mismatches close the connection immediately after handshake).
A connection's sign requests are also strictly checked against the slot's
chain_id -- a peer cannot request signatures for a different chain.

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
├── firmware/                C sources + CMakeLists
├── tools/                   pwctl.py + helpers
├── splash.png               source artwork for splash_image.h
└── third_party/             pico-sdk + Waveshare e-Paper (submodules)
```

---

## License

TBD. The Pico SDK is BSD-3, Monocypher is BSD-2 / CC0, the Waveshare
e-Paper driver is MIT — pick a license compatible with all three.
