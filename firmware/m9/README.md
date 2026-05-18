# M9 — TrustZone-M split, build artifacts

Memory layout, linker scripts, and secure-stub source for the M9 split.
See `PLAN.md` §M9 for the architectural design and threat model. This
directory is intentionally separate from `firmware/src/` so the
existing single-image build is untouched while M9 lands phase by phase.

Phases land as separate commits:

  - **1a.** Memory layout + linker scripts. CMake option
    `PICOWALLET_TRUSTZONE` registered but inactive.
  - **1b.** Secure stub (SAU configuration + BXNS handoff to the
    Non-Secure reset handler) + dual-image build.
  - **1b.1 (this commit).** Defensive Secure stub (re-enters USB
    BOOTSEL if the NS image is missing or corrupted instead of
    BXNS'ing into garbage) + a `merge_uf2.py` helper so `make
    m9-build` produces a single combined `picowallet_m9.uf2`.
  - **1c onward.** First-boot smoke test on hardware; iterate on
    SAU boundaries and ACCESSCTRL defaults.
  - **2.x.** Migrate the keystore, signing, HWM writes, chain config
    writes, display, and button input into the Secure image; replace
    Non-Secure call sites with the veneer symbols declared in
    `firmware/src/os/secure_api.h`.

## Flash workflow

```
make m9-build
# Hold BOOTSEL while plugging in the Pico 2 → RPI-RP2 mounts.
cp firmware/build_m9/picowallet_m9.uf2 /Volumes/RPI-RP2/
# Device reboots; Secure stub runs, BXNS to NS, NS firmware comes up
# as usual (splash, mode select, REPL or PrivVal).
```

If the Secure stub finds the NS slot empty or corrupted (vector
table entries look like `0xFFFFFFFF`, or the initial SP / reset
handler point outside their expected regions), it calls
`reset_usb_boot(0, 0)` and the device re-enters BOOTSEL on its own
-- no need to hold the button. The same recovery fires if a future
NS-side flash gets interrupted mid-write.

## LED diagnostics

The secure stub keeps the LED reserved as a side channel for the
defensive bricking-recovery path. The boot-time success-blink that ran
in early Phase 1 has been removed -- it cost ~1.5 s on every boot and
the path is now solid enough not to need a witness.

| What you see | What it means |
|---|---|
| LED never lights, no splash | bootrom rejected the .uf2 (run `picotool info` on it) OR Secure stub faulted before reaching the NS image |
| 1 long blink → BOOTSEL | NS vector table is `0xFFFFFFFF` (NS image not flashed) |
| 2 long blinks → BOOTSEL | NS initial SP outside `0x20020000..0x20082000` |
| 3 long blinks → BOOTSEL | NS reset handler outside `0x10080000..0x10400000` |
| Splash on the e-paper, then mode select | Phase 1 working |

## Debugging via the Pi debug probe

Once `openocd` and `arm-none-eabi-gdb` are installed (`brew install openocd`
on macOS), wire the probe's SWCLK/SWDIO/GND to the Pico 2's SWD pins and
connect the probe over USB. Then:

```
# terminal 1 -- openocd on default ports (3333=gdb, 4444=telnet)
openocd -f interface/cmsis-dap.cfg -c "adapter speed 5000" -f target/rp2350.cfg

# terminal 2 -- attach to whatever the chip is doing now
arm-none-eabi-gdb \
    -ex "target extended-remote :3333" \
    -ex "monitor halt" \
    -ex "info reg pc lr msp psp control" \
    firmware/build_m9/m9/picowallet_secure.elf
```

`info reg pc` is the most useful first line: where is the chip stuck?
Cross-reference with `arm-none-eabi-objdump -d firmware/build_m9/m9/picowallet_secure.elf`
(or the NS image's .elf) to find the line.

Useful follow-ups inside gdb:
  - `monitor mdw 0xe002ed28 1` -- read SCB_NS->CFSR (the NS-side fault
    status register; non-zero bits say what kind of fault occurred).
  - `monitor mdw 0xe000edfc 1` -- read DEMCR.
  - `monitor mdw 0xe000ed24 1` -- read SHCSR (System Handler Control).
  - `monitor mdw 0xe000ed28 1` -- read S-side CFSR.
  - `monitor mdw 0xe000ed34 1` -- HFSR (hardfault).

Picotool also works through the probe (no BOOTSEL needed):
  - `picotool load -d firmware/build_m9/picowallet_m9.uf2` -- write flash via SWD
  - `picotool save -d --range 0x10080000 0x10080020 dump.bin` -- read the NS vector table directly
  - `picotool reboot -d` -- clean restart

## Memory layout (Phase 1)

Flash (4 MB, base `0x10000000`):

```
0x10000000  ┌─────────────────────────────────────────────┐
            │  Secure image     (.vectors, .text, …)       │
            │   includes Secure IMAGE_DEF block            │
            │   includes the eventual NSC veneers          │
0x10080000  ├─────────────────────────────────────────────┤
            │  Non-Secure image (.vectors, .text, …)       │
            │   includes Non-Secure IMAGE_DEF block        │
            │  ↓ unused / growth ↓                         │
0x102FF000  ├─────────────────────────────────────────────┤
            │  Chains config    (4 KB sector)              │
            │   Secure-write, Non-Secure-read via XIP      │
0x10300000  ├─────────────────────────────────────────────┤
            │  HWM region       (1 MB / 256 sectors)       │
            │   Secure-write, Non-Secure-read via XIP      │
0x10400000  └─────────────────────────────────────────────┘
```

SRAM (520 KB, base `0x20000000`):

```
0x20000000  ┌─────────────────────────────────────────────┐
            │  Secure SRAM       (128 KB)                  │
            │   secure stack, seed, crypto buffers,        │
            │   HWM cache, chain config RAM cache          │
0x20020000  ├─────────────────────────────────────────────┤
            │  Non-Secure SRAM   (384 KB)                  │
            │   TinyUSB pools, lwIP buffers, console,      │
            │   NS heap + NS core0/1 stacks                │
0x20080000  ├─────────────────────────────────────────────┤
            │  SCRATCH_X         (4 KB, Non-Secure)        │
0x20081000  ├─────────────────────────────────────────────┤
            │  SCRATCH_Y         (4 KB, Non-Secure)        │
0x20082000  └─────────────────────────────────────────────┘
```

## SAU regions

RP2350's IDAU defaults every address to Secure. SAU overrides carve
out the Non-Secure and NSC regions. We use three regions in Phase 1
(SAU has 8 available):

| # | Range | Attribute |
|---|---|---|
| 0 | `0x1007F000`–`0x10080000` | NSC (4 KB veneer region at end of Secure code) |
| 1 | `0x10080000`–`0x10400000` | Non-Secure (NS code + chains config + HWM, NS-readable via XIP) |
| 2 | `0x20020000`–`0x20082000` | Non-Secure (NS SRAM + scratch banks) |

Flash *writes* to the Chains and HWM regions remain Secure-only --
they go through the QSPI flash controller registers, which we
restrict via ACCESSCTRL in Phase 1b. SAU is only about the
memory-mapped (XIP) read path.

## File map

  - `layout.h` — region constants used by both linker scripts and (in
    1b) the SAU configuration code.
  - `memmap_secure.ld` — linker script for the Secure image.
  - `memmap_nonsecure.ld` — linker script for the Non-Secure image
    (the existing picowallet code, re-targeted at `0x10080000`).
  - (1b) `secure_stub.c` — boot-time SAU/ACCESSCTRL configuration +
    BLXNS to the Non-Secure reset handler.
  - (1b) `secure_stub_entry.S` — reset vector and any inline assembly.
