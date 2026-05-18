# M9 — TrustZone-M split, build artifacts

Memory layout, linker scripts, and secure-stub source for the M9 split.
See `PLAN.md` §M9 for the architectural design and threat model. This
directory is intentionally separate from `firmware/src/` so the
existing single-image build is untouched while M9 lands phase by phase.

Phases land as separate commits:

  - **1a (this commit).** Memory layout + linker scripts. CMake option
    `PICOWALLET_TRUSTZONE` registered but inactive; nothing in this
    directory is wired into the build yet.
  - **1b.** Secure stub (SAU + ACCESSCTRL configuration, BLXNS handoff
    to the Non-Secure reset handler) + CMake glue that produces a
    dual-image UF2 when `-DPICOWALLET_TRUSTZONE=ON`. Both ELFs link;
    the device boots through Secure into Non-Secure with no behavior
    change for the user.
  - **2.x.** Migrate the keystore, signing, HWM writes, chain config
    writes, display, and button input into the Secure image; replace
    Non-Secure call sites with the veneer symbols declared in
    `firmware/src/os/secure_api.h`.

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
