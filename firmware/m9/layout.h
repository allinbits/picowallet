#pragma once

// M9 memory layout. Used by:
//   - memmap_secure.ld and memmap_nonsecure.ld (via -DM9_LAYOUT_*=...
//     on the linker command line; the .ld files reference these
//     symbols and CMake feeds them in from this header).
//   - secure_stub.c (SAU configuration, Phase 1b).
//
// Any change here is a change to the trust boundary -- read PLAN.md §M9
// before touching it.

// --- Flash --------------------------------------------------------------

#define M9_FLASH_BASE              0x10000000u
#define M9_FLASH_SIZE              0x00400000u   // 4 MB total

// Secure image (vectors, .text, .rodata, NSC veneer at the tail).
#define M9_SECURE_FLASH_BASE       0x10000000u
#define M9_SECURE_FLASH_SIZE       0x00080000u   // 512 KB

// NSC (Non-Secure Callable) veneer lives at the last page of the
// Secure region so the SAU can carve it out cleanly. ARMv8-M requires
// the NSC region to be inside Secure space.
#define M9_NSC_BASE                0x1007F000u
#define M9_NSC_SIZE                0x00001000u   // 4 KB

// Non-Secure image base. Boot ROM hands control here via BLXNS after
// the Secure stub finishes its setup.
#define M9_NONSECURE_FLASH_BASE    0x10080000u
#define M9_NONSECURE_FLASH_SIZE    0x0027F000u   // ~2.5 MB code budget

// Persistent regions accessed memory-mapped by Non-Secure (reads) and
// via the flash controller by Secure (writes). Offsets unchanged from
// the pre-M9 firmware so existing chain config + HWM data survive the
// transition.
#define M9_CHAINS_FLASH_BASE       0x102FF000u
#define M9_CHAINS_FLASH_SIZE       0x00001000u   // 4 KB
#define M9_HWM_FLASH_BASE          0x10300000u
#define M9_HWM_FLASH_SIZE          0x00100000u   // 1 MB

// --- SRAM ---------------------------------------------------------------

#define M9_SRAM_BASE               0x20000000u

#define M9_SECURE_SRAM_BASE        0x20000000u
#define M9_SECURE_SRAM_SIZE        0x00020000u   // 128 KB

#define M9_NONSECURE_SRAM_BASE     0x20020000u
#define M9_NONSECURE_SRAM_SIZE     0x00060000u   // 384 KB

// Scratch banks stay Non-Secure (SDK puts core0/core1 stacks here).
#define M9_SCRATCH_X_BASE          0x20080000u
#define M9_SCRATCH_X_SIZE          0x00001000u   // 4 KB
#define M9_SCRATCH_Y_BASE          0x20081000u
#define M9_SCRATCH_Y_SIZE          0x00001000u   // 4 KB

// --- SAU regions (consumed by secure_stub.c in Phase 1b) ----------------

// Helper to compute SAU_RLAR field. ARMv8-M requires base+limit to be
// 32-byte aligned. Limit is the inclusive last address of the region
// (i.e. base + size - 1, then mask off bottom 5 bits).
#define M9_SAU_LIMIT(base, size)   (((base) + (size) - 1u) & ~0x1Fu)

// Region attribute encoding shorthand (matches PLAN.md §M9.1 table).
#define M9_SAU_REGION_COUNT        3

// Region 0: NSC veneer (Secure, callable from Non-Secure).
#define M9_SAU_R0_BASE             M9_NSC_BASE
#define M9_SAU_R0_LIMIT            M9_SAU_LIMIT(M9_NSC_BASE, M9_NSC_SIZE)
#define M9_SAU_R0_NSC              1

// Region 1: Non-Secure flash (NS code + chains config + HWM, XIP reads).
#define M9_SAU_R1_BASE             M9_NONSECURE_FLASH_BASE
#define M9_SAU_R1_LIMIT            M9_SAU_LIMIT(M9_NONSECURE_FLASH_BASE, \
                                       (M9_FLASH_BASE + M9_FLASH_SIZE) \
                                       - M9_NONSECURE_FLASH_BASE)
#define M9_SAU_R1_NSC              0

// Region 2: Non-Secure SRAM + scratch banks.
#define M9_SAU_R2_BASE             M9_NONSECURE_SRAM_BASE
#define M9_SAU_R2_LIMIT            M9_SAU_LIMIT(M9_NONSECURE_SRAM_BASE, \
                                       (M9_SCRATCH_Y_BASE + M9_SCRATCH_Y_SIZE) \
                                       - M9_NONSECURE_SRAM_BASE)
#define M9_SAU_R2_NSC              0
