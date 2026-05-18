// M9 Phase 1b -- Secure-side bringup stub.
//
// Runs at 0x10000000 after the boot ROM hands off. Does the minimum
// work needed to expose the Non-Secure world to the rest of the
// firmware:
//
//   1. Program the SAU with the regions declared in firmware/m9/layout.h
//      (one NSC range at the tail of Secure flash, one NS flash range
//      covering the NS image + chains config + HWM, one NS SRAM range
//      covering the NS image's RAM + scratch banks).
//   2. Branch-with-state-switch (BXNS) to the Non-Secure image's reset
//      handler at M9_NONSECURE_FLASH_BASE.
//
// ACCESSCTRL peripheral attribution is deferred to Phase 4. Phase 1b
// only verifies the SAU + BXNS plumbing -- the existing firmware
// keeps doing what it does today, just from inside Non-Secure state.
//
// The seed remains in NS in Phase 1b (it lives in keystore.c's
// TEST_SEED, compiled into the NS image). Phase 2.x onward migrates
// keystore, signing, HWM writes, chain config writes, display, and
// button input into the Secure image and replaces the call sites in
// firmware/src/ with the veneers declared in os/secure_api.h.

#include <stdint.h>

#include "hardware/structs/sau.h"
#include "pico/bootrom.h"

#include "layout.h"

// NS view of the System Control Block VTOR register. Set this before
// BXNS so the core finds the NS image's vector table on entry.
#define SCB_NS_VTOR_PTR  ((volatile uint32_t *)0xE002ED08u)

// Validate the NS image's vector table before we jump into it. If the
// NS image hasn't been flashed yet (the slot is erased: 0xFFFFFFFF) or
// the pointers are nonsense, fault->lockup makes the device unflashable
// without holding BOOTSEL on power-on. Instead we drop straight to USB
// BOOTSEL so the operator can flash the NS image without re-cycling
// the BOOTSEL button. Same goes for any future situation where the NS
// image is corrupted -- we recover via re-flash rather than brick.
static int ns_image_looks_valid(uint32_t ns_msp, uint32_t ns_reset) {
    // Erased flash sentinel.
    if (ns_msp == 0xFFFFFFFFu || ns_reset == 0xFFFFFFFFu) return 0;
    // Initial SP must point into NS SRAM (incl. scratch banks).
    if (ns_msp < M9_NONSECURE_SRAM_BASE
        || ns_msp > (M9_SCRATCH_Y_BASE + M9_SCRATCH_Y_SIZE)) return 0;
    // Reset handler must point into NS flash. Mask off the Thumb bit
    // (set by the toolchain on all function pointers).
    uint32_t entry = ns_reset & ~1u;
    if (entry < M9_NONSECURE_FLASH_BASE
        || entry >= (M9_FLASH_BASE + M9_FLASH_SIZE)) return 0;
    return 1;
}

static void m9_sau_program(void) {
    // Disable SAU before reprogramming. Required by ARMv8-M to avoid
    // transient mismatched attributions while we're rewriting.
    sau_hw->ctrl = 0u;
    __asm__ volatile("dsb");

    // Region 0: NSC veneer at the tail of Secure flash. NSC=1 means
    // Non-Secure code may execute Secure Gateway (SG) instructions
    // landing here -- the future veneer entry points.
    sau_hw->rnr  = 0u;
    sau_hw->rbar = M9_SAU_R0_BASE;
    sau_hw->rlar = M9_SAU_R0_LIMIT | ((uint32_t)M9_SAU_R0_NSC << 1) | 1u;

    // Region 1: Non-Secure flash. Covers NS code (0x10080000) through
    // end of flash (0x10400000) so chains config + HWM are NS-readable
    // via XIP. Flash *writes* still go through the QSPI flash
    // controller, which ACCESSCTRL restricts in Phase 4.
    sau_hw->rnr  = 1u;
    sau_hw->rbar = M9_SAU_R1_BASE;
    sau_hw->rlar = M9_SAU_R1_LIMIT | ((uint32_t)M9_SAU_R1_NSC << 1) | 1u;

    // Region 2: Non-Secure SRAM (0x20020000-0x20082000), includes the
    // scratch banks where the SDK puts core0/core1 stacks.
    sau_hw->rnr  = 2u;
    sau_hw->rbar = M9_SAU_R2_BASE;
    sau_hw->rlar = M9_SAU_R2_LIMIT | ((uint32_t)M9_SAU_R2_NSC << 1) | 1u;

    // Enable SAU. ALLNS=0 means anything outside the configured regions
    // stays Secure (matches the RP2350 IDAU default for flash + SRAM).
    sau_hw->ctrl = 1u;
    __asm__ volatile("dsb; isb");
}

__attribute__((noreturn))
static void m9_branch_to_nonsecure(void) {
    // Vector table layout at the NS image's base:
    //   word 0: initial SP
    //   word 1: reset handler entry (Thumb, so bit 0 is set in the
    //           pointer; we mask it off below to indicate "switch to
    //           NS" semantics for BXNS).
    uint32_t *ns_vt    = (uint32_t *)M9_NONSECURE_FLASH_BASE;
    uint32_t  ns_msp   = ns_vt[0];
    uint32_t  ns_reset = ns_vt[1];

    if (!ns_image_looks_valid(ns_msp, ns_reset)) {
        // NS image absent or corrupted. Don't BXNS into garbage --
        // hand control back to the boot ROM's USB BOOTSEL flow so the
        // operator can drop a fresh .uf2 in. reset_usb_boot is
        // noreturn.
        reset_usb_boot(0, 0);
    }

    // Set NS MSP. MSP_NS is the Non-Secure Main Stack Pointer alias;
    // only Secure code can write it. Requires -mcmse on the toolchain.
    __asm__ volatile("msr msp_ns, %0" : : "r" (ns_msp));

    // Point NS-side VTOR at the NS vector table. The CPU consults this
    // when an exception fires while running in NS state.
    *SCB_NS_VTOR_PTR = (uint32_t)M9_NONSECURE_FLASH_BASE;

    // BXNS: branch and switch security state. Bit 0 of the target
    // address is the destination state indicator -- 0 = NS, 1 = stay
    // in S. We clear it explicitly even though the NS reset handler
    // address is Thumb-encoded (bit 0 set), because BXNS itself does
    // not use the Thumb bit the way BX/BLX do.
    ns_reset &= ~1u;
    __asm__ volatile("bxns %0" : : "r" (ns_reset));
    __builtin_unreachable();
}

int main(void) {
    m9_sau_program();
    // ACCESSCTRL configuration deferred to Phase 4. The reset defaults
    // (after the boot ROM's setup) let Core0 in NS state reach the
    // USB / GPIO / SPI peripherals the existing firmware uses. TRNG
    // and SHA stay Secure-only -- NS will get those via veneers in
    // Phase 2.x.
    m9_branch_to_nonsecure();
    __builtin_unreachable();
}
