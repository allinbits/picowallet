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
#include "pico/stdlib.h"

#include "layout.h"

// ---- Phase 1c diagnostic LED blink ---------------------------------------
//
// The Secure stub has no UART / USB / display to tell the operator what
// happened, so we use the onboard LED as a side channel. The exact
// pattern the operator sees on flash:
//
//   1 long blink, then BOOTSEL  -> NS vector table is 0xFFFFFFFF
//                                  (NS image not flashed / erased)
//   2 long blinks, then BOOTSEL -> NS initial SP is out of NS SRAM range
//   3 long blinks, then BOOTSEL -> NS reset handler is out of NS flash range
//   solid LED for ~1 s then off -> validation passed; BXNS to NS in progress.
//                                  If BOOTSEL appears after that, the fault
//                                  is on the NS side (e.g. ACCESSCTRL blocks
//                                  NS access to some peripheral).
//   LED never lights up         -> the Secure stub never ran (bootrom
//                                  rejected the image, or main() faulted
//                                  before this point).
//
// All blink delays are busy-loop based -- no SysTick, no timer, no IRQs.

#define LED_PIN PICO_DEFAULT_LED_PIN

static void busy_wait_short(void) { for (volatile int i = 0; i < 4000000; i++); }
static void busy_wait_long (void) { for (volatile int i = 0; i <12000000; i++); }

static void led_init(void) {
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    gpio_put(LED_PIN, 0);
}

static void led_blink_n_then_bootsel(int n) {
    for (int i = 0; i < n; i++) {
        gpio_put(LED_PIN, 1);
        busy_wait_long();
        gpio_put(LED_PIN, 0);
        busy_wait_short();
    }
    // Give the operator a moment to count, then drop to BOOTSEL.
    busy_wait_long();
    reset_usb_boot(0, 0);
}

// NS view of the System Control Block VTOR register. Set this before
// BXNS so the core finds the NS image's vector table on entry.
#define SCB_NS_VTOR_PTR  ((volatile uint32_t *)0xE002ED08u)

// Validate the NS image's vector table. Returns the blink-code on failure
// (1..3 per the table at the top of this file) or 0 on success.
static int validate_ns_image(uint32_t ns_msp, uint32_t ns_reset) {
    if (ns_msp == 0xFFFFFFFFu || ns_reset == 0xFFFFFFFFu) return 1;
    if (ns_msp < M9_NONSECURE_SRAM_BASE
        || ns_msp > (M9_SCRATCH_Y_BASE + M9_SCRATCH_Y_SIZE)) return 2;
    uint32_t entry = ns_reset & ~1u;
    if (entry < M9_NONSECURE_FLASH_BASE
        || entry >= (M9_FLASH_BASE + M9_FLASH_SIZE)) return 3;
    return 0;
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
    uint32_t *ns_vt    = (uint32_t *)M9_NONSECURE_FLASH_BASE;
    uint32_t  ns_msp   = ns_vt[0];
    uint32_t  ns_reset = ns_vt[1];

    int rc = validate_ns_image(ns_msp, ns_reset);
    if (rc != 0) {
        led_blink_n_then_bootsel(rc);   // no return
        __builtin_unreachable();
    }

    // Validation passed: LED solid on while we set up + BXNS, so the
    // operator sees one steady blink rather than the count-and-recover
    // pattern above. The LED stays on through BXNS; NS code can turn
    // it off whenever it likes (e.g., the existing liveness blinker).
    gpio_put(LED_PIN, 1);
    busy_wait_long();

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
    led_init();
    // ACCESSCTRL configuration deferred to Phase 4. The reset defaults
    // (after the boot ROM's setup) let Core0 in NS state reach the
    // USB / GPIO / SPI peripherals the existing firmware uses. TRNG
    // and SHA stay Secure-only -- NS will get those via veneers in
    // Phase 2.x.
    m9_sau_program();
    m9_branch_to_nonsecure();
    __builtin_unreachable();
}
