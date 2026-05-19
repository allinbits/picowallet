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
#include "pico/runtime_init.h"
#include "pico/stdlib.h"

#include "layout.h"

// Phase 2c3: Secure-side caches for chain config + HWM. Populated from
// flash by chains_init / hwm_init at boot; the s_sign_and_advance
// veneer reads them when validating each privval sign request.
#include "os/storage/chains.h"
#include "os/storage/hwm_flash.h"

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

    // Region 3: peripheral + SIO space (0x40000000-0xDFFFFFFF). Without
    // this, NS code's very first instructions -- which read SIO_CPUID
    // at 0xD0000000 to check core0/core1 -- fault as SecureFault.AUVIOL
    // and double-fault the M33 into lockup before the NS image runs at
    // all.
    sau_hw->rnr  = 3u;
    sau_hw->rbar = M9_SAU_R3_BASE;
    sau_hw->rlar = M9_SAU_R3_LIMIT | ((uint32_t)M9_SAU_R3_NSC << 1) | 1u;

    // Region 4: Boot ROM (0x00000000-0x00007FFF). pico-sdk's NS-side
    // runtime_init_bootrom_reset is the first runtime initializer and
    // immediately reads the bootrom function table via `ldrh r3, [0, #22]`.
    // Without this region the ROM read faults as SecureFault.AUVIOL and
    // we land in the S hardfault handler before the NS image's main()
    // ever runs.
    sau_hw->rnr  = 4u;
    sau_hw->rbar = M9_SAU_R4_BASE;
    sau_hw->rlar = M9_SAU_R4_LIMIT | ((uint32_t)M9_SAU_R4_NSC << 1) | 1u;

    // Enable SAU. ALLNS=0 means anything outside the configured regions
    // stays Secure (matches the RP2350 IDAU default for flash + SRAM).
    sau_hw->ctrl = 1u;
    __asm__ volatile("dsb; isb");
}

// ---- ACCESSCTRL --------------------------------------------------------
//
// SAU is the first gate (memory attribution). ACCESSCTRL is the second:
// per-peripheral attribution by master + security + privilege. Most
// peripherals come out of reset as "Secure-Privileged-only" -- the
// notable ones for our boot path are XIP_CTRL and XIP_QMI (pico-sdk's
// crt0 runs boot2, which touches the QSPI controller registers), plus
// the broader RESETS / CLOCKS / PLL / XOSC / IO_BANK / PADS_BANK
// peripherals that runtime_init walks.
//
// For Phase 1 we open ALL the per-peripheral access registers to
// Non-Secure (both NSP and NSU) so the NS image's runtime_init + SDK
// init can run. Phase 4 hardens this by closing TRNG / SHA / RESETS /
// flash controller back down to Secure-only for the real M9 boundary.
//
// Each per-peripheral register is at ACCESSCTRL_BASE + offset, with:
//   bits [7:0]  : access flags (DBG/DMA/CORE1/CORE0/SP/SU/NSP/NSU)
//   bits [31:16]: must contain the password 0xACCE for the write to land
//
// The first three words (LOCK / FORCE_CORE_NS / CFGRESET) and the next
// two 32-bit GPIO_NSMASK registers have different layouts; we skip them
// here -- early NS code doesn't touch GPIO PADs, and we explicitly do
// not want to touch LOCK by accident.
//
// Per-peripheral registers run from offset 0x14 (ACCESSCTRL_ROM) through
// 0xE4 (ACCESSCTRL_XIP_QMI). That's 0xD4 / 4 = 53 u32 entries.
static void m9_accessctrl_open_for_ns(void) {
    volatile uint32_t *r    = (volatile uint32_t *)0x40060000u;  // BASE
    volatile uint32_t *rset = (volatile uint32_t *)0x40062000u;  // SET alias
    const uint32_t PW       = 0xACCE0000u;

    // GPIO_NSMASK0/1 use all 32 bits for data so password can't fit at
    // the base; use the SET alias (this path is documented to work for
    // these registers and the SDK does it the same way).
    //
    // GPIO_NSMASK0 covers pins 0..31. Bits 8..13 are the e-paper
    // signals (DC, CS, CLK, MOSI, RST, BUSY) which Phase 2d moved
    // fully into Secure; clearing those bits takes pad config rights
    // away from NS so an NS compromise cannot reconfigure the
    // pins (e.g. drive RST and corrupt the framebuffer mid-update or
    // remap MOSI to capture writes). NS still owns:
    //   - pin 16, 17  (LEFT/RIGHT buttons -- gpio_init runs in NS)
    //   - pin 25      (onboard LED        -- main.c blink path)
    // and all other pins for misc NS uses.
    rset[0x0C / 4u] = 0xFFFFC0FFu;   // mask out pins 8..13 from NS
    rset[0x10 / 4u] = 0xFF00FFFFu;

    // Per-peripheral access registers from ROM (0x14) through XIP_QMI
    // (0xE4). These have data in the bottom 8 bits + 0xACCE password
    // in the top 16. The SET-alias path FAULTS on individual peripheral
    // access regs (only GPIO_NSMASK0/1 support it), so write each one
    // via the password mechanism.
    for (uint32_t off = 0x14u; off <= 0xE4u; off += 4u) {
        r[off / 4u] = PW | 0xFFu;
    }

    // --- Phase 4 partial lockdown -----------------------------------
    // Re-narrow specific peripherals after the open-everything pass.
    // Each register reads back as just the lower 8 bits; writing
    // 0xACCE0000 | <new flags> updates only that peripheral. 0xFC =
    // reset value: DBG + DMA + CORE1 + CORE0 + SP + SU set, NSP/NSU
    // cleared (Secure-Privileged-only).
    //
    // TRNG: NS reaches the TRNG exclusively through the s_random()
    // veneer (Phase 2e). Lock direct NS access so a future NS
    // compromise can't measure raw entropy or replay it.
    r[0xB4 / 4u] = PW | 0xFCu;   // ACCESSCTRL_TRNG

    // SPI1: drives the e-paper panel exclusively (Phase 2d moved the
    // Pico_ePaper_Code library + framebuffer + display HAL into the
    // Secure image). NS does not reference spi1 at all; lock it down.
    // SPI0 stays open to NS (currently unused but available for future
    // NS peripherals -- if it grows trust-sensitive uses it gets the
    // same treatment).
    r[0x94 / 4u] = PW | 0xFCu;   // ACCESSCTRL_SPI1

    // OTP: holds factory-set chip identity + future M9.5 sealed-seed
    // material. NS never reads or writes it directly under TZ
    // (pico_unique_id goes through rom_get_sys_info which is the
    // NS-callable bootrom path, not a direct OTP MMIO).
    r[0xA8 / 4u] = PW | 0xFCu;   // ACCESSCTRL_OTP

    // POWMAN: power-management controller (reset, sleep, scratch). NS
    // has no business changing power policy or scratch registers; a
    // POWMAN write from NS could otherwise wedge boot or stage a fake
    // reset cause to mislead the operator.
    r[0xB0 / 4u] = PW | 0xFCu;   // ACCESSCTRL_POWMAN

    // WATCHDOG: NS does not call watchdog_enable / watchdog_reboot
    // anywhere. Locking prevents a compromised NS from disabling the
    // watchdog (if we later enable it Secure-side) or rebooting via
    // a poisoned PC/SP pair through watchdog_reboot.
    // (Note: on RP2350 the per-tick generators moved to a separate
    // TICKS peripheral, so watchdog_hw->tick is no longer in the
    // runtime-init hot path -- safe to lock independently.)
    r[0xD8 / 4u] = PW | 0xFCu;   // ACCESSCTRL_WATCHDOG

    // Clock-tree peripherals. The Secure stub runs clocks_init in
    // Secure state to bring the PLLs / XOSC up before BXNS; NS skips
    // its runtime_init_clocks (PICO_RUNTIME_SKIP_INIT_CLOCKS) and reads
    // frequencies through the s_clock_get_hz veneer when it needs them.
    // ROSC is also locked because pico_rand's ROSC sampler would
    // otherwise read clocks_hw to verify the CPU isn't on ROSC; NS
    // routes randomness through LWIP_RAND -> s_random instead so
    // pico_rand is never called.
    r[0xC0 / 4u] = PW | 0xFCu;   // ACCESSCTRL_CLOCKS
    r[0xC4 / 4u] = PW | 0xFCu;   // ACCESSCTRL_XOSC
    r[0xC8 / 4u] = PW | 0xFCu;   // ACCESSCTRL_ROSC
    r[0xCC / 4u] = PW | 0xFCu;   // ACCESSCTRL_PLL_SYS
    r[0xD0 / 4u] = PW | 0xFCu;   // ACCESSCTRL_PLL_USB

    // SHA-256 hardware (Phase 4). The peripheral + its bootlock at
    // 0x400E080C are Secure-only now -- all SHA-256 in firmware lives
    // in Secure (sha256.c moved into picowallet_secure) and NS reaches
    // HKDF via s_hkdf_extract / s_hkdf_expand veneers. The pico_sha256
    // SDK wrapper is no longer linked into the NS image.
    r[0xB8 / 4u] = PW | 0xFCu;   // ACCESSCTRL_SHA256

    // DMA channel partition. ACCESSCTRL_DMA stays open to NS so NS
    // can still drive any DMA needs that arise (none today after
    // pico_sha256 moved Secure-side). Per-channel SECCFG_CHn is the
    // finer-grained gate. Reserve channel 0 for the
    // Secure side (future SHA / SPI / flash users) by setting
    // SECCFG_CH0 = S=1 + P=1 + LOCK=1 -- once LOCK is set the
    // attribution cannot be modified until reset, so NS cannot
    // re-attribute the channel even if ACCESSCTRL_DMA is open.
    // Channels 1..15 remain at their reset value (S=1, P=1, LOCK=0):
    // NS today writes them and the controller honors the writes
    // because ACCESSCTRL_DMA grants NS, but the LOCK=0 means we can
    // tighten this further in a later commit without a chip change.
    //
    // NS-side bookkeeping (dma_channel_claim(0) in main.c) marks
    // channel 0 as claimed in NS's SDK bitmap so pico_sha256's
    // dma_claim_unused_channel scan skips it.
    volatile uint32_t *dma_seccfg = (volatile uint32_t *)(0x50000000u + 0x480u);
    dma_seccfg[0] = (1u << 1) | (1u << 0) | (1u << 2);  // S=1, P=1, LOCK=1
    __asm__ volatile("dsb");
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
    // The boot-time success-blink was a Phase 1 diagnostic; removed
    // now that the SAU + ACCESSCTRL + bootrom-NS plumbing is debugged.
    // The error-blink path above is kept -- a corrupt NS slot still
    // drops to BOOTSEL with a 1/2/3 long-blink count for diagnosis.

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

// Hardware bring-up that pico-sdk's runtime_init normally does on the
// SDK target. We run it here in Secure state because most of these
// functions reach into bootrom and into peripherals whose RESETS_DONE
// bits the bootrom only honors for Secure callers. The NS image has the
// matching SDK initializers SKIP'd out via PICO_RUNTIME_SKIP_INIT_* in
// firmware/CMakeLists.txt -- without those skips the NS image would try
// to redo this work and either fault (bootrom_reset) or spin forever
// (early_resets RESETS_DONE wait).
//
// Order matches the SDK's runtime_init array order so the dependency
// chain (resets before clocks, clocks before post-clock-resets) is
// preserved.
// Route every IRQ to the Non-Secure handler. ARMv8-M's NVIC has banked
// targeting via NVIC_ITNS[0..15] (each bit = one IRQ); reset value is 0
// = Secure-targeted. With Secure-only IRQs, NS code never gets timer
// callbacks, never runs tud_task(), USB enumeration silently dies. For
// Phase 1 we route everything to NS. Phase 4 will move TRNG / SHA /
// flash-controller / button-GPIO IRQs back to Secure for the BOLOS-
// style trusted-input path.
static void m9_route_irqs_to_ns(void) {
    volatile uint32_t *itns = (volatile uint32_t *)0xE000E380u;
    for (int i = 0; i < 16; i++) {
        itns[i] = 0xFFFFFFFFu;
    }
    __asm__ volatile("dsb");
}

// Open NS coprocessor access. RP2350 routes GPIO operations through CP0
// (the gpioc coprocessor) and the RCP (CP7) is used by libgcc for
// redundancy-checked branches. NSACR resets to 0 (NS denied for all
// coprocessors); leaving it that way means NS's first gpio_init() / any
// gpioc instruction faults as a UsageFault.NOCP. Open everything NS-
// callable: CP0+CP1 (gpio), CP4+CP7 (RCP), CP10+CP11 (FPU, just in case
// future NS code uses floats).
//
// Then mirror those into CPACR_NS so NS can actually issue the
// instructions without first having to write to its own CPACR.
#define SCB_S_NSACR    (*(volatile uint32_t *)0xE000ED8Cu)
#define SCB_S_CPACR    (*(volatile uint32_t *)0xE000ED88u)
#define SCB_NS_CPACR   (*(volatile uint32_t *)0xE002ED88u)
static void m9_open_coprocessors_for_ns(void) {
    SCB_S_NSACR  |= (1u << 11) | (1u << 10)
                  | (1u << 7)  | (1u << 4)
                  | (1u << 1)  | (1u << 0);
    // CPACR layout: each CP has a 2-bit field. 0b11 = full access for
    // priv + unpriv. Mask covers CP0+CP1+CP4+CP7+CP10+CP11.
    const uint32_t mask = (3u << 0)  | (3u << 2)  | (3u << 8)
                        | (3u << 14) | (3u << 20) | (3u << 22);
    SCB_S_CPACR  |= mask;
    SCB_NS_CPACR |= mask;
    __asm__ volatile("dsb; isb");
}

static void m9_runtime_init_for_ns(void) {
    rom_bootrom_state_reset(BOOTROM_STATE_RESET_GLOBAL_STATE
                          | BOOTROM_STATE_RESET_CURRENT_CORE);
    runtime_init_early_resets();
    runtime_init_usb_power_down();
    runtime_init_clocks();
    runtime_init_post_clock_resets();
    runtime_init_boot_locks_reset();
    runtime_init_spin_locks_reset();
    m9_open_coprocessors_for_ns();
    m9_route_irqs_to_ns();

    // bootrom_state_reset(GLOBAL_STATE) cleared the NS API permission
    // bitmap. The NS image's pico_unique_id constructor calls
    // GET_SYS_INFO via rom_func_lookup, so we have to re-enable that
    // permission (and a few other NS-callable APIs we expect to use
    // later) before BXNS. Phase 4 of the M9 plan will lock these back
    // down to only the APIs we actually need.
    rom_set_ns_api_permission(BOOTROM_NS_API_get_sys_info, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_checked_flash_op, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_flash_runtime_to_storage_addr, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_get_partition_table_info, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_secure_call, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_otp_access, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_reboot, true);
    rom_set_ns_api_permission(BOOTROM_NS_API_get_b_partition, true);
}

int main(void) {
    m9_runtime_init_for_ns();
    led_init();
    // Phase 2c3: prime the Secure-side chain config + HWM caches from
    // flash before BXNS so the s_sign_and_advance veneer can look up
    // the slot's chain_id and current HWM without NS being able to
    // influence the read. Both functions are idempotent and just scan
    // their respective flash regions via XIP.
    chains_init();
    hwm_init();
    m9_sau_program();
    m9_accessctrl_open_for_ns();
    m9_branch_to_nonsecure();
    __builtin_unreachable();
}
