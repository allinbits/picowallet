#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/api.h"  // os_curve_t

// ============================================================================
// Secure veneer ABI -- the eventual NSC entries through which the
// Non-Secure world reaches the Secure world's keys, persistent state,
// and trusted UI. See PLAN.md §M9 for the boundary and threat model.
//
// Status (M9 Phase 0): this header codifies the API contract. No
// implementation has landed yet -- call sites still use os_crypto_*
// and the storage helpers directly. When Phase 2 of M9 lands these
// declarations get cmse_nonsecure_entry bodies in the Secure image and
// the call sites switch from the old names to s_*.
//
// Treat this file as load-bearing for review: a change here is a
// change to the trust boundary.
// ============================================================================

// --- Phase 2a smoke test --------------------------------------------------
// Trivial round-trip veneer: NS passes a value, Secure returns it XORed
// with 0xA5A5A5A5. Lets us assert the SG/BXNS gateway path works before
// any real veneer is in place. Delete once Phase 2b ships.
uint32_t s_phase2_test(uint32_t x);

// --- Phase 2b transitional flash veneers ----------------------------------
// Sub-veneers for the persistent-flash regions that NS cannot touch on
// RP2350 (flash mutations are Secure-only). Each is at the "construct
// a page in NS, hand it to Secure to write" granularity rather than the
// typed M9.2 ABI (s_chains_add etc.); NS still owns the validation and
// in-RAM cache of the chain config, Secure only owns the flash erase +
// program. Phase 2c re-tightens this with the proper typed veneers
// once the keystore migrates and Secure owns chain/HWM state directly.
//
// Returns 0 on success, negative status_t on failure (page too large,
// pointer not in NS memory, ...).
int s_flash_write_chains_page(const void *page, size_t len);
int s_flash_erase_hwm_slot(uint8_t slot_idx);
int s_flash_erase_hwm_sector(uint8_t slot_idx, uint8_t sector_in_slot);
int s_flash_erase_hwm_all(void);
int s_flash_write_hwm_page(uint8_t slot_idx, uint16_t page_in_slot,
                           const void *page, size_t len);

// --- Crypto + signing -----------------------------------------------------

// Derive a public key for `curve` at `path` from the Secure-owned seed.
// Output is always exactly 32 bytes (length-locked here because cmse_
// nonsecure_entry only supports up to 4 word-sized register args). For
// non-fixed-length curves the future Secp256k1 path will need its own
// veneer or a struct-pointer variant.
int s_get_pubkey(uint8_t curve, const char *path, uint8_t out_pubkey[32]);

// Sign the 32-byte SecretConnection challenge with the key derived at
// `path`. Length-locked to 32 bytes so this veneer cannot be turned
// into a general-purpose oracle for privval messages -- those go
// through s_sign_and_advance, which fuses HWM strict-advance and the
// signature.
int s_sign_sc_challenge(uint8_t curve, const char *path,
                        const uint8_t challenge[32], uint8_t out_sig[64]);

// Phase 2c transitional: variable-length privval sign without HWM
// fusion. Curve is hardcoded to Ed25519 (the only privval curve the
// device supports). This veneer IS a generic signing oracle and
// loses the HWM strict-advance guarantee that the M9.2 design
// requires. Phase 2c3 replaces it with s_sign_and_advance, which
// takes the HWM slot + (type, height, round) and refuses to sign
// anything that doesn't strict-advance.
int s_sign_privval(const char *path, const uint8_t *data, size_t data_len,
                   uint8_t out_sig[64]);

// Atomically: validate that (type, height, round) strictly advances
// the HWM at slot `hwm_slot_idx`; append a new HWM record; sign
// `data` (canonical sign-bytes) with the slot's key; return signature.
//
// Secure looks up the chain_id from its slot table internally; NS
// cannot lie about it. NS can lie about (type, height, round) but
// only forward -- the seed never leaks, and the worst attacker
// outcome is bricking signing on the slot.
//
// Returns 0 on success; -1 if HWM rejected (replay/regression);
// other negative codes for status_t failures.
//
// All args packed into a struct because cmse_nonsecure_entry can pass
// at most 4 register-sized args. The struct itself is read once from
// NS memory (cmse_check_address_range), then its pointer fields are
// individually validated.
typedef struct {
    const char    *path;       // SLIP-10 path, NUL-terminated (NS RAM)
    const uint8_t *data;       // canonical sign-bytes (NS RAM)
    size_t         data_len;
    uint8_t       *out_sig;    // 64-byte output (NS RAM, writable)
    uint8_t        hwm_slot_idx;
    uint8_t        curve;      // os_curve_t, currently always Ed25519
    int32_t        type;
    int32_t        round;
    int64_t        height;
} s_sign_and_advance_args_t;

int s_sign_and_advance(const s_sign_and_advance_args_t *args);

// --- Chain config mutations ----------------------------------------------
//
// Mirror chains.h's chains_* surface. Routed through Secure so the NS
// REPL dispatcher cannot reach into persistent flash directly.

int  s_chains_add(int family, const char *label, const char *chain_id,
                  const uint8_t dial_host[4], uint16_t port,
                  const uint8_t *pinned_key /*32B or NULL*/);
bool s_chains_remove(int family, const char *label);
void s_chains_wipe(void);
void s_hwm_wipe(void);

// --- Trusted UI primitives ----------------------------------------------

// Show the factory-reset confirm screen. The screen is drawn by Secure
// directly to the e-paper -- NS cannot influence the body text (it is
// baked into the Secure image). Buttons are polled Secure-side via the
// veneered input path. On accept Secure runs the wipe (chain config +
// HWM) and returns true. NS calls this from factory_reset.c after its
// long-hold trigger detector fires.
bool s_factory_reset_with_consent(void);

// --- Display (Phase 2d) -------------------------------------------------
//
// The e-paper SPI, framebuffer, Pico_ePaper_Code library, and all UI
// layout code (splash, console, mode_select, confirm) live in the
// Secure image. NS reaches them only through these veneers. NS does
// NOT have a paint API -- it can push text into a Secure-side history
// buffer (s_console_log) or request one of the canned screens.
//
// The framebuffer never appears in NS memory; Phase 4 closes
// ACCESSCTRL_SPI1 + GPIO_NSMASK bits 8..13 (e-paper pins) to fully
// take the display path away from NS.

// Bring up SPI + e-paper panel + allocate the framebuffer. Called once
// at boot from NS main() before any other display veneer.
void s_display_init(void);

// Render the boot splash (PicoWallet bitmap + build string). Build
// version is baked into the Secure image; NS cannot influence it.
void s_splash_render(void);

// Console history (lives in Secure RAM).
void s_console_init(void);
void s_console_clear_history(void);
// Push one text line into the history buffer. `len` is strlen(line)+1
// (inclusive of NUL) and is capped Secure-side at the configured max.
// Secure validates the NS range before reading.
void s_console_log(const char *line, size_t len);
bool s_console_is_dirty(void);
void s_console_render(void);        // fast refresh
void s_console_render_clean(void);  // multi-pass clean refresh (removes ghosting)

// Show the mode-select prompt, block on a button press, return the
// chosen mode (os_mode_t: 0 = TMKMS, 1 = PRIVVAL).
uint8_t s_mode_select_prompt(void);

// --- Input (low-trust veneer) -------------------------------------------

// Sample button state. NS uses this for non-consent decisions only:
// the boot-mode-select prompt's polling fallback, the factory-reset
// trigger detection. NEVER use for confirming a destructive op -- those
// route through s_factory_reset_with_consent or the equivalent
// Secure-drawn flow.
// btn: 0 = LEFT (GPIO 16), 1 = RIGHT (GPIO 17).
bool s_input_pressed(uint8_t btn);

// --- Utility ------------------------------------------------------------

// TRNG entropy. NS uses this for SC ephemerals.
int s_random(uint8_t *out, size_t n);

// --- SHA-256 (Phase 4) --------------------------------------------------
//
// SHA-256 hardware (and the bootlock it shares) is Secure-only now. The
// only NS-side callers are the SecretConnection HKDF derivation, so
// expose just hkdf_extract + hkdf_expand and skip the raw sha256 /
// hmac_sha256 surface. Args are packed because cmse_nonsecure_entry
// allows at most 4 register-sized parameters.

typedef struct {
    const uint8_t *salt;     // may be NULL with salt_len=0 (RFC 5869)
    size_t         salt_len;
    const uint8_t *ikm;
    size_t         ikm_len;
    uint8_t       *prk;      // 32 bytes
} s_hkdf_extract_args_t;

int s_hkdf_extract(const s_hkdf_extract_args_t *args);

typedef struct {
    const uint8_t *prk;
    size_t         prk_len;
    const uint8_t *info;
    size_t         info_len;
    uint8_t       *okm;
    size_t         okm_len;
} s_hkdf_expand_args_t;

int s_hkdf_expand(const s_hkdf_expand_args_t *args);

// Read a clock frequency from the Secure-side software cache. After
// Phase 4 NS no longer runs runtime_init_clocks (CLOCKS / XOSC / PLLs
// are locked Secure-only), so its own pico-sdk clock_get_hz cache is
// zero. Argument is a pico-sdk clock_handle_t value (clk_sys etc.)
// truncated to uint8_t.
uint32_t s_clock_get_hz(uint8_t clock_idx);

const char *s_status_str(int status);
