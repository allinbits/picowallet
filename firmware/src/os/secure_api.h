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
// Returns 0 on success and writes `*out_len`; negative on error
// (out-of-range path, unknown curve, out_size too small).
int s_get_pubkey(os_curve_t curve, const char *path,
                 uint8_t *out_pubkey, size_t out_size, size_t *out_len);

// Sign the 32-byte SecretConnection challenge with the key derived at
// `path`. Length-locked to 32 bytes so this veneer cannot be turned
// into a general-purpose oracle for privval messages -- those go
// through s_sign_and_advance, which fuses HWM strict-advance and the
// signature.
int s_sign_sc_challenge(os_curve_t curve, const char *path,
                        const uint8_t challenge[32], uint8_t out_sig[64]);

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
int s_sign_and_advance(os_curve_t curve, const char *path,
                       uint8_t hwm_slot_idx,
                       int32_t type, int64_t height, int32_t round,
                       const uint8_t *data, size_t data_len,
                       uint8_t out_sig[64]);

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
// directly to the reserved prompt region of the e-paper -- NS cannot
// influence what is shown. Buttons are polled Secure-side. On accept
// the wipe runs (chain config + HWM). Returns true iff confirmed.
bool s_factory_reset_with_consent(void);

// --- Display + input (low-trust veneers) --------------------------------

// Render the console area of the e-paper. NS supplies text content;
// Secure refuses to draw if a trusted prompt is currently active.
// `lines` is an array of NUL-terminated strings.
void s_console_render_lines(const char * const *lines, size_t n);

// Sample button state. NS uses this for non-consent decisions only:
// the boot-mode-select prompt, the factory-reset trigger detection.
// NEVER use for confirming a destructive op -- those route through
// s_factory_reset_with_consent or the equivalent Secure-drawn flow.
bool s_input_pressed(uint8_t btn);   // 0 = LEFT, 1 = RIGHT

// --- Utility ------------------------------------------------------------

// TRNG entropy. NS uses this for SC ephemerals.
int s_random(uint8_t *out, size_t n);

const char *s_status_str(int status);
