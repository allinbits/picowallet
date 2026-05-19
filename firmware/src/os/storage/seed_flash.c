// M9.5 Phase 7.1/7.2 -- sealed-seed primitives (Secure-side only).

#if PICOWALLET_SECURE_BUILD

#include "os/storage/seed_flash.h"

#include <stdbool.h>
#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/crypto/monocypher.h"
#include "os/storage/chains.h"
#include "os/storage/flash_layout.h"
#include "os/storage/hwm_flash.h"
#include "os/storage/slot_seed.h"
#include "m9_otp.h"
#include "trng.h"

#define SEED_PAGE_SIZE          256u
#define SEED_HEADER_MAGIC       0xC0DEC0DEu
#define SEED_HEADER_VERSION     1u

typedef struct {
    uint32_t          magic;
    uint32_t          version;
    uint8_t           reserved[8];
    m9_sealed_seed_t  blob;
} seed_flash_page0_t;
_Static_assert(sizeof(seed_flash_page0_t) <= SEED_PAGE_SIZE,
               "seed_flash_page0_t must fit in one flash page");

#define SEED_FLASH_PAGE0_PTR \
    ((const seed_flash_page0_t *)(XIP_BASE + SEED_FLASH_OFFSET))
#define SEED_FLASH_COUNTER_PAGE_PTR(n) \
    ((const uint8_t *)(XIP_BASE + SEED_FLASH_OFFSET + (n) * SEED_PAGE_SIZE))

// Argon2id workspace. 64 KiB is the largest power-of-two that fits
// alongside the existing Secure BSS + heap (framebuffer ~32 KB) +
// stack budget within the 128 KB Secure SRAM. Larger would be
// preferable for offline brute-force resistance against a 4-digit
// PIN, but RP2350's SRAM split caps us here. M9.5 mitigates with
// the in-device attempt counter (10 failures -> full wipe).
//
// Static so we don't blow the Secure stack on each call. Argon2id
// writes the entire workspace during compute and the contents are
// nominally KDF-derived (not raw PIN), but we still wipe after use
// to be conservative.
#define M9_ARGON2_BLOCKS  64u  // 64 KiB
#define M9_ARGON2_PASSES  3u
static uint8_t s_argon2_work[M9_ARGON2_BLOCKS * 1024u];

// Derive a 32-byte KEK from PIN (+ optional OTP device secret) + salt
// via Argon2id.
//
// When PICOWALLET_M9_OTP_BIND is defined, the Argon2id `pass` input is
// `OTP_SECRET || PIN`. The 32-byte per-device OTP secret is read (or,
// on first use, burned) from a reserved OTP row -- see m9_otp.c.
// Binding the KEK to the chip means a flash dump alone cannot be
// brute-forced offline; the attacker also needs the OTP secret, which
// is Secure-only (ACCESSCTRL_OTP locked since Phase 4) and survives
// factory reset.
//
// When PICOWALLET_M9_OTP_BIND is undefined (default), the Argon2id
// `pass` is just the PIN, so we avoid the one-time-permanent OTP
// burn until the layout is committed.
static void derive_kek(const uint8_t *pin, size_t pin_len,
                       const uint8_t salt[16], uint8_t out_kek[32]) {
    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = M9_ARGON2_BLOCKS,
        .nb_passes = M9_ARGON2_PASSES,
        .nb_lanes  = 1u,
    };

#if PICOWALLET_M9_OTP_BIND
    uint8_t otp_secret[M9_OTP_DEVICE_SECRET_LEN];
    if (m9_otp_get_device_secret(otp_secret) != 0) {
        // Fail closed if the OTP read/burn fails: zero the KEK so the
        // subsequent unseal/seal returns auth-failure rather than
        // silently using bogus key material.
        crypto_wipe(out_kek, 32);
        return;
    }
    uint8_t pass_buf[M9_OTP_DEVICE_SECRET_LEN + M9_PIN_MAX_LEN];
    memcpy(pass_buf, otp_secret, M9_OTP_DEVICE_SECRET_LEN);
    memcpy(pass_buf + M9_OTP_DEVICE_SECRET_LEN, pin, pin_len);
    crypto_wipe(otp_secret, sizeof(otp_secret));
    crypto_argon2_inputs in = {
        .pass      = pass_buf,
        .salt      = salt,
        .pass_size = (uint32_t)(M9_OTP_DEVICE_SECRET_LEN + pin_len),
        .salt_size = 16u,
    };
    crypto_argon2(out_kek, 32u, s_argon2_work, cfg, in, crypto_argon2_no_extras);
    crypto_wipe(pass_buf, sizeof(pass_buf));
#else
    crypto_argon2_inputs in = {
        .pass      = pin,
        .salt      = salt,
        .pass_size = (uint32_t)pin_len,
        .salt_size = 16u,
    };
    crypto_argon2(out_kek, 32u, s_argon2_work, cfg, in, crypto_argon2_no_extras);
#endif
    crypto_wipe(s_argon2_work, sizeof(s_argon2_work));
}

int m9_seal_payload(const uint8_t *pin,        size_t pin_len,
                    const uint8_t *plaintext,  size_t plain_len,
                    uint8_t        out_salt[16],
                    uint8_t        out_nonce[24],
                    uint8_t       *out_ciphertext,
                    uint8_t        out_tag[16]) {
    if (!pin || !plaintext || !out_salt || !out_nonce ||
        !out_ciphertext || !out_tag) return -1;
    if (plain_len == 0 || plain_len > M9_SEAL_MAX_PAYLOAD) return -1;

    m9_trng_fill(out_salt,  16);
    m9_trng_fill(out_nonce, 24);

    uint8_t kek[32];
    derive_kek(pin, pin_len, out_salt, kek);
    crypto_aead_lock(out_ciphertext, out_tag, kek, out_nonce,
                     NULL, 0u, plaintext, plain_len);
    crypto_wipe(kek, sizeof(kek));
    return 0;
}

int m9_unseal_payload(const uint8_t *pin,        size_t pin_len,
                      const uint8_t  salt[16],
                      const uint8_t  nonce[24],
                      const uint8_t *ciphertext, size_t cipher_len,
                      const uint8_t  tag[16],
                      uint8_t       *out_plaintext) {
    if (!pin || !ciphertext || !out_plaintext) return -1;
    if (cipher_len == 0 || cipher_len > M9_SEAL_MAX_PAYLOAD) return -1;
    uint8_t kek[32];
    derive_kek(pin, pin_len, salt, kek);
    int rc = crypto_aead_unlock(out_plaintext, tag, kek, nonce,
                                NULL, 0u, ciphertext, cipher_len);
    crypto_wipe(kek, sizeof(kek));
    if (rc != 0) {
        crypto_wipe(out_plaintext, cipher_len);
        return -1;
    }
    return 0;
}

int m9_seal_seed(const uint8_t *pin, size_t pin_len,
                 const uint8_t plaintext[M9_SEALED_SEED_LEN],
                 m9_sealed_seed_t *out) {
    if (!out) return -1;
    return m9_seal_payload(pin, pin_len, plaintext, M9_SEALED_SEED_LEN,
                           out->salt, out->nonce, out->ciphertext, out->tag);
}

int m9_unseal_seed(const uint8_t *pin, size_t pin_len,
                   const m9_sealed_seed_t *in,
                   uint8_t out_plaintext[M9_SEALED_SEED_LEN]) {
    if (!in) return -1;
    return m9_unseal_payload(pin, pin_len,
                             in->salt, in->nonce,
                             in->ciphertext, M9_SEALED_SEED_LEN,
                             in->tag, out_plaintext);
}

// ============================================================================
// Phase 7.2 -- persistence + PIN attempt counter
// ============================================================================

bool m9_seed_flash_is_initialized(void) {
    const seed_flash_page0_t *p = SEED_FLASH_PAGE0_PTR;
    return p->magic == SEED_HEADER_MAGIC && p->version == SEED_HEADER_VERSION;
}

const m9_sealed_seed_t *m9_seed_flash_load(void) {
    if (!m9_seed_flash_is_initialized()) return NULL;
    return &SEED_FLASH_PAGE0_PTR->blob;
}

int m9_pin_attempts(void) {
    int count = 0;
    for (int i = 1; i <= M9_PIN_MAX_ATTEMPTS; i++) {
        const uint8_t *page = SEED_FLASH_COUNTER_PAGE_PTR(i);
        bool all_zero = true;
        for (size_t j = 0; j < SEED_PAGE_SIZE; j++) {
            if (page[j] != 0x00) { all_zero = false; break; }
        }
        if (all_zero) count++;
        else          break;     // pages must be contiguous; stop at first 0xFF
    }
    return count;
}

int m9_seed_flash_store(const m9_sealed_seed_t *blob) {
    if (!blob) return -1;
    uint8_t page[SEED_PAGE_SIZE];
    memset(page, 0xFF, sizeof(page));
    seed_flash_page0_t *p = (seed_flash_page0_t *)page;
    p->magic   = SEED_HEADER_MAGIC;
    p->version = SEED_HEADER_VERSION;
    memcpy(&p->blob, blob, sizeof(*blob));

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SEED_FLASH_OFFSET, SEED_FLASH_SIZE);
    flash_range_program(SEED_FLASH_OFFSET, page, sizeof(page));
    restore_interrupts(ints);
    return 0;
}

void m9_pin_attempt_record_failure(void) {
    int count = m9_pin_attempts();
    if (count >= M9_PIN_MAX_ATTEMPTS) return;          // already exhausted
    uint8_t zeros[SEED_PAGE_SIZE];
    memset(zeros, 0x00, sizeof(zeros));
    uint32_t off = SEED_FLASH_OFFSET + (count + 1) * SEED_PAGE_SIZE;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(off, zeros, sizeof(zeros));
    restore_interrupts(ints);
}

void m9_pin_attempt_reset(void) {
    // Snapshot the existing page 0 (sealed blob + header), erase the
    // whole sector, then reprogram page 0. Counter pages return to all
    // 0xFF -- attempt count back to zero.
    if (!m9_seed_flash_is_initialized()) return;
    uint8_t page[SEED_PAGE_SIZE];
    memset(page, 0xFF, sizeof(page));
    memcpy(page, SEED_FLASH_PAGE0_PTR, sizeof(seed_flash_page0_t));

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SEED_FLASH_OFFSET, SEED_FLASH_SIZE);
    flash_range_program(SEED_FLASH_OFFSET, page, sizeof(page));
    restore_interrupts(ints);
}

// ----- PIN cache (Secure RAM) ----------------------------------------------

static uint8_t s_pin_cache[M9_PIN_MAX_LEN];
static size_t  s_pin_cache_len = 0;

void m9_pin_cache_set(const uint8_t *pin, size_t pin_len) {
    if (!pin || pin_len == 0 || pin_len > M9_PIN_MAX_LEN) {
        m9_pin_cache_clear();
        return;
    }
    memcpy(s_pin_cache, pin, pin_len);
    s_pin_cache_len = pin_len;
}

size_t m9_pin_cache_get(uint8_t out[M9_PIN_MAX_LEN]) {
    if (s_pin_cache_len == 0 || !out) return 0;
    memcpy(out, s_pin_cache, s_pin_cache_len);
    return s_pin_cache_len;
}

void m9_pin_cache_clear(void) {
    crypto_wipe(s_pin_cache, sizeof(s_pin_cache));
    s_pin_cache_len = 0;
}

void m9_factory_wipe_all(void) {
    // SEED first so an interrupted wipe leaves a "no PIN configured"
    // state rather than chain config without a seed. SLOT_SEEDS,
    // chains, HWM follow. All four storage regions get cleared so the
    // device returns to a truly blank state.
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SEED_FLASH_OFFSET, SEED_FLASH_SIZE);
    restore_interrupts(ints);
    m9_slot_seeds_wipe_all();
    chains_wipe();
    hwm_flash_wipe();
    m9_pin_cache_clear();
}

#endif  // PICOWALLET_SECURE_BUILD
