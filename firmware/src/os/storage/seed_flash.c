// M9.5 Phase 7.1 -- sealed-seed primitives (Secure-side only).

#if PICOWALLET_SECURE_BUILD

#include "os/storage/seed_flash.h"

#include <string.h>

#include "os/crypto/monocypher.h"
#include "trng.h"

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

// Derive a 32-byte KEK from PIN + salt via Argon2id.
static void derive_kek(const uint8_t *pin, size_t pin_len,
                       const uint8_t salt[16], uint8_t out_kek[32]) {
    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = M9_ARGON2_BLOCKS,
        .nb_passes = M9_ARGON2_PASSES,
        .nb_lanes  = 1u,
    };
    crypto_argon2_inputs in = {
        .pass      = pin,
        .salt      = salt,
        .pass_size = (uint32_t)pin_len,
        .salt_size = 16u,
    };
    crypto_argon2(out_kek, 32u, s_argon2_work, cfg, in, crypto_argon2_no_extras);
    crypto_wipe(s_argon2_work, sizeof(s_argon2_work));
}

int m9_seal_seed(const uint8_t *pin, size_t pin_len,
                 const uint8_t plaintext[M9_SEALED_SEED_LEN],
                 m9_sealed_seed_t *out) {
    if (!pin || !plaintext || !out) return -1;
    m9_trng_fill(out->salt,  sizeof(out->salt));
    m9_trng_fill(out->nonce, sizeof(out->nonce));

    uint8_t kek[32];
    derive_kek(pin, pin_len, out->salt, kek);
    crypto_aead_lock(out->ciphertext, out->tag, kek, out->nonce,
                     NULL, 0u, plaintext, M9_SEALED_SEED_LEN);
    crypto_wipe(kek, sizeof(kek));
    return 0;
}

int m9_unseal_seed(const uint8_t *pin, size_t pin_len,
                   const m9_sealed_seed_t *in,
                   uint8_t out_plaintext[M9_SEALED_SEED_LEN]) {
    if (!pin || !in || !out_plaintext) return -1;
    uint8_t kek[32];
    derive_kek(pin, pin_len, in->salt, kek);
    int rc = crypto_aead_unlock(out_plaintext, in->tag, kek, in->nonce,
                                NULL, 0u, in->ciphertext, M9_SEALED_SEED_LEN);
    crypto_wipe(kek, sizeof(kek));
    if (rc != 0) {
        // Auth failure: ensure caller doesn't see partial plaintext.
        crypto_wipe(out_plaintext, M9_SEALED_SEED_LEN);
        return -1;
    }
    return 0;
}

#endif  // PICOWALLET_SECURE_BUILD
