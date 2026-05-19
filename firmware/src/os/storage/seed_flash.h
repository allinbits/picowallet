#pragma once
#include <stddef.h>
#include <stdint.h>

// M9.5 sealed-seed primitives. Phase 7.1 layer: PIN-derived KEK via
// Argon2id, AEAD via XChaCha20-Poly1305. Implementation lives in
// firmware/src/os/storage/seed_flash.c and is gated by
// PICOWALLET_SECURE_BUILD so it compiles only into picowallet_secure.
// NS never sees these symbols.
//
// Storage flow (will land in Phase 7.2+):
//   PIN-setup:   Secure generates 32-byte master seed; m9_seal_seed
//                produces a m9_sealed_seed_t (120 bytes); the blob is
//                written to SEED_FLASH_OFFSET via flash_range_program.
//   PIN-unlock:  Secure reads the blob from XIP; m9_unseal_seed verifies
//                the Poly1305 tag and writes the plaintext seed into a
//                Secure RAM buffer; signing flows use it from there.
//
// For Phase 7.1 itself the only consumer is s_seal_selftest, which
// round-trips a random payload entirely in RAM.

#define M9_SEALED_SEED_LEN  64u   // master seed = 64B BIP-39 PBKDF2 output

typedef struct {
    uint8_t salt[16];                          // Argon2id salt (TRNG at seal time)
    uint8_t nonce[24];                         // XChaCha20-Poly1305 nonce (TRNG at seal time)
    uint8_t tag[16];                           // Poly1305 MAC
    uint8_t ciphertext[M9_SEALED_SEED_LEN];    // sealed payload
} m9_sealed_seed_t;
_Static_assert(sizeof(m9_sealed_seed_t) == 120, "seed blob must be 120 bytes");

// Seal: encrypt `plaintext` under a key derived from PIN+fresh-salt;
// fills `out` with salt + nonce + ciphertext + tag. Returns 0.
int m9_seal_seed(const uint8_t *pin, size_t pin_len,
                 const uint8_t plaintext[M9_SEALED_SEED_LEN],
                 m9_sealed_seed_t *out);

// Unseal: verify Poly1305 tag and decrypt. Returns 0 on success,
// -1 on authentication failure (wrong PIN or tampered blob).
int m9_unseal_seed(const uint8_t *pin, size_t pin_len,
                   const m9_sealed_seed_t *in,
                   uint8_t out_plaintext[M9_SEALED_SEED_LEN]);
