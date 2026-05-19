#pragma once
#include <stdbool.h>
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

// ----- Phase 7.2: persistence + attempt counter -------------------------
//
// SEED_FLASH sector layout (4 KB):
//   page 0  (256B):  header { magic, version, sealed blob }
//   page 1 .. 10:    counter pages -- programmed to all-0x00 on each
//                    failed unlock; count = number of all-zero pages
//   page 11..15:     unused (reserved for future)
//
// Threshold = 10 failed attempts in a row -> factory wipe of SEED +
// CHAINS + HWM. Counter is incremented BEFORE the unseal attempt, so a
// power-cycle during unseal can't reset the count.

#define M9_PIN_MAX_ATTEMPTS  10
#define M9_PIN_MIN_LEN        4u
#define M9_PIN_MAX_LEN       16u

// True if SEED_FLASH currently holds a valid sealed blob (i.e. a PIN
// is configured). On first boot returns false.
bool m9_seed_flash_is_initialized(void);

// Count of failed-unlock attempts since the last successful unlock.
// 0 right after PIN setup or successful unlock; saturates at
// M9_PIN_MAX_ATTEMPTS.
int  m9_pin_attempts(void);

// Persist a fresh sealed blob: erases the sector, programs page 0.
int  m9_seed_flash_store(const m9_sealed_seed_t *blob);

// XIP pointer to the on-flash sealed blob, or NULL if not initialized.
const m9_sealed_seed_t *m9_seed_flash_load(void);

// Program the next counter page to zeros. No-op if already at max.
void m9_pin_attempt_record_failure(void);

// Erase + reprogram the sector to clear counter pages while preserving
// the sealed blob. Called after a successful unlock.
void m9_pin_attempt_reset(void);

// Full wipe: erase SEED + CHAINS + HWM sectors. Called when the PIN
// attempt counter hits M9_PIN_MAX_ATTEMPTS; also invokable from the
// factory-reset confirm flow.
void m9_factory_wipe_all(void);

// Veneer-callable return codes (mirrors veneers.c's M9_NEG_*).
#define M9_PIN_OK              0
#define M9_PIN_ERR_ALREADY_SET (-1)
#define M9_PIN_ERR_WIPED       (-2)   // attempt counter exhausted -> wiped
#define M9_PIN_ERR_BAD_PIN     (-3)
#define M9_PIN_ERR_INTERNAL    (-4)
