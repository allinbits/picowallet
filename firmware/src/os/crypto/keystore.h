#pragma once
#include <stddef.h>
#include <stdint.h>

#include "os/api.h"

typedef enum {
    KEYSTORE_OK                    =  0,
    KEYSTORE_ERR_BAD_PATH          = -1,
    KEYSTORE_ERR_NON_HARDENED      = -2,  // SLIP-10 Ed25519 requires hardened indices
    KEYSTORE_ERR_CURVE_UNSUPPORTED = -3,
    KEYSTORE_ERR_BUFFER_TOO_SMALL  = -4,
    KEYSTORE_ERR_PATH_TOO_DEEP     = -5,
} keystore_status_t;

#define KEYSTORE_MAX_DEPTH 16

// Phase 7.5 Secure-side helpers used by s_sign_and_advance when the
// chain slot carries a seed override. Both ignore TEST_SEED and use
// only the caller-supplied material. Declared in the header so the
// veneer body can link against them; defined only under
// PICOWALLET_SECURE_BUILD in keystore.c.
int keystore_sign_with_bip39_seed(const uint8_t bip39_seed[64],
                                  const char *path,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out_sig[64]);
int keystore_sign_with_raw_key(const uint8_t raw_seed[32],
                               const uint8_t *data, size_t data_len,
                               uint8_t out_sig[64]);
