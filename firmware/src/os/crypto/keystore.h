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
