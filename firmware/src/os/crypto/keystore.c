#include <string.h>

#include "os/crypto/keystore.h"
#include "os/api.h"
#include "os/crypto/monocypher-ed25519.h"

// ============================================================================
// TEST FIXTURE seed. M4 replaces this with seed unwrapped from encrypted flash
// using the PIN. Do NOT use this build for real funds.
// ============================================================================
static const uint8_t TEST_SEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

// Per SLIP-10 spec for Ed25519.
static const char SLIP10_ED25519_MASTER[] = "ed25519 seed";
static const uint8_t HARDENED_BIT = 0x80;

// ---------------------------------------------------------------------------
// Path parsing: "m" or "m/n[']/n[']/..."
// On success: fills indices, returns count (>= 0).
// On failure: returns negative keystore_status_t.
// ---------------------------------------------------------------------------
static int parse_path(const char *path, uint32_t *out, size_t out_max) {
    if (!path || path[0] != 'm') return KEYSTORE_ERR_BAD_PATH;
    const char *p = path + 1;
    if (*p == '\0') return 0;
    if (*p != '/') return KEYSTORE_ERR_BAD_PATH;
    p++;  // skip first '/'

    size_t count = 0;
    while (*p) {
        if (count >= out_max) return KEYSTORE_ERR_PATH_TOO_DEEP;
        if (*p < '0' || *p > '9') return KEYSTORE_ERR_BAD_PATH;

        uint32_t n = 0;
        while (*p >= '0' && *p <= '9') {
            // overflow guard before *10
            if (n > 0xFFFFFFFFu / 10u) return KEYSTORE_ERR_BAD_PATH;
            n = n * 10u + (uint32_t)(*p - '0');
            p++;
        }
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            if (n & 0x80000000u) return KEYSTORE_ERR_BAD_PATH;  // already too high
            n |= 0x80000000u;
            p++;
        }
        out[count++] = n;

        if (*p == '\0') break;
        if (*p != '/') return KEYSTORE_ERR_BAD_PATH;
        p++;
    }
    return (int)count;
}

// ---------------------------------------------------------------------------
// SLIP-10 Ed25519: master + single child step.
// `node` is a 64-byte buffer: first 32 = private key, last 32 = chain code.
// ---------------------------------------------------------------------------
static void slip10_ed25519_master(uint8_t node[64]) {
    crypto_sha512_hmac(node,
                       (const uint8_t *)SLIP10_ED25519_MASTER,
                       sizeof(SLIP10_ED25519_MASTER) - 1,
                       TEST_SEED, sizeof(TEST_SEED));
}

// `index` must be hardened (high bit set), else returns ERR_NON_HARDENED.
static int slip10_ed25519_step(uint8_t node[64], uint32_t index) {
    if ((index & 0x80000000u) == 0) return KEYSTORE_ERR_NON_HARDENED;
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, node, 32);  // parent private key
    data[33] = (uint8_t)(index >> 24);
    data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >>  8);
    data[36] = (uint8_t)(index);
    uint8_t next[64];
    crypto_sha512_hmac(next, node + 32, 32, data, sizeof(data));
    memcpy(node, next, 64);
    return KEYSTORE_OK;
}

static int derive_ed25519(const char *path,
                          uint8_t secret_key[64], uint8_t public_key[32]);

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------
int os_crypto_get_pubkey(os_curve_t curve, const char *path,
                         uint8_t *out_pubkey, size_t out_size,
                         size_t *out_len) {
    if (curve == OS_CURVE_SECP256K1) return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (curve != OS_CURVE_ED25519)   return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (out_size < 32)               return KEYSTORE_ERR_BUFFER_TOO_SMALL;

    uint8_t secret_key[64];
    int rc = derive_ed25519(path, secret_key, out_pubkey);
    memset(secret_key, 0, sizeof(secret_key));
    if (rc != KEYSTORE_OK) return rc;

    *out_len = 32;
    return KEYSTORE_OK;
}

// Derive an Ed25519 secret key (64 bytes) and public key (32 bytes) for the
// given path. Returns 0 on success, negative keystore_status_t on failure.
static int derive_ed25519(const char *path,
                         uint8_t secret_key[64], uint8_t public_key[32]) {
    uint32_t indices[KEYSTORE_MAX_DEPTH];
    int n = parse_path(path, indices, KEYSTORE_MAX_DEPTH);
    if (n < 0) return n;

    uint8_t node[64];
    slip10_ed25519_master(node);
    for (int i = 0; i < n; i++) {
        int rc = slip10_ed25519_step(node, indices[i]);
        if (rc != KEYSTORE_OK) {
            memset(node, 0, sizeof(node));
            return rc;
        }
    }

    uint8_t ed_seed[32];
    memcpy(ed_seed, node, 32);
    crypto_ed25519_key_pair(secret_key, public_key, ed_seed);

    memset(ed_seed, 0, sizeof(ed_seed));
    memset(node,    0, sizeof(node));
    return KEYSTORE_OK;
}

int os_crypto_sign(os_curve_t curve, const char *path,
                   const uint8_t *data, size_t data_len,
                   uint8_t out_sig[64]) {
    if (curve == OS_CURVE_SECP256K1) return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (curve != OS_CURVE_ED25519)   return KEYSTORE_ERR_CURVE_UNSUPPORTED;

    uint8_t secret_key[64];
    uint8_t public_key[32];
    int rc = derive_ed25519(path, secret_key, public_key);
    if (rc != KEYSTORE_OK) {
        memset(secret_key, 0, sizeof(secret_key));
        return rc;
    }

    crypto_ed25519_sign(out_sig, secret_key, data, data_len);

    memset(secret_key, 0, sizeof(secret_key));
    memset(public_key, 0, sizeof(public_key));
    return KEYSTORE_OK;
}

const char *os_crypto_status_str(int s) {
    switch (s) {
        case KEYSTORE_OK:                    return "ok";
        case KEYSTORE_ERR_BAD_PATH:          return "bad_path";
        case KEYSTORE_ERR_NON_HARDENED:      return "non_hardened_disallowed";
        case KEYSTORE_ERR_CURVE_UNSUPPORTED: return "curve_not_implemented";
        case KEYSTORE_ERR_BUFFER_TOO_SMALL:  return "buffer_too_small";
        case KEYSTORE_ERR_PATH_TOO_DEEP:     return "path_too_deep";
    }
    return "derive_err";
}
