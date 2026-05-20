#include <string.h>

#include "os/crypto/keystore.h"
#include "os/api.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
// ============================================================================
// Non-Secure side. The seed never appears here -- every signing-related
// call delegates to the Secure veneer (NSC entry in firmware/m9/veneers.c).
// ============================================================================
#include "os/secure_api.h"

int os_crypto_get_pubkey(os_curve_t curve, const char *path,
                         uint8_t *out_pubkey, size_t out_size,
                         size_t *out_len) {
    if (out_size < 32) return KEYSTORE_ERR_BUFFER_TOO_SMALL;
    int rc = s_get_pubkey((uint8_t)curve, path, out_pubkey);
    if (rc == 0) *out_len = 32;
    return rc;
}

int os_crypto_sign(os_curve_t curve, const char *path,
                   const uint8_t *data, size_t data_len,
                   uint8_t out_sig[64]) {
    if (curve != OS_CURVE_ED25519) return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (data_len != 32) {
        // Under TZ this dispatcher only handles SC handshake challenges
        // (length-locked, no HWM context). Privval canonical sign-bytes
        // (variable length) MUST go through s_sign_and_advance directly,
        // which fuses HWM strict-advance with the signature -- there is
        // no generic signing oracle veneer.
        return KEYSTORE_ERR_BAD_PATH;
    }
    return s_sign_sc_challenge((uint8_t)curve, path, data, out_sig);
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

#else
// ============================================================================
// Secure-side (or pre-TZ single-image): full implementation including the
// seed. The same code path also services the SG veneers in veneers.c via
// keystore_derive_pubkey / keystore_sign.
// ============================================================================
#include "os/crypto/monocypher.h"           // crypto_wipe
#include "os/crypto/monocypher-ed25519.h"

// ============================================================================
// M9.5 master-seed cache. Filled by m9_master_seed_set after the PIN-unlock /
// PIN-setup flow unseals the on-flash blob; cleared by m9_master_seed_clear
// on factory wipe. The DERIVED signing path uses this; until unlocked, the
// signing path fails closed.
// ============================================================================
#define MASTER_SEED_LEN 64u
static uint8_t  s_master_seed[MASTER_SEED_LEN];
static bool     s_master_seed_loaded = false;

void m9_master_seed_set(const uint8_t seed[MASTER_SEED_LEN]) {
    if (!seed) {
        m9_master_seed_clear();
        return;
    }
    memcpy(s_master_seed, seed, MASTER_SEED_LEN);
    s_master_seed_loaded = true;
}

void m9_master_seed_clear(void) {
    crypto_wipe(s_master_seed, MASTER_SEED_LEN);
    s_master_seed_loaded = false;
}

bool m9_master_seed_loaded(void) { return s_master_seed_loaded; }

// Per SLIP-10 spec for Ed25519.
static const char SLIP10_ED25519_MASTER[] = "ed25519 seed";

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
// SLIP-10 Ed25519 single child step. The master step is now inlined in
// derive_ed25519_from_seed (Phase 7.6) so the seed is a function
// parameter instead of TEST_SEED.
//
// `index` must be hardened (high bit set), else returns ERR_NON_HARDENED.
// ---------------------------------------------------------------------------
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
    // `data` carries the parent private key in bytes [1..32]; `next`
    // is the freshly derived child node (also keyed material). Both
    // must be wiped before return -- memset would be DCE-prunable
    // because nothing reads these stack locals afterward.
    crypto_wipe(data, sizeof(data));
    crypto_wipe(next, sizeof(next));
    return KEYSTORE_OK;
}

// Derive an Ed25519 keypair (secret_key 64 bytes, public_key 32 bytes)
// from an arbitrary seed via SLIP-10. The seed is fed into the master
// HMAC instead of using TEST_SEED, so the same derivation logic serves
// the master seed (Phase 7.6) and per-slot MNEMONIC overrides (Phase 7.5).
static int derive_ed25519_from_seed(const uint8_t *seed, size_t seed_len,
                                    const char *path,
                                    uint8_t secret_key[64], uint8_t public_key[32]) {
    uint32_t indices[KEYSTORE_MAX_DEPTH];
    int n = parse_path(path, indices, KEYSTORE_MAX_DEPTH);
    if (n < 0) return n;

    uint8_t node[64];
    crypto_sha512_hmac(node,
                       (const uint8_t *)SLIP10_ED25519_MASTER,
                       sizeof(SLIP10_ED25519_MASTER) - 1,
                       seed, seed_len);
    for (int i = 0; i < n; i++) {
        int rc = slip10_ed25519_step(node, indices[i]);
        if (rc != KEYSTORE_OK) {
            crypto_wipe(node, sizeof(node));
            return rc;
        }
    }

    uint8_t ed_seed[32];
    memcpy(ed_seed, node, 32);
    crypto_ed25519_key_pair(secret_key, public_key, ed_seed);

    crypto_wipe(ed_seed, sizeof(ed_seed));
    crypto_wipe(node,    sizeof(node));
    return KEYSTORE_OK;
}

// Master-seed wrapper: derives from the unlocked BIP-39 master seed.
// Fails with KEYSTORE_ERR_BAD_PATH if the device hasn't been unlocked
// yet (no seed loaded -- the DERIVED signing path is unreachable
// pre-unlock).
static int derive_ed25519(const char *path,
                          uint8_t secret_key[64], uint8_t public_key[32]) {
    if (!s_master_seed_loaded) return KEYSTORE_ERR_BAD_PATH;
    return derive_ed25519_from_seed(s_master_seed, MASTER_SEED_LEN,
                                    path, secret_key, public_key);
}

// Public Secure-side helpers used by s_sign_and_advance when the slot's
// seed source is MNEMONIC (BIP-39 64-byte seed -> SLIP-10) or RAW_KEY
// (32-byte Ed25519 seed used directly).
int keystore_sign_with_bip39_seed(const uint8_t bip39_seed[64],
                                  const char *path,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out_sig[64]) {
    if (!bip39_seed || !path || !data || !out_sig) return KEYSTORE_ERR_BAD_PATH;
    uint8_t sk[64];
    uint8_t pk[32];
    int rc = derive_ed25519_from_seed(bip39_seed, 64, path, sk, pk);
    if (rc != KEYSTORE_OK) {
        crypto_wipe(sk, sizeof(sk));
        return rc;
    }
    crypto_ed25519_sign(out_sig, sk, data, data_len);
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(pk, sizeof(pk));
    return KEYSTORE_OK;
}

int keystore_sign_with_raw_key(const uint8_t raw_seed[32],
                               const uint8_t *data, size_t data_len,
                               uint8_t out_sig[64]) {
    if (!raw_seed || !data || !out_sig) return KEYSTORE_ERR_BAD_PATH;
    uint8_t sk[64];
    uint8_t pk[32];
    crypto_ed25519_key_pair(sk, pk, raw_seed);
    crypto_ed25519_sign(out_sig, sk, data, data_len);
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(pk, sizeof(pk));
    return KEYSTORE_OK;
}

// ---------------------------------------------------------------------------
// Public entry points. Called directly in pre-TZ builds, and via the Secure
// Gateway veneers (s_get_pubkey / s_sign_sc_challenge) under M9.
// ---------------------------------------------------------------------------
int os_crypto_get_pubkey(os_curve_t curve, const char *path,
                         uint8_t *out_pubkey, size_t out_size,
                         size_t *out_len) {
    if (curve == OS_CURVE_SECP256K1) return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (curve != OS_CURVE_ED25519)   return KEYSTORE_ERR_CURVE_UNSUPPORTED;
    if (out_size < 32)               return KEYSTORE_ERR_BUFFER_TOO_SMALL;

    uint8_t secret_key[64];
    int rc = derive_ed25519(path, secret_key, out_pubkey);
    crypto_wipe(secret_key, sizeof(secret_key));
    if (rc != KEYSTORE_OK) return rc;

    *out_len = 32;
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
        crypto_wipe(secret_key, sizeof(secret_key));
        return rc;
    }

    crypto_ed25519_sign(out_sig, secret_key, data, data_len);

    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(public_key, sizeof(public_key));
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

#endif // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
