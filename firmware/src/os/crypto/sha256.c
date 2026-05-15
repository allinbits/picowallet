#include <string.h>

#include "pico/sha256.h"

#include "os/crypto/sha256.h"

#define SHA256_BLOCK_LEN 64

static void sha256_oneshot(const uint8_t *data, size_t len, uint8_t out[SHA256_OUT_LEN]) {
    pico_sha256_state_t st;
    // Claim the peripheral; block until available. Single-threaded firmware,
    // so contention is impossible in practice, but be defensive.
    while (pico_sha256_try_start(&st, SHA256_BIG_ENDIAN, false) != PICO_OK) {
        tight_loop_contents();
    }
    pico_sha256_update(&st, data, len);
    sha256_result_t r;
    pico_sha256_finish(&st, &r);
    memcpy(out, r.bytes, SHA256_OUT_LEN);
}

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_OUT_LEN]) {
    sha256_oneshot(data, len, out);
}

void hmac_sha256(const uint8_t *key,  size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_OUT_LEN]) {
    uint8_t k[SHA256_BLOCK_LEN];
    if (key_len > SHA256_BLOCK_LEN) {
        sha256_oneshot(key, key_len, k);
        memset(k + SHA256_OUT_LEN, 0, SHA256_BLOCK_LEN - SHA256_OUT_LEN);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, SHA256_BLOCK_LEN - key_len);
    }

    uint8_t ipad[SHA256_BLOCK_LEN];
    uint8_t opad[SHA256_BLOCK_LEN];
    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // inner = SHA256(ipad || data)
    pico_sha256_state_t st;
    while (pico_sha256_try_start(&st, SHA256_BIG_ENDIAN, false) != PICO_OK) {
        tight_loop_contents();
    }
    pico_sha256_update(&st, ipad, SHA256_BLOCK_LEN);
    pico_sha256_update(&st, data, data_len);
    sha256_result_t inner;
    pico_sha256_finish(&st, &inner);

    // outer = SHA256(opad || inner)
    while (pico_sha256_try_start(&st, SHA256_BIG_ENDIAN, false) != PICO_OK) {
        tight_loop_contents();
    }
    pico_sha256_update(&st, opad, SHA256_BLOCK_LEN);
    pico_sha256_update(&st, inner.bytes, SHA256_OUT_LEN);
    sha256_result_t outer;
    pico_sha256_finish(&st, &outer);

    memcpy(out, outer.bytes, SHA256_OUT_LEN);
}

void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm,  size_t ikm_len,
                  uint8_t prk[SHA256_OUT_LEN]) {
    // RFC 5869: if salt is empty, use 32 zero bytes.
    static const uint8_t zero_salt[SHA256_OUT_LEN] = {0};
    if (salt == NULL || salt_len == 0) {
        hmac_sha256(zero_salt, SHA256_OUT_LEN, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

void hkdf_expand(const uint8_t *prk,  size_t prk_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
    uint8_t  t[SHA256_OUT_LEN];
    size_t   t_len  = 0;
    size_t   pos    = 0;
    uint8_t  counter = 1;

    // T(N) = HMAC(prk, T(N-1) || info || N). Materialize the concatenation
    // in a stack buffer; caller must ensure info_len <= 128 (caps total at 161).
    uint8_t  buf[SHA256_OUT_LEN + 128 + 1];
    while (pos < okm_len) {
        size_t buf_len = 0;
        if (t_len) {
            memcpy(buf + buf_len, t, SHA256_OUT_LEN);
            buf_len += SHA256_OUT_LEN;
        }
        if (info_len) {
            memcpy(buf + buf_len, info, info_len);
            buf_len += info_len;
        }
        buf[buf_len++] = counter++;

        hmac_sha256(prk, prk_len, buf, buf_len, t);
        t_len = SHA256_OUT_LEN;

        size_t take = okm_len - pos;
        if (take > SHA256_OUT_LEN) take = SHA256_OUT_LEN;
        memcpy(okm + pos, t, take);
        pos += take;
    }
}
