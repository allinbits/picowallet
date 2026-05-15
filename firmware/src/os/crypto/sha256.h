#pragma once
#include <stddef.h>
#include <stdint.h>

#define SHA256_OUT_LEN 32

// One-shot SHA-256 backed by RP2350's hardware peripheral.
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_OUT_LEN]);

// HMAC-SHA-256 per RFC 2104.
void hmac_sha256(const uint8_t *key,  size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_OUT_LEN]);

// HKDF-SHA-256 extract: prk = HMAC(salt, ikm).
void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm,  size_t ikm_len,
                  uint8_t prk[SHA256_OUT_LEN]);

// HKDF-SHA-256 expand: okm = T(1) || T(2) || ... per RFC 5869.
// okm_len must be <= 255 * 32 (8160 bytes).
void hkdf_expand(const uint8_t *prk,  size_t prk_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);
