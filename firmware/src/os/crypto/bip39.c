// M9.5 Phase 7.3 -- BIP-39 mnemonic generate + seed derivation.

#if PICOWALLET_SECURE_BUILD

#include "os/crypto/bip39.h"
#include "os/crypto/bip39_wordlist.h"

#include <string.h>

#include "os/crypto/monocypher.h"
#include "os/crypto/monocypher-ed25519.h"

// --- Helpers ---------------------------------------------------------------

// Compute the 8-bit BIP-39 checksum: SHA-256(entropy)[0] for ENT=256.
static uint8_t bip39_checksum_byte(const uint8_t entropy[BIP39_ENTROPY_BYTES]) {
    // We can't reach pico_sha256 from here cleanly (it's the hardware
    // wrapper used elsewhere; Secure-side that's fine). To avoid a
    // dependency cycle just use sha256() from os/crypto/sha256.h which
    // is also Secure-only.
    extern void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
    uint8_t h[32];
    sha256(entropy, BIP39_ENTROPY_BYTES, h);
    uint8_t cs = h[0];
    crypto_wipe(h, sizeof(h));
    return cs;
}

// Pack 264 bits (32 entropy + 1 checksum) into 24 11-bit word indices.
static void pack_indices(const uint8_t bits[33],
                         uint16_t out[BIP39_MNEMONIC_WORDS]) {
    for (int w = 0; w < BIP39_MNEMONIC_WORDS; w++) {
        // Extract 11 bits starting at bit (w * 11) from MSB-first stream.
        uint32_t bit_off  = (uint32_t)w * 11u;
        uint32_t byte_off = bit_off >> 3;
        uint32_t shift    = bit_off & 7u;
        // We need up to 19 bits across 3 bytes.
        uint32_t v = ((uint32_t)bits[byte_off    ] << 16) |
                     ((uint32_t)bits[byte_off + 1] <<  8) |
                     ((uint32_t)bits[byte_off + 2]);
        // Top 11 bits after consuming `shift` leading bits.
        out[w] = (uint16_t)((v >> (24 - shift - 11)) & 0x7FFu);
    }
}

// Inverse: turn 24 word indices into 33 bytes (264 bits).
static void unpack_indices(const uint16_t indices[BIP39_MNEMONIC_WORDS],
                           uint8_t out_bits[33]) {
    memset(out_bits, 0, 33);
    for (int w = 0; w < BIP39_MNEMONIC_WORDS; w++) {
        uint32_t v        = (uint32_t)indices[w] & 0x7FFu;
        uint32_t bit_off  = (uint32_t)w * 11u;
        uint32_t byte_off = bit_off >> 3;
        uint32_t shift    = bit_off & 7u;
        // Place 11 bits starting at (shift) into bytes [byte_off..byte_off+2].
        uint32_t v_shifted = v << (24u - shift - 11u);
        out_bits[byte_off    ] |= (uint8_t)((v_shifted >> 16) & 0xFFu);
        out_bits[byte_off + 1] |= (uint8_t)((v_shifted >>  8) & 0xFFu);
        out_bits[byte_off + 2] |= (uint8_t)((v_shifted      ) & 0xFFu);
    }
}

void bip39_generate(uint8_t entropy[BIP39_ENTROPY_BYTES],
                    uint16_t out_word_indices[BIP39_MNEMONIC_WORDS]) {
    uint8_t cs = bip39_checksum_byte(entropy);
    uint8_t bits[33];
    memcpy(bits, entropy, BIP39_ENTROPY_BYTES);
    bits[BIP39_ENTROPY_BYTES] = cs;
    pack_indices(bits, out_word_indices);
    crypto_wipe(bits, sizeof(bits));
}

bool bip39_check_checksum(const uint16_t word_indices[BIP39_MNEMONIC_WORDS]) {
    uint8_t bits[33];
    unpack_indices(word_indices, bits);
    uint8_t entropy[BIP39_ENTROPY_BYTES];
    memcpy(entropy, bits, BIP39_ENTROPY_BYTES);
    uint8_t expect = bip39_checksum_byte(entropy);
    crypto_wipe(entropy, sizeof(entropy));
    bool ok = (bits[BIP39_ENTROPY_BYTES] == expect);
    crypto_wipe(bits, sizeof(bits));
    return ok;
}

size_t bip39_format_phrase(const uint16_t word_indices[BIP39_MNEMONIC_WORDS],
                           char *out_buf, size_t out_size) {
    size_t n = 0;
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
        const char *w = bip39_wordlist[word_indices[i]];
        size_t wl = 0;
        while (w[wl] != '\0') wl++;
        if (n + wl + 1u >= out_size) return 0;
        if (i > 0) out_buf[n++] = ' ';
        memcpy(out_buf + n, w, wl);
        n += wl;
    }
    if (n < out_size) out_buf[n] = '\0';
    return n;
}

// --- PBKDF2-HMAC-SHA512 ----------------------------------------------------
//
// BIP-39 spec: 2048 iterations, salt = "mnemonic" + passphrase (UTF-8).
// We only need a single 64-byte block of output (dkLen = 64 = hLen).

static void pbkdf2_hmac_sha512_block1(const uint8_t *password, size_t pw_len,
                                      const uint8_t *salt, size_t salt_len,
                                      uint32_t iterations,
                                      uint8_t out[64]) {
    // U_1 = HMAC(password, salt || INT_32_BE(1))
    uint8_t salt_block[64 + 4];     // BIP-39 salt is "mnemonic"+passphrase
                                    // (passphrase capped to 25 chars in v1).
    if (salt_len + 4u > sizeof(salt_block)) return;
    memcpy(salt_block, salt, salt_len);
    salt_block[salt_len + 0] = 0;
    salt_block[salt_len + 1] = 0;
    salt_block[salt_len + 2] = 0;
    salt_block[salt_len + 3] = 1;

    uint8_t u[64];
    crypto_sha512_hmac(u, password, pw_len, salt_block, salt_len + 4u);
    memcpy(out, u, 64);

    for (uint32_t i = 1; i < iterations; i++) {
        crypto_sha512_hmac(u, password, pw_len, u, 64);
        for (int j = 0; j < 64; j++) out[j] ^= u[j];
    }
    crypto_wipe(u, sizeof(u));
    crypto_wipe(salt_block, sizeof(salt_block));
}

void bip39_to_seed(const uint16_t word_indices[BIP39_MNEMONIC_WORDS],
                   uint8_t out_seed[BIP39_SEED_BYTES]) {
    char phrase[BIP39_MNEMONIC_WORDS * (BIP39_WORD_MAX_LEN + 1)];  // 216
    size_t phrase_len = bip39_format_phrase(word_indices, phrase, sizeof(phrase));

    // BIP-39 salt = literal "mnemonic" + passphrase. No passphrase in v1.
    static const uint8_t SALT[] = { 'm','n','e','m','o','n','i','c' };

    pbkdf2_hmac_sha512_block1((const uint8_t *)phrase, phrase_len,
                              SALT, sizeof(SALT),
                              2048u, out_seed);
    crypto_wipe(phrase, sizeof(phrase));
}

#endif  // PICOWALLET_SECURE_BUILD
