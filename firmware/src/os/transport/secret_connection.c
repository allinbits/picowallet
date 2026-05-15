#include <string.h>

#include "os/crypto/monocypher.h"
#include "os/crypto/sha256.h"
#include "os/transport/secret_connection.h"

static const char SC_INFO_KEYS[] =
    "TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN";
#define SC_INFO_KEYS_LEN (sizeof(SC_INFO_KEYS) - 1u)  // 50 bytes, excludes NUL

// libsodium's 7-element low-order point blacklist (see gno's tm2 source).
static const uint8_t sc_small_order_blacklist[7][SC_KEY_SIZE] = {
    // 0 (order 4)
    {0},
    // 1 (order 1)
    {0x01},
    // 325...504 (order 8)
    {0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,
     0xfa,0xf1,0x9f,0xc4,0x6a,0xda,0x09,0x8d,0xeb,0x9c,0x32,
     0xb1,0xfd,0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00},
    // 393...823 (order 8)
    {0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,
     0x55,0x9c,0x83,0xef,0x5b,0x04,0x44,0x5c,0xc4,0x58,0x1c,
     0x8e,0x86,0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57},
    // p-1 (order 2)
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    // p (order 4)
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    // p+1 (order 1)
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
};

void sc_derive_keys_hkdf(const uint8_t dh_secret[SC_KEY_SIZE],
                         bool loc_is_least,
                         uint8_t out_recv_key[SC_KEY_SIZE],
                         uint8_t out_send_key[SC_KEY_SIZE],
                         uint8_t out_challenge[SC_KEY_SIZE]) {
    // RFC 5869: when salt is empty, use 32 zero bytes (hkdf_extract handles).
    uint8_t prk[SHA256_OUT_LEN];
    hkdf_extract(NULL, 0, dh_secret, SC_KEY_SIZE, prk);

    uint8_t okm[3 * SC_KEY_SIZE];
    hkdf_expand(prk, SHA256_OUT_LEN,
                (const uint8_t *)SC_INFO_KEYS, SC_INFO_KEYS_LEN,
                okm, sizeof(okm));
    crypto_wipe(prk, sizeof(prk));

    // First and second 32B halves are AEAD keys, ordered by locIsLeast.
    if (loc_is_least) {
        memcpy(out_recv_key, okm + 0,             SC_KEY_SIZE);
        memcpy(out_send_key, okm + SC_KEY_SIZE,   SC_KEY_SIZE);
    } else {
        memcpy(out_send_key, okm + 0,             SC_KEY_SIZE);
        memcpy(out_recv_key, okm + SC_KEY_SIZE,   SC_KEY_SIZE);
    }
    memcpy(out_challenge, okm + 2 * SC_KEY_SIZE, SC_KEY_SIZE);
    crypto_wipe(okm, sizeof(okm));
}

void sc_init(secret_conn_t *sc,
             const uint8_t recv_key[SC_KEY_SIZE],
             const uint8_t send_key[SC_KEY_SIZE]) {
    memcpy(sc->recv_key, recv_key, SC_KEY_SIZE);
    memcpy(sc->send_key, send_key, SC_KEY_SIZE);
    sc->send_seq = 0;
    sc->recv_seq = 0;
}

void sc_wipe(secret_conn_t *sc) {
    crypto_wipe(sc, sizeof(*sc));
}

// Build a 12-byte nonce from the per-direction sequence counter.
//   nonce[0..4]  = 0
//   nonce[4..12] = little-endian uint64(seq)
static void sc_build_nonce(uint64_t seq, uint8_t out[SC_AEAD_NONCE_SIZE]) {
    out[0] = out[1] = out[2] = out[3] = 0;
    for (int i = 0; i < 8; i++) {
        out[4 + i] = (uint8_t)(seq >> (8 * i));
    }
}

void sc_seal_frame(secret_conn_t *sc,
                   const uint8_t *chunk, uint32_t chunk_len,
                   uint8_t out_sealed[SC_SEALED_FRAME_SIZE]) {
    // Build the plaintext frame: 4-byte LE length || chunk || zero pad.
    uint8_t frame[SC_FRAME_SIZE];
    frame[0] = (uint8_t)(chunk_len      );
    frame[1] = (uint8_t)(chunk_len >>  8);
    frame[2] = (uint8_t)(chunk_len >> 16);
    frame[3] = (uint8_t)(chunk_len >> 24);
    if (chunk_len) memcpy(frame + SC_DATA_LEN_SIZE, chunk, chunk_len);
    if (chunk_len < SC_DATA_MAX_SIZE) {
        memset(frame + SC_DATA_LEN_SIZE + chunk_len, 0,
               SC_DATA_MAX_SIZE - chunk_len);
    }

    uint8_t nonce[SC_AEAD_NONCE_SIZE];
    sc_build_nonce(sc->send_seq, nonce);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, sc->send_key, nonce);
    crypto_aead_write(&ctx,
                      out_sealed,                      // cipher_text
                      out_sealed + SC_FRAME_SIZE,      // mac (16B trailing)
                      NULL, 0,                         // no AAD
                      frame, SC_FRAME_SIZE);
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(frame, sizeof(frame));

    sc->send_seq++;  // wraparound at 2^64 frames; not a practical concern
}

int sc_open_frame(secret_conn_t *sc,
                  const uint8_t sealed[SC_SEALED_FRAME_SIZE],
                  uint8_t out_chunk[SC_DATA_MAX_SIZE],
                  uint32_t *out_len) {
    uint8_t nonce[SC_AEAD_NONCE_SIZE];
    sc_build_nonce(sc->recv_seq, nonce);

    uint8_t frame[SC_FRAME_SIZE];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, sc->recv_key, nonce);
    int rc = crypto_aead_read(&ctx,
                              frame,                          // plain_text
                              sealed + SC_FRAME_SIZE,         // mac
                              NULL, 0,
                              sealed, SC_FRAME_SIZE);
    crypto_wipe(&ctx, sizeof(ctx));
    if (rc != 0) {
        // MAC mismatch: do NOT advance recv_seq — caller may retry with the
        // same seq if they think this was line noise. (Tendermint terminates
        // the session on MAC failure, so in practice this is fatal anyway.)
        crypto_wipe(frame, sizeof(frame));
        return -1;
    }

    uint32_t chunk_len = (uint32_t)frame[0]
                       | ((uint32_t)frame[1] <<  8)
                       | ((uint32_t)frame[2] << 16)
                       | ((uint32_t)frame[3] << 24);
    if (chunk_len > SC_DATA_MAX_SIZE) {
        crypto_wipe(frame, sizeof(frame));
        sc->recv_seq++;  // peer is authenticated; this is a protocol violation
        return -2;
    }

    if (chunk_len) memcpy(out_chunk, frame + SC_DATA_LEN_SIZE, chunk_len);
    *out_len = chunk_len;
    crypto_wipe(frame, sizeof(frame));
    sc->recv_seq++;
    return 0;
}

int sc_is_small_order(const uint8_t pub[SC_KEY_SIZE]) {
    for (size_t i = 0; i < sizeof(sc_small_order_blacklist) / SC_KEY_SIZE; i++) {
        // Constant-time compare to avoid leaking which entry matched.
        if (crypto_verify32(pub, sc_small_order_blacklist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void sc_sort32(const uint8_t a[SC_KEY_SIZE], const uint8_t b[SC_KEY_SIZE],
               const uint8_t **lo, const uint8_t **hi, bool *loc_is_least) {
    int cmp = memcmp(a, b, SC_KEY_SIZE);
    if (cmp < 0) {
        *lo = a; *hi = b; *loc_is_least = true;
    } else {
        *lo = b; *hi = a; *loc_is_least = false;
    }
}
