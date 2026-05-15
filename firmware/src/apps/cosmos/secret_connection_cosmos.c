#include <string.h>

#include "pico/rand.h"

#include "os/crypto/monocypher.h"
#include "os/crypto/monocypher-ed25519.h"
#include "os/crypto/merlin.h"
#include "apps/cosmos/secret_connection_cosmos.h"

// -- protobuf wire constants -----------------------------------------------
// Field 1, wire-type 2 (ByteLength): tag byte = (1 << 3) | 2 = 0x0a
// Field 2, wire-type 2 (ByteLength): tag byte = (2 << 3) | 2 = 0x12
#define PB_TAG_F1_BYTES   0x0a
#define PB_TAG_F2_BYTES   0x12

// Ephemeral exchange: `gogotypes.BytesValue{Value: ephPub}` length-delimited.
//   uvarint(34) || 0x0a || varint(32) || <32 bytes>      = 35 bytes
#define EPH_OUTER_LEN   34u

// AuthSigMessage{PubKey: PublicKey{Ed25519: bytes}, Sig: bytes}:
//   uvarint(102) || 0x0a varint(34) [0x0a varint(32) <32 pubkey>]
//                || 0x12 varint(64) <64 sig>             = 103 bytes
//   field 1 outer length = 34 (PublicKey-encoded ed25519 oneof inside)
//   PublicKey inner      = 34 bytes: 0x0a 0x20 <32>
#define AUTH_OUTER_LEN         102u
#define AUTH_PUBKEY_INNER_LEN   34u  // 0x0a 0x20 <32>

// -- Merlin labels (verbatim from cometbft p2p/conn/secret_connection.go) --
#define LBL_TRANSCRIPT   "TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH"
#define LBL_EPH_LOWER    "EPHEMERAL_LOWER_PUBLIC_KEY"
#define LBL_EPH_UPPER    "EPHEMERAL_UPPER_PUBLIC_KEY"
#define LBL_DH_SECRET    "DH_SECRET"
#define LBL_MAC          "SECRET_CONNECTION_MAC"

static void fill_random(uint8_t *out, size_t n) {
    size_t i = 0;
    while (i + 8 <= n) {
        uint64_t r = get_rand_64();
        for (int j = 0; j < 8; j++) out[i + j] = (uint8_t)(r >> (8 * j));
        i += 8;
    }
    if (i < n) {
        uint64_t r = get_rand_64();
        for (size_t j = 0; j < n - i; j++) out[i + j] = (uint8_t)(r >> (8 * j));
    }
}

void cosmos_sc_start(cosmos_sc_t *sc,
                     const uint8_t val_pub[32],
                     uint8_t out_eph_msg[COSMOS_SC_EPH_MSG_SIZE]) {
    memset(sc, 0, sizeof(*sc));
    sc->state = COSMOS_SC_INIT;
    memcpy(sc->val_pub, val_pub, 32);

    fill_random(sc->loc_eph_priv, 32);
    crypto_x25519_public_key(sc->loc_eph_pub, sc->loc_eph_priv);

    // proto-encoded ephemeral: [uvarint(34), 0x0a, 0x20, <32>]
    out_eph_msg[0] = (uint8_t)EPH_OUTER_LEN;
    out_eph_msg[1] = PB_TAG_F1_BYTES;
    out_eph_msg[2] = 32;
    memcpy(out_eph_msg + 3, sc->loc_eph_pub, 32);
}

int cosmos_sc_derive_keys(cosmos_sc_t *sc,
                          const uint8_t in_eph_msg[COSMOS_SC_EPH_MSG_SIZE]) {
    if (sc->state != COSMOS_SC_INIT) {
        sc->state = COSMOS_SC_FAILED;
        return -1;
    }
    if (in_eph_msg[0] != EPH_OUTER_LEN   ||
        in_eph_msg[1] != PB_TAG_F1_BYTES ||
        in_eph_msg[2] != 32) {
        sc->state = COSMOS_SC_FAILED;
        return -1;
    }
    memcpy(sc->rem_eph_pub, in_eph_msg + 3, 32);

    if (sc_is_small_order(sc->rem_eph_pub)) {
        sc->state = COSMOS_SC_FAILED;
        return -2;
    }

    uint8_t dh_secret[32];
    crypto_x25519(dh_secret, sc->loc_eph_priv, sc->rem_eph_pub);
    crypto_wipe(sc->loc_eph_priv, sizeof(sc->loc_eph_priv));

    const uint8_t *lo, *hi;
    bool loc_is_least;
    sc_sort32(sc->loc_eph_pub, sc->rem_eph_pub, &lo, &hi, &loc_is_least);

    // AEAD keys: HKDF-SHA-256, same info string as gno path. We pass a
    // throwaway challenge buffer -- cometbft derives the channel keys from
    // dhSecret directly and the challenge separately via Merlin.
    uint8_t recv_key[32], send_key[32], throwaway[32];
    sc_derive_keys_hkdf(dh_secret, loc_is_least, recv_key, send_key, throwaway);
    crypto_wipe(throwaway, sizeof(throwaway));

    // Merlin transcript: append the sorted ephemerals + DH secret, then
    // extract the 32-byte challenge. Labels and order are verbatim from
    // cometbft/p2p/conn/secret_connection.go.
    merlin_t tr;
    merlin_init(&tr, LBL_TRANSCRIPT);
    merlin_append(&tr, LBL_EPH_LOWER, lo, 32);
    merlin_append(&tr, LBL_EPH_UPPER, hi, 32);
    merlin_append(&tr, LBL_DH_SECRET, dh_secret, 32);
    merlin_challenge(&tr, LBL_MAC, sc->challenge, COSMOS_SC_CHALLENGE_SIZE);
    crypto_wipe(&tr, sizeof(tr));
    crypto_wipe(dh_secret, sizeof(dh_secret));

    sc_init(&sc->sc, recv_key, send_key);
    crypto_wipe(recv_key, sizeof(recv_key));
    crypto_wipe(send_key, sizeof(send_key));

    sc->state = COSMOS_SC_AWAIT_SIG;
    return 0;
}

// Build the 103-byte plaintext AuthSigMessage:
//   uvarint(101)
//   0x0a, 0x22 (varint 34)
//     0x0a, 0x20, <32 pubkey>                  -- PublicKey.ed25519 oneof
//   0x12, 0x40 (varint 64), <64 sig>
static void build_auth_plain(const uint8_t pub[32], const uint8_t sig[64],
                             uint8_t out[COSMOS_SC_AUTH_MSG_SIZE]) {
    size_t pos = 0;
    out[pos++] = (uint8_t)AUTH_OUTER_LEN;        // uvarint(101)
    out[pos++] = PB_TAG_F1_BYTES;                // field 1 (pub_key)
    out[pos++] = (uint8_t)AUTH_PUBKEY_INNER_LEN; // varint(34)
    out[pos++] = PB_TAG_F1_BYTES;                // PublicKey.ed25519 (oneof tag 1)
    out[pos++] = 32;                             // varint(32)
    memcpy(out + pos, pub, 32); pos += 32;
    out[pos++] = PB_TAG_F2_BYTES;                // field 2 (sig)
    out[pos++] = 64;                             // varint(64)
    memcpy(out + pos, sig, 64); pos += 64;
    // pos should be COSMOS_SC_AUTH_MSG_SIZE = 103
}

// Parse the inverse of build_auth_plain. Strict: every prefix byte must
// match the expected wire shape (no malleability).
static int parse_auth_plain(const uint8_t in[COSMOS_SC_AUTH_MSG_SIZE],
                            uint8_t out_pub[32], uint8_t out_sig[64]) {
    if (in[0]  != AUTH_OUTER_LEN        ) return -1;
    if (in[1]  != PB_TAG_F1_BYTES       ) return -1;
    if (in[2]  != AUTH_PUBKEY_INNER_LEN ) return -1;
    if (in[3]  != PB_TAG_F1_BYTES       ) return -1;
    if (in[4]  != 32                    ) return -1;
    if (in[37] != PB_TAG_F2_BYTES       ) return -1;
    if (in[38] != 64                    ) return -1;
    memcpy(out_pub, in + 5,  32);
    memcpy(out_sig, in + 39, 64);
    return 0;
}

int cosmos_sc_seal_auth(cosmos_sc_t *sc,
                        const uint8_t sig[64],
                        uint8_t out_sealed[COSMOS_SC_AUTH_SEALED_SIZE]) {
    if (sc->state != COSMOS_SC_AWAIT_SIG) {
        sc->state = COSMOS_SC_FAILED;
        return -1;
    }

    uint8_t plain[COSMOS_SC_AUTH_MSG_SIZE];
    build_auth_plain(sc->val_pub, sig, plain);
    sc_seal_frame(&sc->sc, plain, COSMOS_SC_AUTH_MSG_SIZE, out_sealed);
    crypto_wipe(plain, sizeof(plain));

    sc->state = COSMOS_SC_AFTER_EPH;
    return 0;
}

int cosmos_sc_handle_auth(cosmos_sc_t *sc,
                          const uint8_t in_sealed[COSMOS_SC_AUTH_SEALED_SIZE]) {
    if (sc->state != COSMOS_SC_AFTER_EPH) {
        sc->state = COSMOS_SC_FAILED;
        return -2;
    }

    uint8_t plain[SC_DATA_MAX_SIZE];
    uint32_t plain_len = 0;
    int rc = sc_open_frame(&sc->sc, in_sealed, plain, &plain_len);
    if (rc != 0) {
        sc->state = COSMOS_SC_FAILED;
        return -1;
    }
    if (plain_len != COSMOS_SC_AUTH_MSG_SIZE) {
        crypto_wipe(plain, sizeof(plain));
        sc->state = COSMOS_SC_FAILED;
        return -2;
    }

    uint8_t rem_pub[32], rem_sig[64];
    if (parse_auth_plain(plain, rem_pub, rem_sig) != 0) {
        crypto_wipe(plain, sizeof(plain));
        sc->state = COSMOS_SC_FAILED;
        return -2;
    }
    crypto_wipe(plain, sizeof(plain));

    if (crypto_ed25519_check(rem_sig, rem_pub,
                             sc->challenge, COSMOS_SC_CHALLENGE_SIZE) != 0) {
        sc->state = COSMOS_SC_FAILED;
        return -3;
    }

    memcpy(sc->rem_pub, rem_pub, 32);
    crypto_wipe(sc->challenge, sizeof(sc->challenge));
    sc->state = COSMOS_SC_READY;
    return 0;
}
