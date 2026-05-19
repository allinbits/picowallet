#include <string.h>

#include "pico/rand.h"

#include "os/crypto/monocypher.h"
#include "os/crypto/monocypher-ed25519.h"   // SHA-512 Ed25519 (Tendermint-compatible)
#include "apps/gnoland/secret_connection_gno.h"

// ----- amino wire constants for the two handshake messages -----
// See [[reference_gno_handshake_wire]] in memory for derivation.
#define AMINO_TAG_F1_BYTES   0x0a   // (1 << 3) | Typ3ByteLength
#define AMINO_TAG_F2_BYTES   0x12   // (2 << 3) | Typ3ByteLength

#define EPH_SIZE_PFX   34u   // uvarint < 128 ⇒ single byte
#define AUTH_SIZE_PFX  100u  // uvarint < 128 ⇒ single byte

#if PICOWALLET_TRUSTZONE
#include "os/secure_api.h"
#endif

static void fill_random(uint8_t *out, size_t n) {
#if PICOWALLET_TRUSTZONE
    // Phase 2e: route through the Secure TRNG veneer so Phase 4 can lock
    // ACCESSCTRL_TRNG back to Secure-only without breaking the SC ephemeral.
    s_random(out, n);
#else
    // get_rand_64 is hardware-TRNG backed on RP2350.
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
#endif
}

void gno_sc_start(gno_sc_t *sc,
                  const uint8_t val_pub[32],
                  uint8_t out_eph_msg[GNO_SC_EPH_MSG_SIZE]) {
    memset(sc, 0, sizeof(*sc));
    sc->state = GNO_SC_INIT;
    memcpy(sc->val_pub, val_pub, 32);

    // Ephemeral X25519 keypair. Monocypher clamps the scalar internally per
    // RFC 7748, so raw 32 random bytes are fine as the private key.
    fill_random(sc->loc_eph_priv, 32);
    crypto_x25519_public_key(sc->loc_eph_pub, sc->loc_eph_priv);

    // amino-encoded outer: [uvarint(34), 0x0a, 0x20, <32 pubkey>]
    out_eph_msg[0] = (uint8_t)EPH_SIZE_PFX;
    out_eph_msg[1] = AMINO_TAG_F1_BYTES;
    out_eph_msg[2] = 32;                              // varint length of pubkey
    memcpy(out_eph_msg + 3, sc->loc_eph_pub, 32);
}

int gno_sc_derive_keys(gno_sc_t *sc,
                       const uint8_t in_eph_msg[GNO_SC_EPH_MSG_SIZE]) {
    if (sc->state != GNO_SC_INIT) {
        sc->state = GNO_SC_FAILED;
        return -1;
    }
    if (in_eph_msg[0] != EPH_SIZE_PFX     ||
        in_eph_msg[1] != AMINO_TAG_F1_BYTES ||
        in_eph_msg[2] != 32) {
        sc->state = GNO_SC_FAILED;
        return -1;
    }
    memcpy(sc->rem_eph_pub, in_eph_msg + 3, 32);

    if (sc_is_small_order(sc->rem_eph_pub)) {
        sc->state = GNO_SC_FAILED;
        return -2;
    }

    uint8_t dh_secret[32];
    crypto_x25519(dh_secret, sc->loc_eph_priv, sc->rem_eph_pub);
    crypto_wipe(sc->loc_eph_priv, sizeof(sc->loc_eph_priv));

    const uint8_t *lo, *hi;
    bool loc_is_least;
    sc_sort32(sc->loc_eph_pub, sc->rem_eph_pub, &lo, &hi, &loc_is_least);
    (void)lo; (void)hi;  // not used in HKDF variant (Merlin variant will use them)

    uint8_t recv_key[32], send_key[32];
    sc_derive_keys_hkdf(dh_secret, loc_is_least, recv_key, send_key, sc->challenge);
    crypto_wipe(dh_secret, sizeof(dh_secret));
    sc_init(&sc->sc, recv_key, send_key);
    crypto_wipe(recv_key, sizeof(recv_key));
    crypto_wipe(send_key, sizeof(send_key));

    sc->state = GNO_SC_AWAIT_SIG;
    return 0;
}

// Build the 101-byte plaintext authSigMessage: uvarint(100) || field1(pubkey)
// || field2(sig). All length prefixes are single-byte uvarints since
// pubkey=32 and sig=64 are both < 128.
static void build_auth_plain(const uint8_t val_pub[32],
                             const uint8_t sig[64],
                             uint8_t out[GNO_SC_AUTH_MSG_SIZE]) {
    out[0]   = (uint8_t)AUTH_SIZE_PFX;     // outer size
    out[1]   = AMINO_TAG_F1_BYTES;         // field 1: Key
    out[2]   = 32;                         // varint(32)
    memcpy(out + 3, val_pub, 32);
    out[35]  = AMINO_TAG_F2_BYTES;         // field 2: Sig
    out[36]  = 64;                         // varint(64)
    memcpy(out + 37, sig, 64);
}

// Parse the 101-byte plaintext authSigMessage. Returns 0 on success.
static int parse_auth_plain(const uint8_t in[GNO_SC_AUTH_MSG_SIZE],
                            uint8_t out_pub[32], uint8_t out_sig[64]) {
    if (in[0]   != AUTH_SIZE_PFX)      return -1;
    if (in[1]   != AMINO_TAG_F1_BYTES) return -1;
    if (in[2]   != 32)                 return -1;
    if (in[35]  != AMINO_TAG_F2_BYTES) return -1;
    if (in[36]  != 64)                 return -1;
    memcpy(out_pub, in + 3,  32);
    memcpy(out_sig, in + 37, 64);
    return 0;
}

int gno_sc_seal_auth(gno_sc_t *sc,
                     const uint8_t sig[64],
                     uint8_t out_sealed[GNO_SC_AUTH_SEALED_SIZE]) {
    if (sc->state != GNO_SC_AWAIT_SIG) {
        sc->state = GNO_SC_FAILED;
        return -1;
    }

    uint8_t plain[GNO_SC_AUTH_MSG_SIZE];
    build_auth_plain(sc->val_pub, sig, plain);
    sc_seal_frame(&sc->sc, plain, GNO_SC_AUTH_MSG_SIZE, out_sealed);
    crypto_wipe(plain, sizeof(plain));

    sc->state = GNO_SC_AFTER_EPH;
    return 0;
}

int gno_sc_handle_auth(gno_sc_t *sc,
                       const uint8_t in_sealed_auth[GNO_SC_AUTH_SEALED_SIZE]) {
    if (sc->state != GNO_SC_AFTER_EPH) {
        sc->state = GNO_SC_FAILED;
        return -2;
    }

    uint8_t plain[SC_DATA_MAX_SIZE];
    uint32_t plain_len = 0;
    int rc = sc_open_frame(&sc->sc, in_sealed_auth, plain, &plain_len);
    if (rc != 0) {
        sc->state = GNO_SC_FAILED;
        return -1;
    }
    if (plain_len != GNO_SC_AUTH_MSG_SIZE) {
        crypto_wipe(plain, sizeof(plain));
        sc->state = GNO_SC_FAILED;
        return -2;
    }

    uint8_t rem_pub[32], rem_sig[64];
    if (parse_auth_plain(plain, rem_pub, rem_sig) != 0) {
        crypto_wipe(plain, sizeof(plain));
        sc->state = GNO_SC_FAILED;
        return -2;
    }
    crypto_wipe(plain, sizeof(plain));

    if (crypto_ed25519_check(rem_sig, rem_pub, sc->challenge, 32) != 0) {
        sc->state = GNO_SC_FAILED;
        return -3;
    }

    memcpy(sc->rem_pub, rem_pub, 32);
    crypto_wipe(sc->challenge, sizeof(sc->challenge));
    sc->state = GNO_SC_READY;
    return 0;
}
