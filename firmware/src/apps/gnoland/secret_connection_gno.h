#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/transport/secret_connection.h"

// Gno.land variant of the SecretConnection handshake. Amino-encoded wire,
// HKDF-SHA-256-derived challenge (no Merlin). Drives the cryptographic side
// only — TCP plumbing is the caller's responsibility. After GNO_SC_READY,
// use sc_seal_frame / sc_open_frame on the embedded `secret_conn_t`.
//
// Signing is delegated to the OS keystore: the caller fetches the challenge
// from the handshake, hands it to os_crypto_sign, then passes the signature
// back via gno_sc_seal_auth. Raw private keys never live in gno_sc_t.

// Exact wire sizes (see [[reference_gno_handshake_wire]] in memory).
#define GNO_SC_EPH_MSG_SIZE         35u
#define GNO_SC_AUTH_MSG_SIZE       101u   // plaintext authSigMessage on wire
#define GNO_SC_AUTH_SEALED_SIZE    SC_SEALED_FRAME_SIZE  // 1044, full frame
#define GNO_SC_CHALLENGE_SIZE       32u

typedef enum {
    GNO_SC_INIT          = 0,  // just constructed; awaiting peer's ephemeral
    GNO_SC_AWAIT_SIG     = 1,  // keys derived, challenge ready, awaiting sig
    GNO_SC_AFTER_EPH     = 2,  // auth-sig sealed and emitted; awaiting peer's
    GNO_SC_READY         = 3,  // peer authenticated; channel live
    GNO_SC_FAILED        = 4,
} gno_sc_state_t;

typedef struct {
    gno_sc_state_t state;
    secret_conn_t  sc;       // valid from AFTER_EPH onwards

    // Our long-term ed25519 pubkey (32B). Private side stays in the OS.
    uint8_t val_pub[32];

    // Ephemeral state. loc_eph_priv is wiped after DH.
    uint8_t loc_eph_priv[32];
    uint8_t loc_eph_pub [32];
    uint8_t rem_eph_pub [32];

    // Challenge derived by HKDF; wiped after auth-sig sealed.
    uint8_t challenge[GNO_SC_CHALLENGE_SIZE];

    // Peer's authenticated long-term ed25519 pubkey (populated in READY).
    uint8_t rem_pub[32];
} gno_sc_t;

// Initialize the handshake. Generates an ephemeral X25519 keypair and writes
// the 35-byte amino-encoded ephemeral exchange message into `out_eph_msg`.
// State transitions INIT.
void gno_sc_start(gno_sc_t *sc,
                  const uint8_t val_pub[32],
                  uint8_t out_eph_msg[GNO_SC_EPH_MSG_SIZE]);

// Process a received 35-byte ephemeral exchange message. Small-order check,
// X25519 DH, HKDF key derivation, sc_init. After this returns 0, the
// challenge is available via `sc->challenge` for the caller to sign with
// the OS keystore (os_crypto_sign over OS_CURVE_ED25519). State -> AWAIT_SIG.
// Returns -1 on bad framing, -2 on small-order point. State -> FAILED on err.
int gno_sc_derive_keys(gno_sc_t *sc,
                       const uint8_t in_eph_msg[GNO_SC_EPH_MSG_SIZE]);

// Build and seal the authSigMessage using the signature the caller obtained
// from the keystore over `sc->challenge`. Writes 1044 bytes to out_sealed.
// State transitions AWAIT_SIG -> AFTER_EPH. Returns 0; -1 if wrong state.
int gno_sc_seal_auth(gno_sc_t *sc,
                     const uint8_t sig[64],
                     uint8_t out_sealed[GNO_SC_AUTH_SEALED_SIZE]);

// Process a received 1044-byte sealed auth-sig frame. Decrypts, parses,
// verifies peer's signature over the challenge. State -> READY on success.
// Returns 0 on success; -1 MAC failure; -2 framing/parse error; -3 sig fail.
int gno_sc_handle_auth(gno_sc_t *sc,
                       const uint8_t in_sealed_auth[GNO_SC_AUTH_SEALED_SIZE]);
