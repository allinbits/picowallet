#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/transport/secret_connection.h"

// CometBFT variant of the SecretConnection handshake.
//
// Differs from the gno.land variant in three ways:
//
//   1. Challenge derivation uses a Merlin transcript ("STROBE-128 over
//      Keccak-f1600") rather than pure HKDF-SHA-256. AEAD keys are still
//      HKDF-SHA-256 -- the Merlin path is only the "MAC challenge"
//      malleability fix that landed in cometbft.
//
//   2. Handshake wire is protobuf-delimited:
//      - ephemeral exchange: `gogotypes.BytesValue{Value: ephPub}` (35 B)
//        -- identical bytes to gno's amino-encoded version, coincidentally
//      - auth-sig: `tmp2p.AuthSigMessage{PubKey: crypto.PublicKey{Ed25519:
//        bytes}, Sig: bytes}` (103 B) -- pubkey wrapped in PublicKey
//        oneof, unlike gno's bare bytes
//
//   3. AEAD frame layer + HKDF AEAD-key derivation come from the shared
//      `secret_connection.{h,c}` module, identical to gno.
//
// After the handshake the embedded `secret_conn_t` is what's used for
// per-frame seal/open via the shared `sc_seal_frame` / `sc_open_frame`.

#define COSMOS_SC_EPH_MSG_SIZE         35u
#define COSMOS_SC_AUTH_MSG_SIZE       103u    // proto-encoded auth on wire
#define COSMOS_SC_AUTH_SEALED_SIZE    SC_SEALED_FRAME_SIZE   // 1044
#define COSMOS_SC_CHALLENGE_SIZE       32u

typedef enum {
    COSMOS_SC_INIT       = 0,  // just constructed; awaiting peer's ephemeral
    COSMOS_SC_AWAIT_SIG  = 1,  // keys derived, challenge ready, awaiting sig
    COSMOS_SC_AFTER_EPH  = 2,  // auth-sig sealed and emitted; awaiting peer's
    COSMOS_SC_READY      = 3,  // peer authenticated; channel live
    COSMOS_SC_FAILED     = 4,
} cosmos_sc_state_t;

typedef struct {
    cosmos_sc_state_t state;
    secret_conn_t     sc;       // valid from AFTER_EPH onwards

    uint8_t val_pub[32];

    uint8_t loc_eph_priv[32];
    uint8_t loc_eph_pub [32];
    uint8_t rem_eph_pub [32];

    uint8_t challenge[COSMOS_SC_CHALLENGE_SIZE];
    uint8_t rem_pub  [32];
} cosmos_sc_t;

// Generate ephemeral X25519 keypair and emit the 35-byte proto-encoded
// ephemeral exchange message.
void cosmos_sc_start(cosmos_sc_t *sc,
                     const uint8_t val_pub[32],
                     uint8_t out_eph_msg[COSMOS_SC_EPH_MSG_SIZE]);

// Process peer's 35-byte ephemeral message. Performs small-order check,
// X25519 DH, HKDF AEAD-key derivation, AND Merlin-based challenge
// derivation. After success, `sc->challenge` is ready for the OS to sign.
// State -> AWAIT_SIG. Returns -1 framing, -2 small-order point.
int cosmos_sc_derive_keys(cosmos_sc_t *sc,
                          const uint8_t in_eph_msg[COSMOS_SC_EPH_MSG_SIZE]);

// Seal the auth-sig (PubKey-wrapped-in-PublicKey + 64-byte sig) into a
// 1044-byte AEAD frame. State -> AFTER_EPH.
int cosmos_sc_seal_auth(cosmos_sc_t *sc,
                        const uint8_t sig[64],
                        uint8_t out_sealed[COSMOS_SC_AUTH_SEALED_SIZE]);

// Process peer's 1044-byte sealed auth-sig. Decrypts, parses, verifies the
// Ed25519 signature against the Merlin-derived challenge. State -> READY.
// -1 MAC, -2 parse, -3 sig verify.
int cosmos_sc_handle_auth(cosmos_sc_t *sc,
                          const uint8_t in_sealed[COSMOS_SC_AUTH_SEALED_SIZE]);
