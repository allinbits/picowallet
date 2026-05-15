#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Shared SecretConnection core for both gno.land and cometbft variants.
// This module handles the encrypted frame layer (identical between forks)
// and the HKDF-SHA-256 key derivation. The handshake wire serialization
// (amino vs protobuf) and the Merlin-vs-HKDF challenge derivation live in
// the per-app code that calls into this.

#define SC_KEY_SIZE              32u
#define SC_DATA_MAX_SIZE         1024u
#define SC_DATA_LEN_SIZE         4u
#define SC_FRAME_SIZE            (SC_DATA_MAX_SIZE + SC_DATA_LEN_SIZE)  // 1028
#define SC_AEAD_OVERHEAD         16u
#define SC_SEALED_FRAME_SIZE     (SC_FRAME_SIZE + SC_AEAD_OVERHEAD)     // 1044
#define SC_AEAD_NONCE_SIZE       12u

typedef struct {
    uint8_t  send_key[SC_KEY_SIZE];
    uint8_t  recv_key[SC_KEY_SIZE];
    uint64_t send_seq;   // little-endian; bytes 4..11 of the nonce
    uint64_t recv_seq;
} secret_conn_t;

// HKDF-SHA-256 derivation per Tendermint pre-Merlin variant (gno.land).
//   info = "TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN"
//   ikm  = dh_secret (32B X25519 result)
//   salt = empty
//   L    = 96 bytes
//   loc_is_least selects which 32B half is recvKey vs sendKey.
//   challenge is always the third 32B slice.
void sc_derive_keys_hkdf(const uint8_t dh_secret[SC_KEY_SIZE],
                         bool loc_is_least,
                         uint8_t out_recv_key[SC_KEY_SIZE],
                         uint8_t out_send_key[SC_KEY_SIZE],
                         uint8_t out_challenge[SC_KEY_SIZE]);

// Populate session struct from derived keys; nonces start at 0.
void sc_init(secret_conn_t *sc,
             const uint8_t recv_key[SC_KEY_SIZE],
             const uint8_t send_key[SC_KEY_SIZE]);

// Wipe session state (zeroes keys and seq counters).
void sc_wipe(secret_conn_t *sc);

// Seal one frame. chunk_len must be <= SC_DATA_MAX_SIZE. The output is
// always SC_SEALED_FRAME_SIZE bytes regardless of chunk length (frame is
// zero-padded to SC_FRAME_SIZE before encryption). Increments send_seq.
void sc_seal_frame(secret_conn_t *sc,
                   const uint8_t *chunk, uint32_t chunk_len,
                   uint8_t out_sealed[SC_SEALED_FRAME_SIZE]);

// Open one frame. Writes inner chunk bytes (length per the frame header)
// to out_chunk and the length to *out_len. Returns 0 on success.
// Returns -1 on MAC failure (out_chunk unchanged, recv_seq NOT advanced).
// Returns -2 if the embedded chunk length exceeds SC_DATA_MAX_SIZE.
// On success recv_seq is incremented exactly once.
int  sc_open_frame(secret_conn_t *sc,
                   const uint8_t sealed[SC_SEALED_FRAME_SIZE],
                   uint8_t out_chunk[SC_DATA_MAX_SIZE],
                   uint32_t *out_len);

// libsodium's low-order point blacklist (7 points). Returns 1 if rejected.
int  sc_is_small_order(const uint8_t pub[SC_KEY_SIZE]);

// Lex-compare two 32-byte arrays. Sets *lo/*hi to point into a or b,
// and *loc_is_least = true if a < b. Used to sort ephemeral pubkeys.
void sc_sort32(const uint8_t a[SC_KEY_SIZE], const uint8_t b[SC_KEY_SIZE],
               const uint8_t **lo, const uint8_t **hi, bool *loc_is_least);
