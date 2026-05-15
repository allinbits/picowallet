#pragma once
#include <stddef.h>
#include <stdint.h>

// STROBE-128 framework over Keccak-f[1600]. Just enough operations to back
// Merlin proof transcripts (what cometbft's SecretConnection challenge
// derivation uses). The crypto operations (SEND_/RECV_/MAC) and the KEY
// rekeying primitive are deliberately omitted -- Merlin doesn't use them.
//
// Reference: STROBE Protocol Framework v1.0.2 (Hamburg 2017). Implementation
// translated from oasisprotocol/curve25519-voi @ v0.0.0-20230904 (BSD-3).

#define STROBE_KECCAK_STATE_BYTES 200u   // 1600 bits, the Keccak state

typedef struct {
    // Keccak state, also accessed byte-wise. uint64_t alignment lets us
    // hand `state` directly to keccak_f1600 without an alias dance.
    uint64_t state[25];
    uint16_t pos;            // current byte offset within rate region
    uint16_t pos_begin;      // pos at start of current operation
    uint16_t r;              // effective rate in bytes (166 post-init)
    uint8_t  cur_flags;      // flags of the currently-running operation
    uint8_t  initialized;
} strobe_t;

// Initialize with a protocol label (NUL-terminated; only the bytes before
// the NUL are absorbed). For Merlin, this is always "Merlin v1.0".
void strobe_init(strobe_t *s, const char *proto);

// AD = "absorb associated data".
void strobe_ad(strobe_t *s, const uint8_t *data, size_t len, int more);

// META_AD = same as AD but tags the data as metadata (framing labels).
void strobe_meta_ad(strobe_t *s, const uint8_t *data, size_t len, int more);

// PRF = "extract pseudo-random output". Writes `len` bytes into `dest`.
void strobe_prf(strobe_t *s, uint8_t *dest, size_t len);
