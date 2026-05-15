#pragma once
#include <stddef.h>
#include <stdint.h>

#include "os/crypto/strobe.h"

// Merlin proof transcripts. Wraps STROBE-128 with labeled append/extract
// operations. Used by cometbft's SecretConnection for the malleability-fix
// challenge derivation.
//
// Reference: merlin.sh (Henry de Valence, George Tankersley). Behaviour
// matches oasisprotocol/curve25519-voi @ primitives/merlin which cometbft
// links against (verified by the canonical test vector in test_merlin.c:
//   NewTranscript("test protocol")
//     .AppendMessage("some label", "some data")
//     .ExtractBytes("challenge", 32)
//     == d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615).

typedef struct {
    strobe_t s;
} merlin_t;

// Initialize a new transcript with the given application label.
void merlin_init(merlin_t *t, const char *app_label);

// Append message bytes under a label.
// Spec: meta_ad(label) || meta_ad(LE32(len(msg))) || ad(msg)
void merlin_append(merlin_t *t, const char *label,
                   const uint8_t *msg, size_t msg_len);

// Extract `dest_len` challenge bytes under a label.
// Spec: meta_ad(label) || meta_ad(LE32(len(dest))) || prf(dest)
void merlin_challenge(merlin_t *t, const char *label,
                      uint8_t *dest, size_t dest_len);
