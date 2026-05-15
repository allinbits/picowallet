#pragma once
#include <stdint.h>

// Keccak-f[1600] permutation. Operates on a 200-byte (25 × 64-bit) state in
// place. Foundation for STROBE-128 (and thus Merlin transcripts), needed by
// cometbft's SecretConnection challenge derivation.
//
// Reference: FIPS 202 (SHA-3 Standard, Appendix B.2).
void keccak_f1600(uint64_t state[25]);
