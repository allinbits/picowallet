#pragma once
#include <stddef.h>
#include <stdint.h>

// Secure-side TRNG helpers. The RP2350 TRNG at 0x400F0000 is locked to
// Secure-only by ACCESSCTRL_TRNG (Phase 4). These helpers feed the
// s_random veneer (entropy to NS) and the seal/unseal flow (salt + nonce
// generation during PIN setup). Compiled into picowallet_secure only.

// Read one 32-bit TRNG word, refilling the internal 6-word cache as needed.
uint32_t m9_trng_word(void);

// Fill `n` bytes with TRNG output.
void m9_trng_fill(uint8_t *out, size_t n);
