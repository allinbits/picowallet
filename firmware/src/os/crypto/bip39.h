#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// BIP-39 24-word mnemonic helpers (Secure-only). The PIN setup flow
// uses bip39_generate at first boot to produce a fresh mnemonic from
// TRNG entropy; bip39_to_seed converts a 24-word mnemonic to the
// 64-byte master seed via PBKDF2-HMAC-SHA512(2048 iters).
//
// Implementation in bip39.c is gated on PICOWALLET_SECURE_BUILD.

#define BIP39_MNEMONIC_WORDS    24
#define BIP39_ENTROPY_BYTES     32        // 256 bits + 8-bit checksum = 24*11
#define BIP39_SEED_BYTES        64

// Generate a fresh mnemonic from 32 bytes of TRNG entropy.
// Fills `out_word_indices[24]` with indices into bip39_wordlist.
// The caller MUST persist (display) the mnemonic so the operator can
// write it down before the entropy is wiped.
void bip39_generate(uint8_t entropy[BIP39_ENTROPY_BYTES],
                    uint16_t out_word_indices[BIP39_MNEMONIC_WORDS]);

// Build the canonical "word1 word2 ... word24" string (lowercase ASCII,
// single-space separated, no trailing NUL by default). Returns the
// number of bytes written to `out_buf` (not counting NUL). `out_buf`
// must be at least 24 * (BIP39_WORD_MAX_LEN + 1) bytes = 216 bytes.
size_t bip39_format_phrase(const uint16_t word_indices[BIP39_MNEMONIC_WORDS],
                           char *out_buf, size_t out_size);

// Convert a 24-word mnemonic to the 64-byte master seed.
// Uses PBKDF2-HMAC-SHA512 with salt = "mnemonic" + passphrase (no
// passphrase support in v1) and 2048 iterations.
void bip39_to_seed(const uint16_t word_indices[BIP39_MNEMONIC_WORDS],
                   uint8_t out_seed[BIP39_SEED_BYTES]);

// Verify the embedded 8-bit checksum on a mnemonic (the bottom 8 bits of
// the 264-bit packing must equal SHA-256(entropy)[0]). Returns true on
// match. Used by the restore flow (Phase 7.4) to reject typos.
bool bip39_check_checksum(const uint16_t word_indices[BIP39_MNEMONIC_WORDS]);
