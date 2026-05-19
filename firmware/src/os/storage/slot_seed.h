#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// M9.5 Phase 7.5 -- per-chain-slot seed override.
//
// Each chain slot owns a 4 KB sector in SLOT_SEEDS_FLASH. Sectors are
// blank (all 0xFF) by default, meaning the slot uses the DERIVED source
// (master mnemonic + slot's BIP-44 path). When the operator imports a
// chain-specific mnemonic or raw priv-key, the slot's sector gets a
// header + sealed blob.
//
// Implementation lives in slot_seed.c, gated on PICOWALLET_SECURE_BUILD.

typedef enum {
    SLOT_SEED_SOURCE_DERIVED  = 0,   // no override; use master seed + path
    SLOT_SEED_SOURCE_MNEMONIC = 1,   // 64-byte BIP-39-derived seed
    SLOT_SEED_SOURCE_RAW_KEY  = 2,   // 32-byte Ed25519 priv-key seed
} slot_seed_source_t;

// Query: what's the slot currently configured as?
slot_seed_source_t m9_slot_seed_source(uint8_t slot_idx);

// Load + unseal the slot's override material. Returns the plaintext
// length on success (32 or 64), or 0 if the slot is DERIVED / no
// override / authentication failed.
// `pin` + `pin_len` must match the PIN that sealed the blob.
size_t m9_slot_seed_unseal(uint8_t slot_idx,
                           const uint8_t *pin, size_t pin_len,
                           uint8_t out[64]);

// Store a fresh override blob for the slot. `source` selects MNEMONIC
// (64 B plaintext) or RAW_KEY (32 B plaintext). Returns 0 on success.
int m9_slot_seed_store(uint8_t slot_idx,
                       slot_seed_source_t source,
                       const uint8_t *pin, size_t pin_len,
                       const uint8_t *plaintext, size_t plain_len);

// Erase the slot's sector. Slot falls back to DERIVED. Used by clear /
// import-replace flows.
void m9_slot_seed_clear(uint8_t slot_idx);

// Erase ALL slot sectors. Called by m9_factory_wipe_all.
void m9_slot_seeds_wipe_all(void);
