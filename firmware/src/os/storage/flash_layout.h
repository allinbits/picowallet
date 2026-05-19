#pragma once
#include "pico/platform.h"

// Device-wide flash layout for persistent storage regions. Reserved regions
// grow from the END of QSPI flash backwards, leaving the front of flash for
// the firmware image and future growth.
//
// Layout (Pico 2: 4 MB):
//   [ firmware ][ ... unused ... ][ SLOT_SEEDS (64 KB) ][ SEED (4 KB) ][ CHAINS (4 KB) ][ HWM (1 MB) ]
//                                  ^                     ^              ^                ^           ^
//                                  SLOT_SEEDS_FLASH_OFFSET                                            PICO_FLASH_SIZE_BYTES
//
// SLOT_SEEDS holds the M9.5 Phase 7.5 per-chain-slot seed override
// blobs: 16 sectors of 4 KB, one per slot. Each slot's sector is empty
// by default (slot uses the master mnemonic + BIP-44 path) and is
// programmed when the operator imports a slot-specific mnemonic or
// raw key. See firmware/src/os/storage/slot_seed.c.
//
// SEED holds the master PIN-encrypted seed blob (Argon2id +
// XChaCha20-Poly1305 in firmware/src/os/storage/seed_flash.c).
// CHAINS holds the chain-config slot table. HWM holds the per-slot
// strict-advance high-water-mark records.

#define HWM_FLASH_SIZE         (1024u * 1024u)
#define HWM_FLASH_OFFSET       (PICO_FLASH_SIZE_BYTES - HWM_FLASH_SIZE)

#define CHAINS_FLASH_SIZE      4096u
#define CHAINS_FLASH_OFFSET    (HWM_FLASH_OFFSET - CHAINS_FLASH_SIZE)

#define SEED_FLASH_SIZE        4096u
#define SEED_FLASH_OFFSET      (CHAINS_FLASH_OFFSET - SEED_FLASH_SIZE)

#define SLOT_SEED_FLASH_SIZE   4096u                     // per-slot sector
#define SLOT_SEED_COUNT        16u                        // 8 cosmos + 8 gno
#define SLOT_SEEDS_FLASH_SIZE  (SLOT_SEED_FLASH_SIZE * SLOT_SEED_COUNT)
#define SLOT_SEEDS_FLASH_OFFSET (SEED_FLASH_OFFSET - SLOT_SEEDS_FLASH_SIZE)
#define SLOT_SEED_OFFSET(idx)  (SLOT_SEEDS_FLASH_OFFSET + (idx) * SLOT_SEED_FLASH_SIZE)
