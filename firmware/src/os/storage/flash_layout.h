#pragma once
#include "pico/platform.h"

// Device-wide flash layout for persistent storage regions. Reserved regions
// grow from the END of QSPI flash backwards, leaving the front of flash for
// the firmware image and future growth.
//
// Layout (Pico 2: 4 MB):
//   [ firmware ][ ... unused ... ][ SEED (4 KB) ][ CHAINS (4 KB) ][ HWM (1 MB) ]
//                                  ^              ^                ^           ^
//                                  SEED_FLASH_OFFSET                            PICO_FLASH_SIZE_BYTES
//
// SEED holds the M9.5 PIN-encrypted master seed blob (sealed via
// Argon2id + XChaCha20-Poly1305 in firmware/src/os/storage/seed_flash.c).
// CHAINS holds the chain-config slot table. HWM holds the per-slot
// strict-advance high-water-mark records.

#define HWM_FLASH_SIZE        (1024u * 1024u)
#define HWM_FLASH_OFFSET      (PICO_FLASH_SIZE_BYTES - HWM_FLASH_SIZE)

#define CHAINS_FLASH_SIZE     4096u
#define CHAINS_FLASH_OFFSET   (HWM_FLASH_OFFSET - CHAINS_FLASH_SIZE)

#define SEED_FLASH_SIZE       4096u
#define SEED_FLASH_OFFSET     (CHAINS_FLASH_OFFSET - SEED_FLASH_SIZE)
