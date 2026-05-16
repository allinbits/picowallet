#pragma once
#include "pico/platform.h"

// Device-wide flash layout for persistent storage regions. Reserved regions
// grow from the END of QSPI flash backwards, leaving the front of flash for
// the firmware image and future growth.
//
// Layout (Pico 2: 4 MB):
//   [ firmware ][ ... unused ... ][ CHAINS (4 KB) ][ HWM (1 MB) ]
//                                  ^                ^           ^
//                                  CHAINS_FLASH_OFFSET           PICO_FLASH_SIZE_BYTES

#define HWM_FLASH_SIZE        (1024u * 1024u)
#define HWM_FLASH_OFFSET      (PICO_FLASH_SIZE_BYTES - HWM_FLASH_SIZE)

#define CHAINS_FLASH_SIZE     4096u
#define CHAINS_FLASH_OFFSET   (HWM_FLASH_OFFSET - CHAINS_FLASH_SIZE)
