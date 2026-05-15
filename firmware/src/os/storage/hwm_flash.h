#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Per-(key, chain) HWM persisted across power cycles.
//
// One validator key can sign for multiple chains (cosmoshub-4, osmosis-1,
// gno.land/r/test1, ...) and each chain's consensus state is independent --
// signing height H on chain A does NOT preclude height H on chain B. So we
// key the HWM by chain_id, not just by validator key.
//
// Storage: 16-record ring buffer in the last 4 KB sector of QSPI flash.
// Each record carries the chain_id plus (height, round, type). On boot we
// scan all records and keep the highest-seq entry per chain_id. Save appends
// to the next slot; when wrapping to slot 0 we first compact (one record
// per live chain) into the freshly-erased sector so no chain's state is lost.

#define HWM_MAX_CHAINS         8u
#define HWM_CHAIN_ID_MAX       64u

typedef struct {
    int64_t  height;
    int32_t  round;
    int32_t  type;
} hwm_state_t;

// Load all valid persisted records into the in-memory cache. Call once on
// boot before any signing app starts.
void hwm_init(void);

// Look up the current HWM for `chain_id`. Returns {0, 0, 0} if this chain
// hasn't been seen before (caller can sign any positive height).
hwm_state_t hwm_current(const char *chain_id, size_t chain_id_len);

// Check whether (type, height, round) strictly advances `chain_id`'s HWM.
// On accept: persist a new record AND update the in-memory cache before
// returning true. On reject: leave all state unchanged and return false.
//
// Per-chain ordering: (height, round, type) lexicographic strict-increase.
// Returns false if the chain_id is too long or the chain table is full.
bool hwm_advance(const char *chain_id, size_t chain_id_len,
                 int32_t type, int64_t height, int32_t round);

// Erase all HWM storage. Use for factory reset. Drops the in-memory cache.
void hwm_flash_wipe(void);
