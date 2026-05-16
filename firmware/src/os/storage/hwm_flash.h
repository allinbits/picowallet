#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Per-chain HWM (height/round/type) persisted across power cycles, used to
// block double-signing. Indexed by a HWM slot in the range 0..HWM_TOTAL_SLOTS-1.
// The slot mapping comes from chains.h (chains_hwm_slot_idx) so each chain
// config slot owns exactly one HWM slot.
//
// Storage model: per-slot dedicated regions. Each slot owns
// HWM_SECTORS_PER_SLOT contiguous 4 KB sectors at the tail of QSPI flash,
// arranged as a rolling log. Records within a slot's region are 64 B (4
// per flash page via sub-page programming), 64 records per sector. Sectors
// within a slot are rotated round-robin and erased on reuse.
//
// Because each slot's region is private, there is NO compaction across
// chains -- a slot's "current state" is simply the highest-seq record in
// its region. No write amplification beyond the natural records-per-erase
// ratio.
//
// Endurance at 100K erase-cycles/sector (NOR spec minimum):
//   per chain: 100K * 16 sectors * 64 records = 102M signs lifetime
//   at 0.35 signs/sec/chain: ~9.3 years per chain, regardless of how many
//   other chains are configured (wear is isolated per slot).
// Real-world flash typically does 2-5x the spec, so 20-45 years in practice.

#define HWM_TOTAL_SLOTS        16u   // 8 cosmos + 8 gno (matches chain config)

typedef struct {
    int64_t  height;
    int32_t  round;
    int32_t  type;
} hwm_state_t;

// Load all valid persisted records into the in-memory per-slot state.
// Call once on boot before any signing app starts.
void hwm_init(void);

// Look up the current HWM for `slot_idx`. Returns {0, 0, 0} for an
// out-of-range index or a slot that has never signed.
hwm_state_t hwm_current(uint8_t slot_idx);

// Check whether (type, height, round) strictly advances slot `slot_idx`'s
// HWM. On accept: persist a new record AND update the in-memory state
// before returning true. On reject (or any error): leave all state
// unchanged and return false.
//
// The chain_id text is used both as a sanity-check field embedded in the
// flash record (hashed, 8 bytes on disk) and to identify the chain in
// log messages. The slot is the source of truth -- two callers with the
// same slot_idx but different chain_ids would be a bug at the call site.
//
// Per-chain ordering: (height, round, type) lexicographic strict-increase.
// Returns false if slot_idx is out of range.
bool hwm_advance(uint8_t slot_idx,
                 const char *chain_id, size_t chain_id_len,
                 int32_t type, int64_t height, int32_t round);

// Erase one slot's region (16 sectors). Used when an operator reassigns a
// chain config slot to a new chain_id, so the new chain starts fresh and
// cannot inherit a higher-height block from a different chain.
void hwm_wipe_slot(uint8_t slot_idx);

// Erase the entire HWM region. Used for factory reset / fresh testnets.
void hwm_flash_wipe(void);
