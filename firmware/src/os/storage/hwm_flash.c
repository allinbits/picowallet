#include <string.h>
#include <stddef.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/storage/hwm_flash.h"
#include "os/storage/flash_layout.h"

// ---- Per-slot rolling-log HWM storage ----
//
// HWM region (1 MB) is partitioned into HWM_TOTAL_SLOTS=16 contiguous
// regions of HWM_SECTORS_PER_SLOT=16 sectors each. Slot i owns sectors
// [i*16, i*16+15]. Each chain config slot maps 1:1 to a HWM slot via
// chains_hwm_slot_idx().
//
// Records are 64 B; flash pages (256 B) hold 4 records via sub-page
// programming. Programming 0xFF over an already-programmed byte is a
// no-op on NOR flash (1->0 only), so writing record N of a page leaves
// records 0..N-1 intact. Sectors hold 64 records each.
//
// Within a slot, sectors are used in rolling-log fashion: write into the
// current sector until it fills, then advance to the next sector, erase
// it, and write at record 0. Old sectors get naturally erased on reuse.
//
// On boot, each slot is scanned independently: the highest-seq valid
// record in the slot's region is the current state, and cur_sector /
// next_rec are derived from that record's position. Per-slot seq numbers
// are independent (a slot's seq starts at 1 on its first ever sign).
//
// Power-loss safety: a record's magic + cksum guard against partial
// writes. A partially-erased "next" sector cannot mask the previous
// sector's records (the partial sector has lower seq values, if any
// valid records remain at all). Before each write we also check the
// destination 64 B is all 0xFF (fully erased); if not, we advance the
// sector (re-erase if needed) so we never AND fresh record bytes into
// stale data.

#define HWM_PAGE_SIZE         FLASH_PAGE_SIZE     // 256: flash program-page
#define HWM_RECS_PER_PAGE     4u
#define HWM_REC_SIZE          (HWM_PAGE_SIZE / HWM_RECS_PER_PAGE)   // 64
#define HWM_SECTOR_SIZE       FLASH_SECTOR_SIZE   // 4096
#define HWM_RECS_PER_SECTOR   (HWM_SECTOR_SIZE / HWM_REC_SIZE)      // 64
#define HWM_NUM_SECTORS       (HWM_FLASH_SIZE / HWM_SECTOR_SIZE)    // 256
#define HWM_SECTORS_PER_SLOT  (HWM_NUM_SECTORS / HWM_TOTAL_SLOTS)   // 16

#define HWM_MAGIC             0xA1A2A3C0u   // bumped from v1's 0xA1A2A3A5

// FNV-1a 64-bit hash of the chain_id text. Embedded in each record for a
// cheap sanity check that the slot's region wasn't reassigned without a
// wipe (which should never happen given chains_add wipes on assignment).
// Collision probability with 16 chains: <2^-58.
static uint64_t chain_id_hash(const char *chain_id, size_t len) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)chain_id[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

typedef struct {
    uint32_t magic;
    uint32_t reserved0;
    uint64_t seq;             // monotonic within slot
    uint64_t chain_id_hash;   // sanity-check vs slot owner
    int64_t  height;
    int32_t  round;
    int32_t  type;
    uint32_t cksum;           // FNV-1a 32 over preceding fields
    uint32_t reserved1[5];    // pad to 64
} hwm_rec_t;

_Static_assert(sizeof(hwm_rec_t) == HWM_REC_SIZE,
               "hwm_rec_t must be exactly HWM_REC_SIZE bytes");
_Static_assert(HWM_FLASH_SIZE == HWM_NUM_SECTORS * HWM_SECTOR_SIZE,
               "HWM_FLASH_SIZE must be sector-aligned");
_Static_assert(HWM_NUM_SECTORS == HWM_TOTAL_SLOTS * HWM_SECTORS_PER_SLOT,
               "sector count must divide evenly across slots");

typedef struct {
    bool         valid;          // any state on flash for this slot?
    uint64_t     chain_id_hash;  // 0 until first write/scan match
    uint32_t     cur_sector;     // 0..HWM_SECTORS_PER_SLOT-1 (relative to slot)
    uint32_t     next_rec;       // 0..HWM_RECS_PER_SECTOR (== full means advance)
    uint64_t     next_seq;       // monotonic per slot
    hwm_state_t  state;
} hwm_slot_state_t;

static hwm_slot_state_t s_slots[HWM_TOTAL_SLOTS];

// ---- low-level addressing -----------------------------------------------

static uint32_t abs_sector(uint8_t slot_idx, uint32_t rel_sector) {
    return (uint32_t)slot_idx * HWM_SECTORS_PER_SLOT + rel_sector;
}

static uint32_t sector_offset(uint32_t sector) {
    return HWM_FLASH_OFFSET + sector * HWM_SECTOR_SIZE;
}

static const hwm_rec_t *rec_ptr(uint32_t sector, uint32_t rec) {
    return (const hwm_rec_t *)(XIP_BASE + sector_offset(sector)
                               + rec * HWM_REC_SIZE);
}

static uint32_t page_offset_for_rec(uint32_t sector, uint32_t rec) {
    return sector_offset(sector) + (rec / HWM_RECS_PER_PAGE) * HWM_PAGE_SIZE;
}

static uint32_t cksum_of(const hwm_rec_t *r) {
    const uint8_t *b = (const uint8_t *)r;
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < offsetof(hwm_rec_t, cksum); i++) {
        h ^= b[i];
        h *= 0x01000193u;
    }
    return h;
}

static bool is_rec_erased(uint32_t sector, uint32_t rec) {
    const uint8_t *p = (const uint8_t *)rec_ptr(sector, rec);
    for (size_t i = 0; i < HWM_REC_SIZE; i++) {
        if (p[i] != 0xFFu) return false;
    }
    return true;
}

// ---- write path ---------------------------------------------------------

// Program a single 64 B record into (sector, rec). Builds the full 256 B
// flash page with the record placed in the correct quarter, 0xFF elsewhere.
// Sub-page programming relies on NOR's 1->0 semantics: writing 0xFF over an
// already-programmed byte changes nothing.
static void write_record(uint32_t sector, uint32_t rec,
                         uint64_t seq, uint64_t hash,
                         const hwm_state_t *s) {
    uint8_t page[HWM_PAGE_SIZE];
    memset(page, 0xFF, sizeof(page));
    uint32_t rec_in_page = rec % HWM_RECS_PER_PAGE;
    hwm_rec_t *r = (hwm_rec_t *)(page + rec_in_page * HWM_REC_SIZE);
    r->magic         = HWM_MAGIC;
    r->reserved0     = 0;
    r->seq           = seq;
    r->chain_id_hash = hash;
    r->height        = s->height;
    r->round         = s->round;
    r->type          = s->type;
    memset(r->reserved1, 0, sizeof(r->reserved1));
    r->cksum         = cksum_of(r);
    flash_range_program(page_offset_for_rec(sector, rec), page, HWM_PAGE_SIZE);
}

static void erase_sector(uint32_t sector) {
    flash_range_erase(sector_offset(sector), HWM_SECTOR_SIZE);
}

static void erase_slot_region(uint8_t slot_idx) {
    flash_range_erase(sector_offset(abs_sector(slot_idx, 0)),
                      HWM_SECTORS_PER_SLOT * HWM_SECTOR_SIZE);
}

// ---- boot scan ----------------------------------------------------------

static void scan_slot(uint8_t slot_idx, hwm_slot_state_t *s) {
    s->valid         = false;
    s->chain_id_hash = 0;
    s->cur_sector    = 0;
    s->next_rec      = 0;
    s->next_seq      = 1;
    s->state         = (hwm_state_t){ 0, 0, 0 };

    uint64_t max_seq = 0;
    int      max_sect = -1;   // relative sector index
    int      max_rec  = -1;
    uint64_t max_hash = 0;
    hwm_state_t max_state = { 0, 0, 0 };

    for (uint32_t rs = 0; rs < HWM_SECTORS_PER_SLOT; rs++) {
        uint32_t as = abs_sector(slot_idx, rs);
        for (uint32_t k = 0; k < HWM_RECS_PER_SECTOR; k++) {
            const hwm_rec_t *r = rec_ptr(as, k);
            if (r->magic != HWM_MAGIC)         continue;
            if (r->cksum != cksum_of(r))       continue;
            if (r->seq <= max_seq)             continue;
            max_seq   = r->seq;
            max_sect  = (int)rs;
            max_rec   = (int)k;
            max_hash  = r->chain_id_hash;
            max_state.height = r->height;
            max_state.round  = r->round;
            max_state.type   = r->type;
        }
    }

    if (max_sect < 0) return;   // no valid records: fresh slot

    s->valid         = true;
    s->chain_id_hash = max_hash;
    s->cur_sector    = (uint32_t)max_sect;
    s->next_rec      = (uint32_t)max_rec + 1;
    s->next_seq      = max_seq + 1;
    s->state         = max_state;
    // next_rec may equal HWM_RECS_PER_SECTOR (sector logically full).
    // We defer the actual advance to the next write.
}

void hwm_init(void) {
    memset(s_slots, 0, sizeof(s_slots));
    for (uint8_t i = 0; i < HWM_TOTAL_SLOTS; i++) {
        scan_slot(i, &s_slots[i]);
    }
}

// ---- public API ---------------------------------------------------------

hwm_state_t hwm_current(uint8_t slot_idx) {
    if (slot_idx >= HWM_TOTAL_SLOTS) return (hwm_state_t){ 0, 0, 0 };
    return s_slots[slot_idx].state;
}

// Map the raw cometbft/gno SignedMsgType to BFT step ordering. Within
// a single (height, round) the consensus protocol signs in this order:
// propose, then prevote, then precommit. The raw type values (Proposal
// = 0x20, Prevote = 0x01, Precommit = 0x02) are NOT monotonic in that
// order, so we must translate before checking strict-increase or every
// (Proposal -> Prevote) transition would be rejected as a double-sign.
static int type_to_step(int32_t t) {
    switch (t) {
        case 0x20: return 1;   // Proposal
        case 0x01: return 2;   // Prevote
        case 0x02: return 3;   // Precommit
        default:   return 0;   // unknown / no prior signing
    }
}

bool hwm_advance(uint8_t slot_idx,
                 const char *chain_id, size_t chain_id_len,
                 int32_t type, int64_t height, int32_t round) {
    if (slot_idx >= HWM_TOTAL_SLOTS) return false;
    int new_step = type_to_step(type);
    if (new_step == 0) return false;

    hwm_slot_state_t *s = &s_slots[slot_idx];

    // Strict-advance check against current in-RAM state.
    if (s->valid) {
        if (height < s->state.height)              return false;
        if (height == s->state.height) {
            if (round < s->state.round)            return false;
            if (round == s->state.round) {
                if (new_step <= type_to_step(s->state.type)) return false;
            }
        }
    }

    hwm_state_t new_state = { .height = height, .round = round, .type = type };
    uint64_t    hash       = chain_id_hash(chain_id, chain_id_len);

    uint32_t ints = save_and_disable_interrupts();

    // Sector advance if we've filled the current one.
    if (s->next_rec >= HWM_RECS_PER_SECTOR) {
        s->cur_sector = (s->cur_sector + 1) % HWM_SECTORS_PER_SLOT;
        erase_sector(abs_sector(slot_idx, s->cur_sector));
        s->next_rec = 0;
    }

    // Defensive: destination must be fully erased before we sub-page
    // program. If a prior crash left partial bytes there, advance to
    // the next sector. (Erasing an already-erased sector is harmless.)
    if (!is_rec_erased(abs_sector(slot_idx, s->cur_sector), s->next_rec)) {
        s->cur_sector = (s->cur_sector + 1) % HWM_SECTORS_PER_SLOT;
        erase_sector(abs_sector(slot_idx, s->cur_sector));
        s->next_rec = 0;
    }

    write_record(abs_sector(slot_idx, s->cur_sector), s->next_rec,
                 s->next_seq, hash, &new_state);

    s->next_seq++;
    s->next_rec++;
    s->state         = new_state;
    s->chain_id_hash = hash;
    s->valid         = true;

    restore_interrupts(ints);
    return true;
}

void hwm_wipe_slot(uint8_t slot_idx) {
    if (slot_idx >= HWM_TOTAL_SLOTS) return;
    uint32_t ints = save_and_disable_interrupts();
    erase_slot_region(slot_idx);
    restore_interrupts(ints);
    memset(&s_slots[slot_idx], 0, sizeof(s_slots[slot_idx]));
    s_slots[slot_idx].next_seq = 1;
}

void hwm_flash_wipe(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(HWM_FLASH_OFFSET, HWM_FLASH_SIZE);
    restore_interrupts(ints);
    memset(s_slots, 0, sizeof(s_slots));
    for (uint8_t i = 0; i < HWM_TOTAL_SLOTS; i++) {
        s_slots[i].next_seq = 1;
    }
}
