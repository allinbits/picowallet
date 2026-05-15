#include <string.h>
#include <stddef.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/storage/hwm_flash.h"
#include "os/storage/flash_layout.h"

// ---- Multi-sector rolling-log HWM storage ----
//
// 256 sectors x 16 records-per-sector, at the tail of QSPI flash.
// Each sign appends a record at the current sector's next slot. When a
// sector fills, we advance to the next sector (mod N), erase it, and write
// one compaction record per live chain there. Old data lingers in previous
// sectors until naturally erased by sector reuse, giving power-loss safety:
// at any moment the previous sector's records remain valid (with lower seq)
// and boot-scan picks the sector with the global max seq.
//
// No explicit "current sector pointer" is persisted -- boot-scan derives it
// from the highest-seq record across all sectors. This avoids a separate
// bootstrap area that would itself need wear leveling.
//
// Endurance at 100K erase-cycles/sector (NOR spec minimum):
//   1 chain (15 useful appends per erase): ~384M signs ≈ 35y at 0.35 signs/s
//   8 chains (8 useful per erase, 8 compaction): ~205M signs ≈ 2.3y total
// Real-world flash typically does 2-5x the spec, so add a comfort margin.

#define HWM_REC_SIZE             256u
#define HWM_RECS_PER_SECTOR      16u
#define HWM_SECTOR_SIZE          (HWM_REC_SIZE * HWM_RECS_PER_SECTOR)   // 4096
#define HWM_NUM_SECTORS          (HWM_FLASH_SIZE / HWM_SECTOR_SIZE)
#define HWM_MAGIC                0xA1A2A3A5u

_Static_assert(HWM_FLASH_SIZE == HWM_NUM_SECTORS * HWM_SECTOR_SIZE,
               "HWM_FLASH_SIZE must be sector-aligned");

typedef struct {
    uint32_t magic;
    uint64_t seq;          // monotonic across the device's lifetime
    uint8_t  chain_id_len;
    uint8_t  pad0[3];
    char     chain_id[HWM_CHAIN_ID_MAX];
    int64_t  height;
    int32_t  round;
    int32_t  type;
    uint32_t cksum;        // FNV-1a over preceding fields
} hwm_rec_t;

_Static_assert(sizeof(hwm_rec_t) <= HWM_REC_SIZE,
               "hwm_rec_t must fit in one flash page");

typedef struct {
    bool        in_use;
    uint8_t     chain_id_len;
    char        chain_id[HWM_CHAIN_ID_MAX];
    hwm_state_t state;
} hwm_cache_t;

static hwm_cache_t s_cache[HWM_MAX_CHAINS];
static uint32_t    s_cur_sector = 0;       // active sector (0..NUM_SECTORS-1)
static uint32_t    s_next_slot  = 0;       // next slot to write in s_cur_sector
static uint64_t    s_next_seq   = 1;

static uint32_t sector_offset(uint32_t sector) {
    return HWM_FLASH_OFFSET + sector * HWM_SECTOR_SIZE;
}

static const hwm_rec_t *slot_ptr(uint32_t sector, uint32_t slot) {
    return (const hwm_rec_t *)(XIP_BASE + sector_offset(sector)
                               + slot * HWM_REC_SIZE);
}

static uint32_t slot_offset(uint32_t sector, uint32_t slot) {
    return sector_offset(sector) + slot * HWM_REC_SIZE;
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

static hwm_cache_t *cache_find(const char *chain_id, size_t chain_id_len) {
    for (size_t i = 0; i < HWM_MAX_CHAINS; i++) {
        hwm_cache_t *c = &s_cache[i];
        if (!c->in_use) continue;
        if (c->chain_id_len != (uint8_t)chain_id_len) continue;
        if (memcmp(c->chain_id, chain_id, chain_id_len) == 0) return c;
    }
    return NULL;
}

static hwm_cache_t *cache_get_or_alloc(const char *chain_id, size_t chain_id_len) {
    hwm_cache_t *c = cache_find(chain_id, chain_id_len);
    if (c) return c;
    for (size_t i = 0; i < HWM_MAX_CHAINS; i++) {
        if (!s_cache[i].in_use) {
            c = &s_cache[i];
            c->in_use       = true;
            c->chain_id_len = (uint8_t)chain_id_len;
            memcpy(c->chain_id, chain_id, chain_id_len);
            c->state.height = 0;
            c->state.round  = 0;
            c->state.type   = 0;
            return c;
        }
    }
    return NULL;
}

void hwm_init(void) {
    memset(s_cache, 0, sizeof(s_cache));

    uint64_t max_seq = 0;
    int      max_sector = -1;
    int      max_slot   = -1;
    uint64_t per_chain_best_seq[HWM_MAX_CHAINS] = {0};

    for (uint32_t s = 0; s < HWM_NUM_SECTORS; s++) {
        for (uint32_t k = 0; k < HWM_RECS_PER_SECTOR; k++) {
            const hwm_rec_t *r = slot_ptr(s, k);
            if (r->magic != HWM_MAGIC)                continue;
            if (r->chain_id_len == 0
                || r->chain_id_len > HWM_CHAIN_ID_MAX) continue;
            if (r->cksum != cksum_of(r))              continue;

            hwm_cache_t *c = cache_get_or_alloc(r->chain_id, r->chain_id_len);
            if (!c) continue;  // chain table full
            size_t ci = (size_t)(c - s_cache);
            if (r->seq > per_chain_best_seq[ci]) {
                per_chain_best_seq[ci] = r->seq;
                c->state.height = r->height;
                c->state.round  = r->round;
                c->state.type   = r->type;
            }
            if (r->seq > max_seq) {
                max_seq    = r->seq;
                max_sector = (int)s;
                max_slot   = (int)k;
            }
        }
    }

    if (max_sector < 0) {
        s_cur_sector = 0;
        s_next_slot  = 0;
        s_next_seq   = 1;
    } else {
        s_cur_sector = (uint32_t)max_sector;
        s_next_slot  = ((uint32_t)max_slot + 1) % HWM_RECS_PER_SECTOR;
        s_next_seq   = max_seq + 1;
    }
}

hwm_state_t hwm_current(const char *chain_id, size_t chain_id_len) {
    hwm_cache_t *c = cache_find(chain_id, chain_id_len);
    if (c) return c->state;
    return (hwm_state_t){ 0, 0, 0 };
}

// Build a single 256B page and program it. Caller holds the interrupt
// critical section.
static void write_record(uint32_t sector, uint32_t slot,
                         const char *chain_id, size_t chain_id_len,
                         uint64_t seq, const hwm_state_t *s) {
    uint8_t page[HWM_REC_SIZE];
    memset(page, 0xFF, sizeof(page));
    hwm_rec_t *r = (hwm_rec_t *)page;
    r->magic        = HWM_MAGIC;
    r->seq          = seq;
    r->chain_id_len = (uint8_t)chain_id_len;
    memcpy(r->chain_id, chain_id, chain_id_len);
    r->height       = s->height;
    r->round        = s->round;
    r->type         = s->type;
    r->cksum        = cksum_of(r);
    flash_range_program(slot_offset(sector, slot), page, HWM_REC_SIZE);
}

// Move to the next sector: erase it, then write compaction records (one per
// live chain) starting at slot 0. Updates s_cur_sector / s_next_slot.
// Power-loss safe: the previous sector's records remain valid until the
// new sector's compaction records gain higher seq numbers.
static void advance_sector(void) {
    uint32_t next = (s_cur_sector + 1) % HWM_NUM_SECTORS;
    flash_range_erase(sector_offset(next), HWM_SECTOR_SIZE);

    uint32_t slot = 0;
    for (size_t ci = 0; ci < HWM_MAX_CHAINS; ci++) {
        if (!s_cache[ci].in_use) continue;
        write_record(next, slot,
                     s_cache[ci].chain_id, s_cache[ci].chain_id_len,
                     s_next_seq++, &s_cache[ci].state);
        slot++;
        if (slot >= HWM_RECS_PER_SECTOR) break;  // shouldn't happen: chains < records
    }
    s_cur_sector = next;
    s_next_slot  = slot;
}

bool hwm_advance(const char *chain_id, size_t chain_id_len,
                 int32_t type, int64_t height, int32_t round) {
    if (chain_id_len == 0 || chain_id_len > HWM_CHAIN_ID_MAX) return false;

    hwm_cache_t *c = cache_get_or_alloc(chain_id, chain_id_len);
    if (!c) return false;

    if (height < c->state.height) return false;
    if (height > c->state.height) goto ok;
    if (round  < c->state.round)  return false;
    if (round  > c->state.round)  goto ok;
    if (type   <= c->state.type)  return false;
ok: ;

    hwm_state_t new_state = { .height = height, .round = round, .type = type };

    uint32_t ints = save_and_disable_interrupts();
    if (s_next_slot >= HWM_RECS_PER_SECTOR) {
        // Pre-update cache so compaction writes the new state for this chain.
        c->state = new_state;
        advance_sector();
    } else {
        write_record(s_cur_sector, s_next_slot,
                     chain_id, chain_id_len, s_next_seq, &new_state);
        s_next_seq++;
        s_next_slot++;
        c->state = new_state;
    }
    restore_interrupts(ints);
    return true;
}

void hwm_flash_wipe(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(HWM_FLASH_OFFSET, HWM_FLASH_SIZE);
    restore_interrupts(ints);
    memset(s_cache, 0, sizeof(s_cache));
    s_cur_sector = 0;
    s_next_slot  = 0;
    s_next_seq   = 1;
}
