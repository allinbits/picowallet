#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/storage/chains.h"
#include "os/storage/flash_layout.h"

// Single-sector erase-and-rewrite layout. Admin operations are rare (operator
// edits config via TMKMS-mode REPL), so even at one rewrite/day the 100K-cycle
// flash spec gives ~270 years. No log/ring needed.

#define CHAINS_MAGIC      0xCA10D00Eu
#define CHAINS_VERSION    1u
#define CHAINS_REC_SIZE   4096u

typedef struct {
    uint32_t     magic;
    uint32_t     version;
    chain_slot_t cosmos[CHAINS_MAX_PER_FAMILY];
    chain_slot_t gno[CHAINS_MAX_PER_FAMILY];
    uint32_t     cksum;       // FNV-1a over preceding fields
} chains_record_t;

_Static_assert(sizeof(chains_record_t) <= CHAINS_REC_SIZE,
               "chains_record_t must fit in one flash sector");

static chain_slot_t s_cosmos[CHAINS_MAX_PER_FAMILY];
static chain_slot_t s_gno[CHAINS_MAX_PER_FAMILY];

static chain_slot_t *table_for(chains_family_t fam) {
    return (fam == CHAINS_FAMILY_COSMOS) ? s_cosmos : s_gno;
}

static const chains_record_t *flash_ptr(void) {
    return (const chains_record_t *)(XIP_BASE + CHAINS_FLASH_OFFSET);
}

static uint32_t cksum_of(const chains_record_t *r) {
    const uint8_t *b = (const uint8_t *)r;
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < offsetof(chains_record_t, cksum); i++) {
        h ^= b[i];
        h *= 0x01000193u;
    }
    return h;
}

static void persist(void) {
    static uint8_t page[CHAINS_REC_SIZE];
    memset(page, 0xFF, sizeof(page));
    chains_record_t *rec = (chains_record_t *)page;
    rec->magic   = CHAINS_MAGIC;
    rec->version = CHAINS_VERSION;
    memcpy(rec->cosmos, s_cosmos, sizeof(rec->cosmos));
    memcpy(rec->gno,    s_gno,    sizeof(rec->gno));
    rec->cksum   = cksum_of(rec);

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(CHAINS_FLASH_OFFSET, CHAINS_FLASH_SIZE);
    flash_range_program(CHAINS_FLASH_OFFSET, page, CHAINS_REC_SIZE);
    restore_interrupts(ints);
}

void chains_init(void) {
    memset(s_cosmos, 0, sizeof(s_cosmos));
    memset(s_gno,    0, sizeof(s_gno));

    const chains_record_t *r = flash_ptr();
    if (r->magic   != CHAINS_MAGIC)   return;
    if (r->version != CHAINS_VERSION) return;
    if (r->cksum   != cksum_of(r))    return;

    memcpy(s_cosmos, r->cosmos, sizeof(s_cosmos));
    memcpy(s_gno,    r->gno,    sizeof(s_gno));
}

size_t chains_count(chains_family_t fam) {
    const chain_slot_t *t = table_for(fam);
    size_t n = 0;
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        if (t[i].in_use) n++;
    }
    return n;
}

const chain_slot_t *chains_get(chains_family_t fam, size_t i) {
    if (i >= CHAINS_MAX_PER_FAMILY) return NULL;
    return &table_for(fam)[i];
}

const chain_slot_t *chains_find_by_label(chains_family_t fam, const char *label) {
    if (!label || !*label) return NULL;
    const chain_slot_t *t = table_for(fam);
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        if (!t[i].in_use) continue;
        if (strcmp(t[i].label, label) == 0) return &t[i];
    }
    return NULL;
}

static bool is_zero_pubkey(const uint8_t pub[CHAINS_PUBKEY_LEN]) {
    uint8_t accum = 0;
    for (size_t i = 0; i < CHAINS_PUBKEY_LEN; i++) accum |= pub[i];
    return accum == 0;
}

int chains_add(chains_family_t fam,
               const char *label,
               const char *chain_id,
               const uint8_t dial_host[4],
               uint16_t port,
               const uint8_t pinned_key[CHAINS_PUBKEY_LEN]) {
    if (!label    || !*label    || strlen(label)    >= CHAINS_LABEL_MAX)    return -4;
    if (!chain_id || !*chain_id || strlen(chain_id) >= CHAINS_CHAIN_ID_MAX) return -4;
    if (port == 0)                                                          return -4;
    if (fam == CHAINS_FAMILY_COSMOS && !dial_host)                          return -4;
    if (pinned_key && is_zero_pubkey(pinned_key))                           return -4;

    chain_slot_t *t = table_for(fam);
    int free_idx = -1;
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        if (!t[i].in_use) {
            if (free_idx < 0) free_idx = (int)i;
            continue;
        }
        if (strcmp(t[i].label,    label)    == 0) return -2;
        if (strcmp(t[i].chain_id, chain_id) == 0) return -3;
    }
    if (free_idx < 0) return -1;

    chain_slot_t *s = &t[free_idx];
    memset(s, 0, sizeof(*s));
    s->in_use = true;
    // strlen-checked above, so these copies always fit with room for NUL.
    memcpy(s->label,    label,    strlen(label)    + 1);
    memcpy(s->chain_id, chain_id, strlen(chain_id) + 1);
    s->port = port;
    if (fam == CHAINS_FAMILY_COSMOS) memcpy(s->dial_host, dial_host, 4);
    if (pinned_key) {
        s->has_pinned_key = true;
        memcpy(s->pinned_key, pinned_key, CHAINS_PUBKEY_LEN);
    }
    persist();
    return 0;
}

bool chains_remove(chains_family_t fam, const char *label) {
    chain_slot_t *t = table_for(fam);
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        if (!t[i].in_use) continue;
        if (strcmp(t[i].label, label) != 0) continue;
        memset(&t[i], 0, sizeof(t[i]));
        persist();
        return true;
    }
    return false;
}

void chains_wipe(void) {
    memset(s_cosmos, 0, sizeof(s_cosmos));
    memset(s_gno,    0, sizeof(s_gno));
    persist();
}
