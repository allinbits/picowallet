#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/storage/auth_keys.h"
#include "os/storage/flash_layout.h"

// Single-sector erase-and-rewrite layout. Admin operations are rare (operator
// adds/removes keys via TMKMS-mode REPL), so even at 1 admin op/day the
// 100K-cycle flash spec gives ~270 years. No log/ring needed.
//
// Record format (512 bytes = 2 page-program units, fits in one 4 KB sector):
//   magic    (4)
//   count    (1) + pad (3)
//   keys     (AUTH_KEYS_MAX * 32 = 256)
//   cksum    (4)
//   reserved (244 = pad to 512)

#define AUTH_KEYS_MAGIC      0xC0DEC0DEu
#define AUTH_KEYS_REC_SIZE   512u

typedef struct {
    uint32_t magic;
    uint8_t  count;
    uint8_t  pad0[3];
    uint8_t  keys[AUTH_KEYS_MAX][AUTH_KEYS_PUBKEY_LEN];
    uint32_t cksum;
    uint8_t  pad1[AUTH_KEYS_REC_SIZE
                  - 4 - 4 - (AUTH_KEYS_MAX * AUTH_KEYS_PUBKEY_LEN) - 4];
} auth_keys_record_t;

_Static_assert(sizeof(auth_keys_record_t) == AUTH_KEYS_REC_SIZE,
               "auth_keys_record_t must be exactly 512 bytes");

static uint8_t s_keys[AUTH_KEYS_MAX][AUTH_KEYS_PUBKEY_LEN];
static uint8_t s_count;

static const auth_keys_record_t *flash_ptr(void) {
    return (const auth_keys_record_t *)(XIP_BASE + AUTH_KEYS_FLASH_OFFSET);
}

static uint32_t cksum_of(const auth_keys_record_t *r) {
    const uint8_t *b = (const uint8_t *)r;
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < offsetof(auth_keys_record_t, cksum); i++) {
        h ^= b[i];
        h *= 0x01000193u;
    }
    return h;
}

static void persist(void) {
    auth_keys_record_t rec;
    memset(&rec, 0xFF, sizeof(rec));
    rec.magic = AUTH_KEYS_MAGIC;
    rec.count = s_count;
    memset(rec.pad0, 0, sizeof(rec.pad0));
    memcpy(rec.keys, s_keys, sizeof(rec.keys));
    rec.cksum = cksum_of(&rec);

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(AUTH_KEYS_FLASH_OFFSET, AUTH_KEYS_FLASH_SIZE);
    flash_range_program(AUTH_KEYS_FLASH_OFFSET,
                        (const uint8_t *)&rec, AUTH_KEYS_REC_SIZE);
    restore_interrupts(ints);
}

void auth_keys_init(void) {
    memset(s_keys, 0, sizeof(s_keys));
    s_count = 0;

    const auth_keys_record_t *r = flash_ptr();
    if (r->magic != AUTH_KEYS_MAGIC)            return;
    if (r->count > AUTH_KEYS_MAX)               return;
    if (r->cksum != cksum_of(r))                return;

    s_count = r->count;
    memcpy(s_keys, r->keys, sizeof(s_keys));
}

size_t auth_keys_count(void) {
    return (size_t)s_count;
}

static bool is_zero_pubkey(const uint8_t pub[AUTH_KEYS_PUBKEY_LEN]) {
    uint8_t accum = 0;
    for (size_t i = 0; i < AUTH_KEYS_PUBKEY_LEN; i++) accum |= pub[i];
    return accum == 0;
}

bool auth_keys_add(const uint8_t pubkey[AUTH_KEYS_PUBKEY_LEN]) {
    if (is_zero_pubkey(pubkey))               return false;
    if (s_count >= AUTH_KEYS_MAX)              return false;
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_keys[i], pubkey, AUTH_KEYS_PUBKEY_LEN) == 0) return false;
    }
    memcpy(s_keys[s_count], pubkey, AUTH_KEYS_PUBKEY_LEN);
    s_count++;
    persist();
    return true;
}

void auth_keys_clear(void) {
    memset(s_keys, 0, sizeof(s_keys));
    s_count = 0;
    persist();
}

bool auth_keys_check(const uint8_t pubkey[AUTH_KEYS_PUBKEY_LEN]) {
    if (s_count == 0) return true;  // permissive when no keys pinned
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_keys[i], pubkey, AUTH_KEYS_PUBKEY_LEN) == 0) return true;
    }
    return false;
}

// Read the i-th pinned key into `out`. Returns false if i >= count.
// Exposed for the `os.auth_list` REPL command.
bool auth_keys_get(size_t i, uint8_t out[AUTH_KEYS_PUBKEY_LEN]) {
    if (i >= s_count) return false;
    memcpy(out, s_keys[i], AUTH_KEYS_PUBKEY_LEN);
    return true;
}
