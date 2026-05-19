// M9.5 Phase 7.5 -- per-chain-slot seed override storage (Secure-only).

#if PICOWALLET_SECURE_BUILD

#include "os/storage/slot_seed.h"

#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/platform.h"

#include "os/crypto/monocypher.h"
#include "os/storage/flash_layout.h"
#include "os/storage/seed_flash.h"   // m9_seal_payload / m9_unseal_payload

#define SLOT_SEED_PAGE_SIZE   256u
#define SLOT_SEED_MAGIC       0x510750FEu
#define SLOT_SEED_VERSION     1u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t  source;     // slot_seed_source_t cast
    uint8_t  plain_len;  // 32 (RAW_KEY) or 64 (MNEMONIC)
    uint8_t  reserved[6];
    uint8_t  salt[16];
    uint8_t  nonce[24];
    uint8_t  tag[16];
    uint8_t  ciphertext[64];   // up to M9_SEAL_MAX_PAYLOAD
} slot_seed_record_t;
_Static_assert(sizeof(slot_seed_record_t) <= SLOT_SEED_PAGE_SIZE,
               "slot seed record must fit in one flash page");

static const slot_seed_record_t *slot_record_ptr(uint8_t idx) {
    return (const slot_seed_record_t *)(XIP_BASE + SLOT_SEED_OFFSET(idx));
}

slot_seed_source_t m9_slot_seed_source(uint8_t slot_idx) {
    if (slot_idx >= SLOT_SEED_COUNT) return SLOT_SEED_SOURCE_DERIVED;
    const slot_seed_record_t *r = slot_record_ptr(slot_idx);
    if (r->magic   != SLOT_SEED_MAGIC)   return SLOT_SEED_SOURCE_DERIVED;
    if (r->version != SLOT_SEED_VERSION) return SLOT_SEED_SOURCE_DERIVED;
    if (r->source == SLOT_SEED_SOURCE_MNEMONIC && r->plain_len == 64) {
        return SLOT_SEED_SOURCE_MNEMONIC;
    }
    if (r->source == SLOT_SEED_SOURCE_RAW_KEY && r->plain_len == 32) {
        return SLOT_SEED_SOURCE_RAW_KEY;
    }
    return SLOT_SEED_SOURCE_DERIVED;
}

size_t m9_slot_seed_unseal(uint8_t slot_idx,
                           const uint8_t *pin, size_t pin_len,
                           uint8_t out[64]) {
    if (slot_idx >= SLOT_SEED_COUNT || !pin || !out) return 0;
    const slot_seed_record_t *r = slot_record_ptr(slot_idx);
    if (r->magic   != SLOT_SEED_MAGIC)   return 0;
    if (r->version != SLOT_SEED_VERSION) return 0;
    size_t plain_len = r->plain_len;
    if (plain_len != 32 && plain_len != 64) return 0;

    int rc = m9_unseal_payload(pin, pin_len,
                               r->salt, r->nonce,
                               r->ciphertext, plain_len,
                               r->tag, out);
    if (rc != 0) return 0;
    return plain_len;
}

int m9_slot_seed_store(uint8_t slot_idx,
                       slot_seed_source_t source,
                       const uint8_t *pin, size_t pin_len,
                       const uint8_t *plaintext, size_t plain_len) {
    if (slot_idx >= SLOT_SEED_COUNT) return -1;
    if (source != SLOT_SEED_SOURCE_MNEMONIC && source != SLOT_SEED_SOURCE_RAW_KEY) return -1;
    if (source == SLOT_SEED_SOURCE_MNEMONIC && plain_len != 64) return -1;
    if (source == SLOT_SEED_SOURCE_RAW_KEY  && plain_len != 32) return -1;

    uint8_t page[SLOT_SEED_PAGE_SIZE];
    memset(page, 0xFF, sizeof(page));
    slot_seed_record_t *rec = (slot_seed_record_t *)page;
    rec->magic     = SLOT_SEED_MAGIC;
    rec->version   = SLOT_SEED_VERSION;
    rec->source    = (uint8_t)source;
    rec->plain_len = (uint8_t)plain_len;

    int rc = m9_seal_payload(pin, pin_len, plaintext, plain_len,
                             rec->salt, rec->nonce,
                             rec->ciphertext, rec->tag);
    if (rc != 0) {
        crypto_wipe(page, sizeof(page));
        return -1;
    }

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SLOT_SEED_OFFSET(slot_idx), SLOT_SEED_FLASH_SIZE);
    flash_range_program(SLOT_SEED_OFFSET(slot_idx), page, sizeof(page));
    restore_interrupts(ints);
    crypto_wipe(page, sizeof(page));
    return 0;
}

void m9_slot_seed_clear(uint8_t slot_idx) {
    if (slot_idx >= SLOT_SEED_COUNT) return;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SLOT_SEED_OFFSET(slot_idx), SLOT_SEED_FLASH_SIZE);
    restore_interrupts(ints);
}

void m9_slot_seeds_wipe_all(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SLOT_SEEDS_FLASH_OFFSET, SLOT_SEEDS_FLASH_SIZE);
    restore_interrupts(ints);
}

#endif  // PICOWALLET_SECURE_BUILD
