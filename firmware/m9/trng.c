#include "trng.h"

#include <stdbool.h>

// RP2350 TRNG (Secure-only after Phase 4). Hardware emits 192 bits per
// cycle across EHR_DATA0..5; we cache the unused words between calls.
#define TRNG_BASE_S            0x400F0000u
#define TRNG_RND_SOURCE_ENABLE (*(volatile uint32_t *)(TRNG_BASE_S + 0x12Cu))
#define TRNG_TRNG_VALID        (*(volatile uint32_t *)(TRNG_BASE_S + 0x110u))
#define TRNG_RNG_ICR           (*(volatile uint32_t *)(TRNG_BASE_S + 0x108u))
#define TRNG_EHR_DATA0_ADDR    ((volatile uint32_t *)(TRNG_BASE_S + 0x114u))

static uint32_t s_trng_buf[6];
static uint32_t s_trng_pos = 6;
static bool     s_trng_enabled = false;

uint32_t m9_trng_word(void) {
    if (!s_trng_enabled) {
        TRNG_RND_SOURCE_ENABLE = 1u;
        s_trng_enabled = true;
    }
    if (s_trng_pos >= 6u) {
        while (!(TRNG_TRNG_VALID & 1u)) { /* spin until 192 bits ready */ }
        for (int i = 0; i < 6; i++) s_trng_buf[i] = TRNG_EHR_DATA0_ADDR[i];
        // Writing 1 to RNG_ICR's interrupt bits clears VALID so the next
        // batch starts collecting. The 0x3F mask covers all six EHR_*
        // valid-ready bits the bootrom uses; harmless to write spares.
        TRNG_RNG_ICR = 0x3Fu;
        s_trng_pos = 0;
    }
    return s_trng_buf[s_trng_pos++];
}

void m9_trng_fill(uint8_t *out, size_t n) {
    size_t i = 0;
    while (i + 4u <= n) {
        uint32_t w = m9_trng_word();
        out[i + 0] = (uint8_t)(w);
        out[i + 1] = (uint8_t)(w >> 8);
        out[i + 2] = (uint8_t)(w >> 16);
        out[i + 3] = (uint8_t)(w >> 24);
        i += 4;
    }
    if (i < n) {
        uint32_t w = m9_trng_word();
        for (size_t j = 0; j < n - i; j++) out[i + j] = (uint8_t)(w >> (8 * j));
    }
}
