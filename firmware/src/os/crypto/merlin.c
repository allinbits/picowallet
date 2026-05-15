#include <string.h>

#include "os/crypto/merlin.h"

#define MERLIN_PROTO       "Merlin v1.0"
#define MERLIN_DOM_SEP     "dom-sep"

static size_t cstrlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void put_le32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >>  8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

void merlin_init(merlin_t *t, const char *app_label) {
    strobe_init(&t->s, MERLIN_PROTO);
    merlin_append(t, MERLIN_DOM_SEP,
                  (const uint8_t *)app_label, cstrlen(app_label));
}

void merlin_append(merlin_t *t, const char *label,
                   const uint8_t *msg, size_t msg_len) {
    uint8_t sz[4];
    put_le32(sz, (uint32_t)msg_len);
    strobe_meta_ad(&t->s, (const uint8_t *)label, cstrlen(label), /*more=*/0);
    strobe_meta_ad(&t->s, sz, sizeof(sz), /*more=*/1);
    strobe_ad(&t->s, msg, msg_len, /*more=*/0);
}

void merlin_challenge(merlin_t *t, const char *label,
                      uint8_t *dest, size_t dest_len) {
    uint8_t sz[4];
    put_le32(sz, (uint32_t)dest_len);
    strobe_meta_ad(&t->s, (const uint8_t *)label, cstrlen(label), /*more=*/0);
    strobe_meta_ad(&t->s, sz, sizeof(sz), /*more=*/1);
    strobe_prf(&t->s, dest, dest_len);
}
