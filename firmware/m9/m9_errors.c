// M9.5 structured error telemetry. Lives Secure-side so the boundary
// is the single source of truth.

#include "m9_errors.h"

#include <string.h>

static m9_error_state_t s_state;

void m9_error_log(uint8_t category, const char *msg) {
    if (category >= M9_ERR_CAT_COUNT) category = M9_ERR_CAT_INTERNAL;
    s_state.counters[category]++;
    s_state.total++;
    s_state.last_cat = category;
    if (msg) {
        // Plain truncating copy. The message is operator-facing
        // diagnostic, not secret -- no crypto_wipe needed on
        // overwrite.
        size_t i = 0;
        for (; i + 1 < sizeof(s_state.last_msg) && msg[i] != '\0'; i++) {
            s_state.last_msg[i] = msg[i];
        }
        s_state.last_msg[i] = '\0';
    }
}

void m9_error_get(m9_error_state_t *out) {
    if (!out) return;
    memcpy(out, &s_state, sizeof(*out));
}

void m9_error_reset(void) {
    uint32_t prev_boot_seq = s_state.boot_seq;
    memset(&s_state, 0, sizeof(s_state));
    s_state.boot_seq = prev_boot_seq + 1;
}
