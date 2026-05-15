// STROBE-128 over Keccak-f[1600]. See strobe.h.
//
// Hot path during a Merlin-bearing handshake: ~4 PRF / ~8 AD operations
// total, plus init. Not performance-critical; we keep the code simple.

#include <string.h>

#include "os/crypto/keccak.h"
#include "os/crypto/strobe.h"

// Flag bits per STROBE spec. T (transport) and K (key) are unused because
// we don't expose KEY / SEND_* / RECV_* operations.
#define FLAG_I  (1u << 0)   // inbound
#define FLAG_A  (1u << 1)   // application
#define FLAG_C  (1u << 2)   // cipher
#define FLAG_M  (1u << 4)   // meta

// constN = 200, constSec = 128 (bits). r = N - sec/4 = 200 - 32 = 168.
// After absorbing the init domain, r is reduced by 2 to make room for the
// two-byte runF framing.
#define R_INIT  168u

static inline uint8_t *state_bytes(strobe_t *s) {
    return (uint8_t *)s->state;
}

static void strobe_runF(strobe_t *s) {
    if (s->initialized) {
        uint8_t *b = state_bytes(s);
        b[s->pos]     ^= (uint8_t)s->pos_begin;
        b[s->pos + 1] ^= 0x04;
        b[s->r + 1]   ^= 0x80;
    }
    keccak_f1600(s->state);
    s->pos       = 0;
    s->pos_begin = 0;
}

// duplex absorbs `data` into the state byte-by-byte through the rate
// window, calling Keccak-f whenever the rate fills. If c_before is set
// (the C flag is on), `data` is first XOR'd with the state bytes -- used
// by PRF and KEY. force_f forces a final Keccak-f after even partial
// absorption (used only during init).
static void strobe_duplex(strobe_t *s, uint8_t *data, size_t len,
                          int c_before, int force_f) {
    uint8_t *bytes = state_bytes(s);
    size_t dpos = 0;
    while (dpos < len) {
        size_t avail = (size_t)(s->r - s->pos);
        size_t n = len - dpos;
        if (n > avail) n = avail;

        if (c_before) {
            for (size_t i = 0; i < n; i++) {
                data[dpos + i] ^= bytes[s->pos + i];
            }
        }
        for (size_t i = 0; i < n; i++) {
            bytes[s->pos + i] ^= data[dpos + i];
        }

        s->pos = (uint16_t)(s->pos + n);
        dpos += n;

        if (s->pos == s->r) {
            strobe_runF(s);
        }
    }

    if (force_f && s->pos != 0) {
        strobe_runF(s);
    }
}

static void strobe_begin_op(strobe_t *s, uint8_t flags) {
    uint8_t old_begin = (uint8_t)s->pos_begin;
    s->pos_begin = (uint16_t)(s->pos + 1);

    uint8_t op_bytes[2] = { old_begin, flags };
    // Per spec: framing bytes are c_before=false, force_f=(C in flags).
    int force_f = (flags & FLAG_C) ? 1 : 0;
    strobe_duplex(s, op_bytes, 2, /*c_before=*/0, force_f);
}

// operate begins a fresh op (or continues one when `more` is set), then
// duplexes `data`. The `more` path is how Merlin chains a meta-AD label
// with a length field: meta_ad(label, more=0); meta_ad(len, more=1).
static void strobe_operate(strobe_t *s, uint8_t flags,
                           uint8_t *data, size_t len, int more) {
    if (more) {
        // Caller's responsibility: flags must match. Silently ignore the
        // mismatch case (rather than panicking) because the Merlin code
        // path that calls us has the same flag both times by construction.
    } else {
        strobe_begin_op(s, flags);
        s->cur_flags = flags;
    }

    int c_before = (flags & FLAG_C) ? 1 : 0;
    strobe_duplex(s, data, len, c_before, /*force_f=*/0);
}

void strobe_init(strobe_t *s, const char *proto) {
    memset(s, 0, sizeof(*s));
    s->r = R_INIT;

    // Domain separator: STROBE init label bytes per spec.
    uint8_t domain[] = {
        1, (uint8_t)s->r, 1, 0, 1, 12 * 8,
        'S', 'T', 'R', 'O', 'B', 'E', 'v', '1', '.', '0', '.', '2',
    };
    strobe_duplex(s, domain, sizeof(domain), /*c_before=*/0, /*force_f=*/1);

    s->r           = (uint16_t)(s->r - 2);
    s->initialized = 1;

    size_t proto_len = 0;
    while (proto[proto_len]) proto_len++;
    strobe_operate(s, FLAG_A | FLAG_M, (uint8_t *)proto, proto_len, /*more=*/0);
}

void strobe_ad(strobe_t *s, const uint8_t *data, size_t len, int more) {
    // AD has no C flag, so duplex won't mutate the buffer. The const cast
    // is safe; we just can't express that through the strobe_operate type.
    strobe_operate(s, FLAG_A, (uint8_t *)(uintptr_t)data, len, more);
}

void strobe_meta_ad(strobe_t *s, const uint8_t *data, size_t len, int more) {
    strobe_operate(s, FLAG_A | FLAG_M, (uint8_t *)(uintptr_t)data, len, more);
}

void strobe_prf(strobe_t *s, uint8_t *dest, size_t len) {
    // PRF has I + A + C. With C set, duplex XOR's state into `dest` before
    // absorbing -- but the spec extracts pseudo-random bytes, so `dest`
    // must start zeroed.
    memset(dest, 0, len);
    strobe_operate(s, FLAG_I | FLAG_A | FLAG_C, dest, len, /*more=*/0);
}
