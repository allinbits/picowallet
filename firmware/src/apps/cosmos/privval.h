#pragma once
#include <stddef.h>
#include <stdint.h>

// Cosmos/CometBFT privval parser + handlers. Bytes are fed in one at a
// time via privval_feed_byte; responses come out through the caller's
// sink. The only transport is the SecretConnection driver on port 26660
// (apps/cosmos/sc_driver_cosmos.c) -- there's no plaintext listener.
//
// Parser state lives in caller-owned storage (one per connection) so the
// driver can host multiple concurrent privval sessions.

#define PRIVVAL_FRAME_MAX        4096  // generous cap on a single privval message
#define PRIVVAL_CHAIN_ID_MAX     48    // matches CHAINS_CHAIN_ID_MAX

typedef struct {
    int      phase;      // PHASE_LEN (0) or PHASE_BODY (1)
    uint64_t len_value;
    int      len_shift;
    uint8_t  body[PRIVVAL_FRAME_MAX];
    size_t   body_len;
    size_t   body_pos;
    // The chain_id this connection is bound to (from the chain slot config).
    // Sign requests whose canonical bytes claim a different chain_id are
    // refused with a remote-signer error.
    char     expected_chain_id[PRIVVAL_CHAIN_ID_MAX];
} privval_state_t;

typedef struct {
    // Write `len` response bytes. May be called multiple times per response
    // frame (header then body). Return 0 on success, non-zero to abort.
    int  (*write)(void *ctx, const uint8_t *bytes, size_t len);
    // End-of-frame signal. The SC sink seals + sends here.
    void (*flush)(void *ctx);
    void *ctx;
} privval_sink_t;

// Reset a parser to expect a fresh uvarint length prefix and bind it to
// `expected_chain_id`. Call once per new connection. May be passed NULL
// to reset framing only (sign requests will then fail the chain_id check).
void privval_reset_state(privval_state_t *st, const char *expected_chain_id);

// Push a single byte through the parser. Returns 0 if all is well, -1 if
// the connection should be closed (malformed/oversize frame).
int  privval_feed_byte(privval_state_t *st, privval_sink_t *sink, uint8_t b);
