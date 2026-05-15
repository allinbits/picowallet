#pragma once
#include <stddef.h>
#include <stdint.h>

// Cosmos/CometBFT privval parser + handlers. Bytes are fed in one at a
// time via privval_feed_byte; responses come out through the caller's
// sink. The only transport is the SecretConnection driver on port 26660
// (apps/cosmos/sc_driver_cosmos.c) -- there's no plaintext listener.

typedef struct {
    // Write `len` response bytes. May be called multiple times per response
    // frame (header then body). Return 0 on success, non-zero to abort.
    int  (*write)(void *ctx, const uint8_t *bytes, size_t len);
    // End-of-frame signal. The SC sink seals + sends here; the plaintext
    // sink just calls tcp_output here.
    void (*flush)(void *ctx);
    void *ctx;
} privval_sink_t;

// Reset the privval frame parser to expect a fresh uvarint length prefix.
// Call at the start of each new connection.
void privval_reset_state(void);

// Push a single byte through the privval state machine. Returns 0 if all
// is well, -1 if the connection should be closed (malformed/oversize frame).
int  privval_feed_byte(privval_sink_t *sink, uint8_t b);
