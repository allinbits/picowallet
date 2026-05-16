// TCP driver for cometbft's SecretConnection handshake (Merlin variant).
//
// Mirrors apps/gnoland/sc_driver.c. As with the gno driver, we never
// tcp_write inside tcp_accept (lwIP returns ERR_MEM in that path); the
// peer sends first and we respond with our ephemeral + sealed auth back
// to back from on_recv.
//
// After handshake completion this driver currently just logs success and
// holds the connection open. Wiring the existing protobuf privval state
// machine (apps/cosmos/privval.c) through the encrypted frame layer is a
// follow-up.

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"

#include "apps/cosmos/sc_driver_cosmos.h"
#include "apps/cosmos/secret_connection_cosmos.h"
#include "apps/cosmos/privval.h"
#include "os/api.h"
#include "os/storage/auth_keys.h"

#define VALIDATOR_KEY_PATH "m/0'"

typedef enum {
    RX_NONE = 0,
    RX_EPH,
    RX_AUTH,
    RX_PRIVVAL,    // handshake done; reading sealed privval frames
} rx_phase_t;

typedef struct {
    cosmos_sc_t   handshake;
    rx_phase_t    phase;
    uint8_t       val_pub[32];
    uint8_t       rx_buf[COSMOS_SC_AUTH_SEALED_SIZE];
    uint16_t      rx_need;
    uint16_t      rx_got;
} conn_state_t;

static conn_state_t g_state;

// Sink that buffers each privval response frame's plaintext and, on flush,
// seals it into one AEAD-encrypted SC frame before tcp_write'ing it.
//
// Privval responses are tiny (PubKey ~50 B, SignVoteResponse ~150 B, etc.),
// so a single SC_DATA_MAX_SIZE buffer comfortably holds one response. If a
// future message exceeds that, the sink_write call returns -1 and the
// privval state machine aborts the connection.
static uint8_t  g_sc_sink_buf[SC_DATA_MAX_SIZE];
static uint16_t g_sc_sink_pos;

static int sc_sink_write(void *ctx, const uint8_t *bytes, size_t len) {
    (void)ctx;
    if ((size_t)g_sc_sink_pos + len > sizeof(g_sc_sink_buf)) {
        os_console_log("cosmos-sc: response overflowed SC frame");
        return -1;
    }
    memcpy(g_sc_sink_buf + g_sc_sink_pos, bytes, len);
    g_sc_sink_pos = (uint16_t)(g_sc_sink_pos + len);
    return 0;
}

static void sc_sink_flush(void *ctx) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)ctx;
    uint8_t sealed[SC_SEALED_FRAME_SIZE];
    sc_seal_frame(&g_state.handshake.sc, g_sc_sink_buf,
                  (uint32_t)g_sc_sink_pos, sealed);
    g_sc_sink_pos = 0;
    if (tcp_write(pcb, sealed, SC_SEALED_FRAME_SIZE, TCP_WRITE_FLAG_COPY)
        == ERR_OK) {
        tcp_output(pcb);
    }
}

static void state_reset(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.phase = RX_NONE;
    g_sc_sink_pos = 0;
}

static int push_bytes(struct tcp_pcb *pcb, const uint8_t *bytes, uint16_t len) {
    err_t e = tcp_write(pcb, bytes, len, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) {
        char b[48];
        snprintf(b, sizeof(b), "cosmos-sc: tcp_write err=%d sndbuf=%u",
                 (int)e, (unsigned)tcp_sndbuf(pcb));
        os_console_log(b);
        return -1;
    }
    e = tcp_output(pcb);
    if (e != ERR_OK) {
        char b[40];
        snprintf(b, sizeof(b), "cosmos-sc: tcp_output err=%d", (int)e);
        os_console_log(b);
        return -1;
    }
    return 0;
}

static int advance(struct tcp_pcb *pcb) {
    if (g_state.rx_got < g_state.rx_need) return 0;

    if (g_state.phase == RX_EPH) {
        uint8_t eph_msg[COSMOS_SC_EPH_MSG_SIZE];
        cosmos_sc_start(&g_state.handshake, g_state.val_pub, eph_msg);
        if (push_bytes(pcb, eph_msg, COSMOS_SC_EPH_MSG_SIZE) != 0) {
            os_console_log("cosmos-sc: tx eph failed");
            return -1;
        }

        int rc = cosmos_sc_derive_keys(&g_state.handshake, g_state.rx_buf);
        if (rc != 0) {
            os_console_log("cosmos-sc: derive_keys failed");
            return -1;
        }

        uint8_t sig[64];
        rc = os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                            g_state.handshake.challenge,
                            COSMOS_SC_CHALLENGE_SIZE, sig);
        if (rc != 0) {
            os_console_log("cosmos-sc: os_crypto_sign failed");
            return -1;
        }

        uint8_t sealed[COSMOS_SC_AUTH_SEALED_SIZE];
        if (cosmos_sc_seal_auth(&g_state.handshake, sig, sealed) != 0) {
            os_console_log("cosmos-sc: seal_auth failed");
            return -1;
        }
        if (push_bytes(pcb, sealed, COSMOS_SC_AUTH_SEALED_SIZE) != 0) {
            os_console_log("cosmos-sc: tx auth failed");
            return -1;
        }

        g_state.phase   = RX_AUTH;
        g_state.rx_got  = 0;
        g_state.rx_need = COSMOS_SC_AUTH_SEALED_SIZE;
        return 0;
    }

    if (g_state.phase == RX_AUTH) {
        int rc = cosmos_sc_handle_auth(&g_state.handshake, g_state.rx_buf);
        if (rc != 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "cosmos-sc: handle_auth rc=%d", rc);
            os_console_log(buf);
            return -1;
        }
        if (auth_keys_count() == 0) {
            os_console_log("cosmos-sc: WARN no pinned peer keys (permissive)");
        } else if (!auth_keys_check(g_state.handshake.rem_pub)) {
            os_console_log("cosmos-sc: peer pubkey not in allowlist; closing");
            return -1;
        }
        os_console_log("cosmos-sc: handshake complete");
        privval_reset_state();          // reuse the cosmos privval state machine
        g_state.phase   = RX_PRIVVAL;
        g_state.rx_got  = 0;
        g_state.rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    if (g_state.phase == RX_PRIVVAL) {
        // Decrypt one sealed frame, then feed its plaintext bytes through
        // the existing privval state machine. The sink wraps each response
        // frame in another AEAD seal before pushing it back over TCP.
        uint8_t plain[SC_DATA_MAX_SIZE];
        uint32_t plain_len = 0;
        if (sc_open_frame(&g_state.handshake.sc, g_state.rx_buf,
                          plain, &plain_len) != 0) {
            os_console_log("cosmos-sc: open_frame failed");
            return -1;
        }

        privval_sink_t sink = {
            .write = sc_sink_write,
            .flush = sc_sink_flush,
            .ctx   = pcb,
        };
        g_sc_sink_pos = 0;
        for (uint32_t i = 0; i < plain_len; i++) {
            if (privval_feed_byte(&sink, plain[i]) < 0) {
                os_console_log("cosmos-sc: privval bad frame, closing");
                return -1;
            }
        }

        g_state.rx_got  = 0;
        g_state.rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    return 0;
}

// In dialer mode, schedule a reconnect after the active connection ends
// (clean disconnect, framing error, etc.). In listener mode this is a no-op.
static void connection_closed(void);

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) {
        os_console_log("cosmos-sc: client disconnected");
        tcp_close(pcb);
        connection_closed();
        return ERR_OK;
    }

    for (struct pbuf *q = p; q != NULL; q = q->next) {
        const uint8_t *bytes = (const uint8_t *)q->payload;
        uint16_t avail = q->len;
        uint16_t off = 0;
        while (off < avail) {
            uint16_t want = g_state.rx_need - g_state.rx_got;
            uint16_t take = (uint16_t)(avail - off);
            if (take > want) take = want;
            memcpy(g_state.rx_buf + g_state.rx_got, bytes + off, take);
            g_state.rx_got += take;
            off += take;
            if (advance(pcb) < 0) {
                tcp_recved(pcb, p->tot_len);
                pbuf_free(p);
                tcp_close(pcb);
                connection_closed();
                return ERR_ABRT;
            }
        }
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)arg; (void)err;
    os_console_log("cosmos-sc: client connected");
    state_reset();

    size_t val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             g_state.val_pub, sizeof(g_state.val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("cosmos-sc: get_pubkey failed");
        tcp_close(pcb);
        return ERR_ABRT;
    }

    g_state.phase   = RX_EPH;
    g_state.rx_need = COSMOS_SC_EPH_MSG_SIZE;
    g_state.rx_got  = 0;
    tcp_recv(pcb, on_recv);
    return ERR_OK;
}

// ============================================================================
// Two operating modes, selected at compile time:
//
//   - Default: TCP listener on COSMOS_SC_DRIVER_PORT. pwctl + dev clients
//     dial in. Convenient for testing.
//
//   - With -DCOSMOS_SC_DIAL_HOST=\"x.y.z.w\" (and optional COSMOS_SC_DIAL_PORT):
//     TCP dialer. The device connects out to cometbft's
//     `priv_validator_laddr` listener. This is what stock cometbft
//     expects -- cometbft is the server, the signer is the client.
//
// In dialer mode we retry every COSMOS_SC_DIAL_RETRY_MS milliseconds if
// the connection drops or fails, so cometbft can be started after the
// device or restarted at will.
// ============================================================================

#ifdef COSMOS_SC_DIAL_HOST

#include "pico/time.h"
#include "tusb.h"
#include "lwip/ip4_addr.h"

#ifndef COSMOS_SC_DIAL_PORT
#define COSMOS_SC_DIAL_PORT     26690
#endif
#ifndef COSMOS_SC_DIAL_RETRY_MS
#define COSMOS_SC_DIAL_RETRY_MS 3000
#endif
// Settling time after USB enumerates before the first dial. The diagnostic
// dialer-test build (apps/dialer_test.c) proved that issuing tcp_connect
// before tud_ready() + a brief stabilization window is what was wedging the
// netif; this constant is the same shape that test used.
#ifndef COSMOS_SC_DIAL_STABILIZE_TICKS
#define COSMOS_SC_DIAL_STABILIZE_TICKS 1000
#endif

// Connection-state flags driven by the callbacks. Reads/writes happen only
// from the main loop or lwIP callbacks (same context under NO_SYS=1).
static bool        g_dial_in_flight = false;  // SYN sent, awaiting on_dial_connected/on_dial_err
static bool        g_connected      = false;  // on_dial_connected returned OK; pcb live
static uint32_t    g_ready_ticks    = 0;      // ticks since tud_ready() first true
static absolute_time_t g_next_dial_at;        // absolute time of next retry

static void connection_closed(void) {
    g_connected      = false;
    g_dial_in_flight = false;
    g_next_dial_at   = make_timeout_time_ms(COSMOS_SC_DIAL_RETRY_MS);
}

// tcp_err: lwIP invokes this when the pcb is aborted (RST, ARP failure,
// transmit fatal error, ...). The pcb is already freed -- do NOT touch it.
static void on_dial_err(void *arg, err_t err) {
    (void)arg;
    char buf[48];
    snprintf(buf, sizeof(buf), "cosmos-sc: dial err cb rc=%d", (int)err);
    os_console_log(buf);
    connection_closed();
}

static err_t on_dial_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)pcb; (void)len;
    return ERR_OK;
}

static err_t on_dial_poll(void *arg, struct tcp_pcb *pcb) {
    (void)arg; (void)pcb;
    return ERR_OK;
}

static err_t on_dial_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)arg;
    if (err != ERR_OK) {
        char buf[48];
        snprintf(buf, sizeof(buf), "cosmos-sc: connect cb rc=%d; retrying", (int)err);
        os_console_log(buf);
        connection_closed();
        return err;
    }
    os_console_log("cosmos-sc: connected to remote validator");
    state_reset();

    size_t val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             g_state.val_pub, sizeof(g_state.val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("cosmos-sc: get_pubkey failed");
        tcp_abort(pcb);
        connection_closed();
        return ERR_ABRT;
    }

    g_state.phase   = RX_EPH;
    g_state.rx_need = COSMOS_SC_EPH_MSG_SIZE;
    g_state.rx_got  = 0;
    tcp_recv(pcb, on_recv);
    g_connected      = true;
    g_dial_in_flight = false;
    return ERR_OK;
}

// Issue one dial attempt. Caller has already determined this is the right
// moment (USB up, no connection in flight, retry interval elapsed).
static void issue_dial(void) {
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) {
        os_console_log("cosmos-sc: tcp_new failed");
        connection_closed();
        return;
    }

    // Canonical pico-examples order: arg first, then every callback, THEN
    // tcp_connect. The diagnostic dialer-test build proved that the prior
    // sparse callback set (only tcp_err) + early sys_timeout firing was the
    // wedge pattern.
    tcp_arg(pcb,  NULL);
    tcp_err(pcb,  on_dial_err);
    tcp_sent(pcb, on_dial_sent);
    tcp_poll(pcb, on_dial_poll, 4);

    ip4_addr_t remote;
    if (!ip4addr_aton(COSMOS_SC_DIAL_HOST, &remote)) {
        os_console_log("cosmos-sc: bad COSMOS_SC_DIAL_HOST");
        tcp_abort(pcb);
        g_dial_in_flight = false;  // fatal misconfig; don't retry
        return;
    }

    os_console_log("cosmos-sc: dialing...");
    g_dial_in_flight = true;
    err_t e = tcp_connect(pcb, &remote, COSMOS_SC_DIAL_PORT, on_dial_connected);
    if (e != ERR_OK) {
        char buf[48];
        snprintf(buf, sizeof(buf), "cosmos-sc: tcp_connect sync rc=%d", (int)e);
        os_console_log(buf);
        tcp_abort(pcb);
        connection_closed();
    }
    // success path: leave g_dial_in_flight=true; on_dial_connected or
    // on_dial_err clears it when the attempt resolves.
}

void cosmos_sc_driver_init(void) {
    state_reset();
    char b[64];
    snprintf(b, sizeof(b), "cosmos-sc: dial mode -> " COSMOS_SC_DIAL_HOST ":%d",
             COSMOS_SC_DIAL_PORT);
    os_console_log(b);
    g_next_dial_at = get_absolute_time();   // first dial is gated by USB-ready, not time
}

void cosmos_sc_driver_service(void) {
    if (g_connected || g_dial_in_flight) return;
    if (!tud_ready()) { g_ready_ticks = 0; return; }
    if (g_ready_ticks < COSMOS_SC_DIAL_STABILIZE_TICKS) {
        g_ready_ticks++;
        return;
    }
    if (absolute_time_diff_us(get_absolute_time(), g_next_dial_at) > 0) return;
    issue_dial();
}

#else   // ---- listener mode (default) ----

static void connection_closed(void) { /* no-op: listener keeps listening */ }

void cosmos_sc_driver_init(void) {
    state_reset();

    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) return;
    if (tcp_bind(pcb, IP_ADDR_ANY, COSMOS_SC_DRIVER_PORT) != ERR_OK) return;
    struct tcp_pcb *lpcb = tcp_listen(pcb);
    if (!lpcb) return;
    tcp_accept(lpcb, on_accept);
}

void cosmos_sc_driver_service(void) { /* no-op in listener mode */ }

#endif
