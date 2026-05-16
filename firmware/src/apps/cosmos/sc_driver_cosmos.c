// TCP driver for cometbft's SecretConnection handshake (Merlin variant).
//
// Mirrors apps/gnoland/sc_driver.c. As with the gno driver, we never
// tcp_write inside tcp_accept (lwIP returns ERR_MEM in that path); the
// peer sends first and we respond with our ephemeral + sealed auth back
// to back from on_recv.
//
// Per-connection state is allocated from a small pool and attached to
// each pcb via tcp_arg, so concurrent SC sessions don't share parser
// state. The pool size today is 1 (single-target dialer / single-listener
// behavior unchanged from before); a later commit bumps it alongside
// per-chain dial-target wiring.

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"

#include "apps/cosmos/sc_driver_cosmos.h"
#include "apps/cosmos/secret_connection_cosmos.h"
#include "apps/cosmos/privval.h"
#include "os/api.h"
#include "os/storage/chains.h"

#define VALIDATOR_KEY_PATH "m/0'"

typedef enum {
    RX_NONE = 0,
    RX_EPH,
    RX_AUTH,
    RX_PRIVVAL,    // handshake done; reading sealed privval frames
} rx_phase_t;

typedef struct cosmos_conn {
    bool             in_use;
    struct tcp_pcb  *pcb;
    cosmos_sc_t      handshake;
    rx_phase_t       phase;
    uint8_t          val_pub[32];
    uint8_t          rx_buf[COSMOS_SC_AUTH_SEALED_SIZE];
    uint16_t         rx_need;
    uint16_t         rx_got;
    privval_state_t  parser;
    uint8_t          sink_buf[SC_DATA_MAX_SIZE];
    uint16_t         sink_pos;
} cosmos_conn_t;

// Pool of per-connection slots. One is enough for today's single-target
// behavior; the per-chain dialer/listener work bumps this to match the
// number of configured chain slots.
#define COSMOS_CONN_POOL_SIZE  1
static cosmos_conn_t g_pool[COSMOS_CONN_POOL_SIZE];

static cosmos_conn_t *conn_alloc(void) {
    for (size_t i = 0; i < COSMOS_CONN_POOL_SIZE; i++) {
        if (!g_pool[i].in_use) {
            memset(&g_pool[i], 0, sizeof(g_pool[i]));
            g_pool[i].in_use = true;
            g_pool[i].phase  = RX_NONE;
            return &g_pool[i];
        }
    }
    return NULL;
}

static void conn_free(cosmos_conn_t *c) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
}

// Sink that buffers each privval response frame's plaintext and, on flush,
// seals it into one AEAD-encrypted SC frame before tcp_write'ing it.
// `ctx` is the per-connection cosmos_conn_t pointer.
//
// Privval responses are tiny (PubKey ~50 B, SignVoteResponse ~150 B, etc.),
// so a single SC_DATA_MAX_SIZE buffer comfortably holds one response. If a
// future message exceeds that, sink_write returns -1 and the privval
// state machine aborts the connection.
static int sc_sink_write(void *ctx, const uint8_t *bytes, size_t len) {
    cosmos_conn_t *c = (cosmos_conn_t *)ctx;
    if ((size_t)c->sink_pos + len > sizeof(c->sink_buf)) {
        os_console_log("cosmos-sc: response overflowed SC frame");
        return -1;
    }
    memcpy(c->sink_buf + c->sink_pos, bytes, len);
    c->sink_pos = (uint16_t)(c->sink_pos + len);
    return 0;
}

static void sc_sink_flush(void *ctx) {
    cosmos_conn_t *c = (cosmos_conn_t *)ctx;
    uint8_t sealed[SC_SEALED_FRAME_SIZE];
    sc_seal_frame(&c->handshake.sc, c->sink_buf,
                  (uint32_t)c->sink_pos, sealed);
    c->sink_pos = 0;
    if (tcp_write(c->pcb, sealed, SC_SEALED_FRAME_SIZE, TCP_WRITE_FLAG_COPY)
        == ERR_OK) {
        tcp_output(c->pcb);
    }
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

static int advance(cosmos_conn_t *c) {
    if (c->rx_got < c->rx_need) return 0;

    if (c->phase == RX_EPH) {
        uint8_t eph_msg[COSMOS_SC_EPH_MSG_SIZE];
        cosmos_sc_start(&c->handshake, c->val_pub, eph_msg);
        if (push_bytes(c->pcb, eph_msg, COSMOS_SC_EPH_MSG_SIZE) != 0) {
            os_console_log("cosmos-sc: tx eph failed");
            return -1;
        }

        int rc = cosmos_sc_derive_keys(&c->handshake, c->rx_buf);
        if (rc != 0) {
            os_console_log("cosmos-sc: derive_keys failed");
            return -1;
        }

        uint8_t sig[64];
        rc = os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                            c->handshake.challenge,
                            COSMOS_SC_CHALLENGE_SIZE, sig);
        if (rc != 0) {
            os_console_log("cosmos-sc: os_crypto_sign failed");
            return -1;
        }

        uint8_t sealed[COSMOS_SC_AUTH_SEALED_SIZE];
        if (cosmos_sc_seal_auth(&c->handshake, sig, sealed) != 0) {
            os_console_log("cosmos-sc: seal_auth failed");
            return -1;
        }
        if (push_bytes(c->pcb, sealed, COSMOS_SC_AUTH_SEALED_SIZE) != 0) {
            os_console_log("cosmos-sc: tx auth failed");
            return -1;
        }

        c->phase   = RX_AUTH;
        c->rx_got  = 0;
        c->rx_need = COSMOS_SC_AUTH_SEALED_SIZE;
        return 0;
    }

    if (c->phase == RX_AUTH) {
        int rc = cosmos_sc_handle_auth(&c->handshake, c->rx_buf);
        if (rc != 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "cosmos-sc: handle_auth rc=%d", rc);
            os_console_log(buf);
            return -1;
        }
        if (chains_pinned_count() == 0) {
            os_console_log("cosmos-sc: WARN no pinned peer keys (permissive)");
        } else if (!chains_pinned_check(c->handshake.rem_pub)) {
            os_console_log("cosmos-sc: peer pubkey not in allowlist; closing");
            return -1;
        }
        os_console_log("cosmos-sc: handshake complete");
        privval_reset_state(&c->parser);
        c->phase   = RX_PRIVVAL;
        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    if (c->phase == RX_PRIVVAL) {
        // Decrypt one sealed frame, then feed its plaintext bytes through
        // the privval state machine. The sink wraps each response frame
        // in another AEAD seal before pushing it back over TCP.
        uint8_t plain[SC_DATA_MAX_SIZE];
        uint32_t plain_len = 0;
        if (sc_open_frame(&c->handshake.sc, c->rx_buf,
                          plain, &plain_len) != 0) {
            os_console_log("cosmos-sc: open_frame failed");
            return -1;
        }

        privval_sink_t sink = {
            .write = sc_sink_write,
            .flush = sc_sink_flush,
            .ctx   = c,
        };
        c->sink_pos = 0;
        for (uint32_t i = 0; i < plain_len; i++) {
            if (privval_feed_byte(&c->parser, &sink, plain[i]) < 0) {
                os_console_log("cosmos-sc: privval bad frame, closing");
                return -1;
            }
        }

        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    return 0;
}

// In dialer mode, schedule a reconnect after the active connection ends
// (clean disconnect, framing error, etc.). In listener mode this is a no-op.
static void connection_closed(cosmos_conn_t *c);

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)err;
    cosmos_conn_t *c = (cosmos_conn_t *)arg;
    if (!p) {
        os_console_log("cosmos-sc: client disconnected");
        tcp_close(pcb);
        connection_closed(c);
        conn_free(c);
        return ERR_OK;
    }

    for (struct pbuf *q = p; q != NULL; q = q->next) {
        const uint8_t *bytes = (const uint8_t *)q->payload;
        uint16_t avail = q->len;
        uint16_t off = 0;
        while (off < avail) {
            uint16_t want = c->rx_need - c->rx_got;
            uint16_t take = (uint16_t)(avail - off);
            if (take > want) take = want;
            memcpy(c->rx_buf + c->rx_got, bytes + off, take);
            c->rx_got += take;
            off += take;
            if (advance(c) < 0) {
                tcp_recved(pcb, p->tot_len);
                pbuf_free(p);
                tcp_close(pcb);
                connection_closed(c);
                conn_free(c);
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
    cosmos_conn_t *c = conn_alloc();
    if (!c) {
        os_console_log("cosmos-sc: pool full; rejecting");
        tcp_close(pcb);
        return ERR_MEM;
    }
    os_console_log("cosmos-sc: client connected");
    c->pcb = pcb;

    size_t val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             c->val_pub, sizeof(c->val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("cosmos-sc: get_pubkey failed");
        tcp_close(pcb);
        conn_free(c);
        return ERR_ABRT;
    }

    c->phase   = RX_EPH;
    c->rx_need = COSMOS_SC_EPH_MSG_SIZE;
    c->rx_got  = 0;
    tcp_arg(pcb,  c);
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
// Settling time after USB enumerates before the first dial. Issuing
// tcp_connect before tud_ready() + a brief stabilization window wedges the
// netif on macOS hosts.
#ifndef COSMOS_SC_DIAL_STABILIZE_TICKS
#define COSMOS_SC_DIAL_STABILIZE_TICKS 1000
#endif

// Connection-state flags driven by the callbacks. Reads/writes happen only
// from the main loop or lwIP callbacks (same context under NO_SYS=1).
// Stay process-global for now; per-target FSM lands with multi-slot
// wiring in a follow-up commit.
static bool        g_dial_in_flight = false;  // SYN sent, awaiting on_dial_connected/on_dial_err
static bool        g_connected      = false;  // on_dial_connected returned OK; pcb live
static uint32_t    g_ready_ticks    = 0;      // ticks since tud_ready() first true
static absolute_time_t g_next_dial_at;        // absolute time of next retry

static void connection_closed(cosmos_conn_t *c) {
    (void)c;
    g_connected      = false;
    g_dial_in_flight = false;
    g_next_dial_at   = make_timeout_time_ms(COSMOS_SC_DIAL_RETRY_MS);
}

// tcp_err: lwIP invokes this when the pcb is aborted (RST, ARP failure,
// transmit fatal error, ...). The pcb is already freed -- do NOT touch it.
static void on_dial_err(void *arg, err_t err) {
    cosmos_conn_t *c = (cosmos_conn_t *)arg;
    char buf[48];
    snprintf(buf, sizeof(buf), "cosmos-sc: dial err cb rc=%d", (int)err);
    os_console_log(buf);
    connection_closed(c);
    conn_free(c);
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
    cosmos_conn_t *c = (cosmos_conn_t *)arg;
    if (err != ERR_OK) {
        char buf[48];
        snprintf(buf, sizeof(buf), "cosmos-sc: connect cb rc=%d; retrying", (int)err);
        os_console_log(buf);
        connection_closed(c);
        conn_free(c);
        return err;
    }
    os_console_log("cosmos-sc: connected to remote validator");
    c->pcb = pcb;

    size_t val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             c->val_pub, sizeof(c->val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("cosmos-sc: get_pubkey failed");
        tcp_abort(pcb);
        connection_closed(c);
        conn_free(c);
        return ERR_ABRT;
    }

    c->phase   = RX_EPH;
    c->rx_need = COSMOS_SC_EPH_MSG_SIZE;
    c->rx_got  = 0;
    tcp_recv(pcb, on_recv);
    g_connected      = true;
    g_dial_in_flight = false;
    return ERR_OK;
}

// Issue one dial attempt. Caller has already determined this is the right
// moment (USB up, no connection in flight, retry interval elapsed).
static void issue_dial(void) {
    cosmos_conn_t *c = conn_alloc();
    if (!c) {
        os_console_log("cosmos-sc: pool full; deferring dial");
        g_next_dial_at = make_timeout_time_ms(COSMOS_SC_DIAL_RETRY_MS);
        return;
    }
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) {
        os_console_log("cosmos-sc: tcp_new failed");
        conn_free(c);
        connection_closed(c);
        return;
    }

    // Canonical pico-examples order: arg first, then every callback, THEN
    // tcp_connect. A prior sparse callback set (only tcp_err) plus
    // sys_timeout firing early was the original wedge pattern.
    tcp_arg(pcb,  c);
    tcp_err(pcb,  on_dial_err);
    tcp_sent(pcb, on_dial_sent);
    tcp_poll(pcb, on_dial_poll, 4);

    ip4_addr_t remote;
    if (!ip4addr_aton(COSMOS_SC_DIAL_HOST, &remote)) {
        os_console_log("cosmos-sc: bad COSMOS_SC_DIAL_HOST");
        tcp_abort(pcb);
        conn_free(c);
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
        conn_free(c);
        connection_closed(c);
    }
    // success path: leave g_dial_in_flight=true; on_dial_connected or
    // on_dial_err clears it when the attempt resolves.
}

void cosmos_sc_driver_init(void) {
    memset(g_pool, 0, sizeof(g_pool));
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

static void connection_closed(cosmos_conn_t *c) { (void)c; /* listener keeps listening */ }

void cosmos_sc_driver_init(void) {
    memset(g_pool, 0, sizeof(g_pool));

    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) return;
    if (tcp_bind(pcb, IP_ADDR_ANY, COSMOS_SC_DRIVER_PORT) != ERR_OK) return;
    struct tcp_pcb *lpcb = tcp_listen(pcb);
    if (!lpcb) return;
    tcp_accept(lpcb, on_accept);
}

void cosmos_sc_driver_service(void) { /* no-op in listener mode */ }

#endif
