// TCP dialer for cometbft's SecretConnection handshake (Merlin variant).
//
// One outbound dialer per configured cosmos chain slot
// (os/storage/chains.h). Each slot owns its own dial FSM, active
// connection state, privval parser, and sink buffer. Slots run
// independently so a slow or unresponsive peer on one chain doesn't queue
// signing for any other chain.
//
// With zero cosmos slots configured the driver is dormant: no pcbs
// allocated, no dial attempts. Slots are read once from the chain config
// table at init; the operator must reboot to apply changes (chain config
// is editable only in TMKMS mode).

#include <stdio.h>
#include <string.h>

#include "pico/time.h"
#include "tusb.h"
#include "lwip/tcp.h"
#include "lwip/ip4_addr.h"

#include "apps/cosmos/sc_driver_cosmos.h"
#include "apps/cosmos/secret_connection_cosmos.h"
#include "apps/cosmos/privval.h"
#include "os/api.h"
#include "os/storage/chains.h"

#define VALIDATOR_KEY_PATH      "m/0'"

#define COSMOS_SC_DIAL_RETRY_MS         3000
// Settling time after USB enumerates before the first dial. Issuing
// tcp_connect before tud_ready() + a brief stabilization window wedges the
// netif on macOS hosts.
#define COSMOS_SC_DIAL_STABILIZE_TICKS  1000

typedef enum {
    RX_NONE = 0,
    RX_EPH,
    RX_AUTH,
    RX_PRIVVAL,    // handshake done; reading sealed privval frames
} rx_phase_t;

typedef struct cosmos_chain {
    const chain_slot_t *slot;       // NULL if this index is unconfigured

    // Dial FSM
    bool                dial_in_flight;
    bool                connected;
    uint32_t            ready_ticks;
    absolute_time_t     next_dial_at;

    // Active connection (lives between on_dial_connected and on_recv-close).
    struct tcp_pcb     *pcb;
    cosmos_sc_t         handshake;
    rx_phase_t          phase;
    uint8_t             val_pub[32];
    uint8_t             rx_buf[COSMOS_SC_AUTH_SEALED_SIZE];
    uint16_t            rx_need;
    uint16_t            rx_got;
    privval_state_t     parser;
    uint8_t             sink_buf[SC_DATA_MAX_SIZE];
    uint16_t            sink_pos;
} cosmos_chain_t;

// One slot per configurable chain. Index matches chains_get(COSMOS, i).
static cosmos_chain_t g_chains[CHAINS_MAX_PER_FAMILY];

static void reset_conn_state(cosmos_chain_t *c) {
    c->pcb            = NULL;
    c->phase          = RX_NONE;
    c->rx_need        = 0;
    c->rx_got         = 0;
    c->sink_pos       = 0;
    c->dial_in_flight = false;
    c->connected      = false;
    memset(&c->handshake, 0, sizeof(c->handshake));
    memset(c->rx_buf,     0, sizeof(c->rx_buf));
    memset(c->sink_buf,   0, sizeof(c->sink_buf));
    memset(&c->parser,    0, sizeof(c->parser));
}

static void schedule_retry(cosmos_chain_t *c) {
    c->next_dial_at = make_timeout_time_ms(COSMOS_SC_DIAL_RETRY_MS);
}

// Sink: ctx is the per-chain pointer. Buffer plaintext on write, seal and
// emit on flush. Privval responses are tiny (PubKey ~50 B, SignVoteResponse
// ~150 B), so one SC_DATA_MAX_SIZE buffer comfortably holds one response.
static int sc_sink_write(void *ctx, const uint8_t *bytes, size_t len) {
    cosmos_chain_t *c = (cosmos_chain_t *)ctx;
    if ((size_t)c->sink_pos + len > sizeof(c->sink_buf)) {
        os_console_log("cosmos-sc: response overflowed SC frame");
        return -1;
    }
    memcpy(c->sink_buf + c->sink_pos, bytes, len);
    c->sink_pos = (uint16_t)(c->sink_pos + len);
    return 0;
}

static void sc_sink_flush(void *ctx) {
    cosmos_chain_t *c = (cosmos_chain_t *)ctx;
    uint8_t sealed[SC_SEALED_FRAME_SIZE];
    sc_seal_frame(&c->handshake.sc, c->sink_buf,
                  (uint32_t)c->sink_pos, sealed);
    c->sink_pos = 0;
    if (tcp_write(c->pcb, sealed, SC_SEALED_FRAME_SIZE, TCP_WRITE_FLAG_COPY)
        == ERR_OK) {
        tcp_output(c->pcb);
    }
}

static int push_bytes(struct tcp_pcb *pcb, const uint8_t *bytes, uint16_t len,
                      const char *label) {
    err_t e = tcp_write(pcb, bytes, len, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) {
        char b[64];
        snprintf(b, sizeof(b), "cosmos-sc[%s]: tcp_write err=%d sndbuf=%u",
                 label, (int)e, (unsigned)tcp_sndbuf(pcb));
        os_console_log(b);
        return -1;
    }
    e = tcp_output(pcb);
    if (e != ERR_OK) {
        char b[56];
        snprintf(b, sizeof(b), "cosmos-sc[%s]: tcp_output err=%d", label, (int)e);
        os_console_log(b);
        return -1;
    }
    return 0;
}

static int advance(cosmos_chain_t *c) {
    if (c->rx_got < c->rx_need) return 0;
    const char *label = c->slot->label;

    if (c->phase == RX_EPH) {
        uint8_t eph_msg[COSMOS_SC_EPH_MSG_SIZE];
        cosmos_sc_start(&c->handshake, c->val_pub, eph_msg);
        if (push_bytes(c->pcb, eph_msg, COSMOS_SC_EPH_MSG_SIZE, label) != 0) {
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
        if (push_bytes(c->pcb, sealed, COSMOS_SC_AUTH_SEALED_SIZE, label) != 0) {
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
            char buf[64];
            snprintf(buf, sizeof(buf), "cosmos-sc[%s]: handle_auth rc=%d", label, rc);
            os_console_log(buf);
            return -1;
        }
        if (chains_pinned_count() == 0) {
            os_console_log("cosmos-sc: WARN no pinned peer keys (permissive)");
        } else if (!chains_pinned_check(c->handshake.rem_pub)) {
            os_console_log("cosmos-sc: peer pubkey not in allowlist; closing");
            return -1;
        }
        char log[64];
        snprintf(log, sizeof(log), "cosmos-sc[%s]: handshake complete", label);
        os_console_log(log);
        privval_reset_state(&c->parser, c->slot->chain_id);
        c->phase   = RX_PRIVVAL;
        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    if (c->phase == RX_PRIVVAL) {
        uint8_t plain[SC_DATA_MAX_SIZE];
        uint32_t plain_len = 0;
        if (sc_open_frame(&c->handshake.sc, c->rx_buf, plain, &plain_len) != 0) {
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

static void connection_closed(cosmos_chain_t *c) {
    reset_conn_state(c);
    schedule_retry(c);
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)err;
    cosmos_chain_t *c = (cosmos_chain_t *)arg;
    if (!p) {
        char log[64];
        snprintf(log, sizeof(log), "cosmos-sc[%s]: peer closed", c->slot->label);
        os_console_log(log);
        tcp_close(pcb);
        connection_closed(c);
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
                return ERR_ABRT;
            }
        }
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

// tcp_err: lwIP invokes this when the pcb is aborted. The pcb is already
// freed -- do NOT touch it.
static void on_dial_err(void *arg, err_t err) {
    cosmos_chain_t *c = (cosmos_chain_t *)arg;
    char buf[64];
    snprintf(buf, sizeof(buf), "cosmos-sc[%s]: dial err rc=%d",
             c->slot->label, (int)err);
    os_console_log(buf);
    connection_closed(c);
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
    cosmos_chain_t *c = (cosmos_chain_t *)arg;
    if (err != ERR_OK) {
        char buf[64];
        snprintf(buf, sizeof(buf), "cosmos-sc[%s]: connect rc=%d",
                 c->slot->label, (int)err);
        os_console_log(buf);
        connection_closed(c);
        return err;
    }
    char log[64];
    snprintf(log, sizeof(log), "cosmos-sc[%s]: connected", c->slot->label);
    os_console_log(log);
    c->pcb = pcb;

    size_t val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             c->val_pub, sizeof(c->val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("cosmos-sc: get_pubkey failed");
        tcp_abort(pcb);
        connection_closed(c);
        return ERR_ABRT;
    }

    c->phase   = RX_EPH;
    c->rx_need = COSMOS_SC_EPH_MSG_SIZE;
    c->rx_got  = 0;
    tcp_recv(pcb, on_recv);
    c->connected      = true;
    c->dial_in_flight = false;
    return ERR_OK;
}

// Issue one dial attempt for slot c. Caller has already determined this
// is the right moment.
static void issue_dial(cosmos_chain_t *c) {
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) {
        os_console_log("cosmos-sc: tcp_new failed");
        connection_closed(c);
        return;
    }

    // Canonical pico-examples order: arg first, then every callback, THEN
    // tcp_connect.
    tcp_arg(pcb,  c);
    tcp_err(pcb,  on_dial_err);
    tcp_sent(pcb, on_dial_sent);
    tcp_poll(pcb, on_dial_poll, 4);

    ip4_addr_t remote;
    IP4_ADDR(&remote,
             c->slot->dial_host[0], c->slot->dial_host[1],
             c->slot->dial_host[2], c->slot->dial_host[3]);

    char log[80];
    snprintf(log, sizeof(log),
             "cosmos-sc[%s]: dialing %u.%u.%u.%u:%u",
             c->slot->label,
             c->slot->dial_host[0], c->slot->dial_host[1],
             c->slot->dial_host[2], c->slot->dial_host[3],
             (unsigned)c->slot->port);
    os_console_log(log);
    c->dial_in_flight = true;
    err_t e = tcp_connect(pcb, &remote, c->slot->port, on_dial_connected);
    if (e != ERR_OK) {
        char buf[64];
        snprintf(buf, sizeof(buf), "cosmos-sc[%s]: tcp_connect rc=%d",
                 c->slot->label, (int)e);
        os_console_log(buf);
        tcp_abort(pcb);
        connection_closed(c);
    }
    // success path: leave dial_in_flight=true; on_dial_connected or
    // on_dial_err clears it when the attempt resolves.
}

void cosmos_sc_driver_init(void) {
    memset(g_chains, 0, sizeof(g_chains));
    size_t configured = 0;
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        const chain_slot_t *slot = chains_get(CHAINS_FAMILY_COSMOS, i);
        if (!slot->in_use) continue;
        g_chains[i].slot         = slot;
        g_chains[i].next_dial_at = get_absolute_time();   // first dial gated by USB-ready
        configured++;
    }
    char b[48];
    snprintf(b, sizeof(b), "cosmos-sc: %zu chain(s) configured", configured);
    os_console_log(b);
}

void cosmos_sc_driver_service(void) {
    if (!tud_ready()) {
        for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) g_chains[i].ready_ticks = 0;
        return;
    }
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        cosmos_chain_t *c = &g_chains[i];
        if (!c->slot) continue;
        if (c->connected || c->dial_in_flight) continue;
        if (c->ready_ticks < COSMOS_SC_DIAL_STABILIZE_TICKS) {
            c->ready_ticks++;
            continue;
        }
        if (absolute_time_diff_us(get_absolute_time(), c->next_dial_at) > 0) continue;
        issue_dial(c);
    }
}
