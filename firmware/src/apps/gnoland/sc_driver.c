// TCP driver for the gno.land SecretConnection handshake.
//
// Listens on GNO_SC_DRIVER_PORT. Peer connects, sends their 35-byte
// ephemeral; on receiving it we emit our 35-byte ephemeral + the 1044-byte
// sealed auth-sig back-to-back, then wait for the peer's sealed auth-sig.
//
// NOTE: we deliberately do NOT tcp_write inside tcp_accept -- pico-sdk's
// bundled lwIP returns ERR_MEM in that path. See [[reference_lwip_accept_no_write]].
// The peer is therefore required to send first. The Go reference protocol
// does both sides concurrently in goroutines, so this asymmetric ordering
// is compatible -- only one side blocks waiting, never both.
//
// Per-connection state is allocated from a small pool and attached to
// each pcb via tcp_arg. Pool size is 1 today (single-listener behavior
// unchanged from before); a later commit bumps it to match the number of
// configured gno chain slots.

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"

#include "apps/gnoland/sc_driver.h"
#include "apps/gnoland/secret_connection_gno.h"
#include "apps/gnoland/gno_privval.h"
#include "os/api.h"
#include "os/storage/hwm_flash.h"
#include "os/storage/chains.h"

#define VALIDATOR_KEY_PATH "m/0'"

typedef enum {
    RX_NONE = 0,
    RX_EPH,             // accumulating peer's 35-byte ephemeral
    RX_AUTH,            // accumulating peer's 1044-byte sealed auth
    RX_PRIVVAL,         // handshake done; reading sealed privval frames
} rx_phase_t;

typedef struct gno_conn {
    bool             in_use;
    struct tcp_pcb  *pcb;
    gno_sc_t         handshake;
    bool             handshake_init;
    rx_phase_t       phase;
    uint8_t          val_pub[32];
    uint8_t          rx_buf[GNO_SC_AUTH_SEALED_SIZE];  // big enough for either stage
    uint16_t         rx_need;
    uint16_t         rx_got;
} gno_conn_t;

#define GNO_CONN_POOL_SIZE  1
static gno_conn_t g_pool[GNO_CONN_POOL_SIZE];

static gno_conn_t *conn_alloc(void) {
    for (size_t i = 0; i < GNO_CONN_POOL_SIZE; i++) {
        if (!g_pool[i].in_use) {
            memset(&g_pool[i], 0, sizeof(g_pool[i]));
            g_pool[i].in_use = true;
            g_pool[i].phase  = RX_NONE;
            return &g_pool[i];
        }
    }
    return NULL;
}

static void conn_free(gno_conn_t *c) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
}

// Push len bytes via tcp_write+tcp_output. Returns 0 on success, -1 on err.
// Logs the lwIP error code so failures aren't ambiguous.
static int push_bytes(struct tcp_pcb *pcb, const uint8_t *bytes, uint16_t len) {
    err_t e = tcp_write(pcb, bytes, len, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) {
        char b[48];
        snprintf(b, sizeof(b), "gno-sc: tcp_write err=%d sndbuf=%u",
                 (int)e, (unsigned)tcp_sndbuf(pcb));
        os_console_log(b);
        return -1;
    }
    e = tcp_output(pcb);
    if (e != ERR_OK) {
        char b[40];
        snprintf(b, sizeof(b), "gno-sc: tcp_output err=%d", (int)e);
        os_console_log(b);
        return -1;
    }
    return 0;
}

// Drive the state machine forward whenever rx_got reaches rx_need.
// Returns 0 if the connection should stay open; -1 to close.
static int advance(gno_conn_t *c) {
    if (c->rx_got < c->rx_need) return 0;  // need more bytes

    if (c->phase == RX_EPH) {
        // Peer's 35-byte ephemeral is in rx_buf. Now generate ours, push it,
        // derive keys, sign the challenge via the OS keystore, seal the
        // auth-sig, and push that too.
        uint8_t eph_msg[GNO_SC_EPH_MSG_SIZE];
        gno_sc_start(&c->handshake, c->val_pub, eph_msg);
        c->handshake_init = true;
        if (push_bytes(c->pcb, eph_msg, GNO_SC_EPH_MSG_SIZE) != 0) {
            os_console_log("gno-sc: tx eph failed");
            return -1;
        }

        int rc = gno_sc_derive_keys(&c->handshake, c->rx_buf);
        if (rc != 0) {
            os_console_log("gno-sc: derive_keys failed");
            return -1;
        }

        uint8_t sig[64];
        rc = os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                            c->handshake.challenge,
                            GNO_SC_CHALLENGE_SIZE, sig);
        if (rc != 0) {
            os_console_log("gno-sc: os_crypto_sign failed");
            return -1;
        }

        uint8_t sealed[GNO_SC_AUTH_SEALED_SIZE];
        if (gno_sc_seal_auth(&c->handshake, sig, sealed) != 0) {
            os_console_log("gno-sc: seal_auth failed");
            return -1;
        }
        if (push_bytes(c->pcb, sealed, GNO_SC_AUTH_SEALED_SIZE) != 0) {
            os_console_log("gno-sc: tx auth failed");
            return -1;
        }

        c->phase   = RX_AUTH;
        c->rx_got  = 0;
        c->rx_need = GNO_SC_AUTH_SEALED_SIZE;
        return 0;
    }

    if (c->phase == RX_AUTH) {
        int rc = gno_sc_handle_auth(&c->handshake, c->rx_buf);
        if (rc != 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "gno-sc: handle_auth rc=%d", rc);
            os_console_log(buf);
            return -1;
        }
        // Peer pubkey pinning: if any keys are configured, the peer must
        // match; otherwise we run permissive and log a warning so operators
        // notice they're unpinned.
        if (chains_pinned_count() == 0) {
            os_console_log("gno-sc: WARN no pinned peer keys (permissive)");
        } else if (!chains_pinned_check(c->handshake.rem_pub)) {
            os_console_log("gno-sc: peer pubkey not in allowlist; closing");
            return -1;
        }
        os_console_log("gno-sc: handshake complete");
        // Switch to reading sealed privval frames.
        c->phase   = RX_PRIVVAL;
        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    if (c->phase == RX_PRIVVAL) {
        // One sealed frame = one privval request (multi-frame messages
        // aren't supported yet; gno's PubKey/SignRequest are tiny and fit).
        uint8_t plain[SC_DATA_MAX_SIZE];
        uint32_t plain_len = 0;
        int rc = sc_open_frame(&c->handshake.sc, c->rx_buf,
                               plain, &plain_len);
        if (rc != 0) {
            os_console_log("gno-sc: open_frame failed");
            return -1;
        }

        gno_privval_req_t req_type = GNO_PRIVVAL_REQ_UNKNOWN;
        const uint8_t *sign_bytes  = NULL;
        size_t         sign_len    = 0;
        size_t         consumed    = 0;
        if (gno_privval_parse_request(plain, plain_len, &req_type,
                                      &sign_bytes, &sign_len, &consumed) != 0) {
            os_console_log("gno-sc: parse_request failed");
            return -1;
        }

        uint8_t resp_plain[256];   // PubKeyResp=93B, SignResp=100B
        size_t  resp_len = 0;
        if (req_type == GNO_PRIVVAL_REQ_PUBKEY) {
            resp_len = gno_privval_encode_pubkey_response(
                c->val_pub, resp_plain, sizeof(resp_plain));
            if (!resp_len) {
                os_console_log("gno-sc: encode pubkey_resp failed");
                return -1;
            }
            os_console_log("gno-sc: served PubKeyRequest");
        } else if (req_type == GNO_PRIVVAL_REQ_SIGN) {
            // Parse the canonical sign-bytes to extract HWM-relevant fields.
            // Reject anything that doesn't look like a vote/proposal -- we
            // must never sign blindly, even for an authenticated peer.
            int32_t      type   = 0;
            int64_t      height = 0;
            int32_t      round  = 0;
            const char  *chain_id     = NULL;
            size_t       chain_id_len = 0;
            if (gno_privval_parse_canonical_sign_bytes(
                    sign_bytes, sign_len, &type, &height, &round,
                    &chain_id, &chain_id_len) != 0) {
                os_console_log("gno-sc: bad canonical sign bytes");
                resp_len = gno_privval_encode_sign_response_error(
                    "bad_sign_bytes", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            if (!hwm_advance(chain_id, chain_id_len, type, height, round)) {
                char log[80];
                int cid_show = (int)(chain_id_len > 20 ? 20 : chain_id_len);
                snprintf(log, sizeof(log),
                         "gno-sc: double_sign_refused %.*s t=%d h=%lld r=%d",
                         cid_show, chain_id, (int)type,
                         (long long)height, (int)round);
                os_console_log(log);
                resp_len = gno_privval_encode_sign_response_error(
                    "double_sign_refused", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            uint8_t sig[64];
            if (os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                               sign_bytes, sign_len, sig) != 0) {
                os_console_log("gno-sc: os_crypto_sign failed");
                return -1;
            }
            resp_len = gno_privval_encode_sign_response(
                sig, resp_plain, sizeof(resp_plain));
            if (!resp_len) {
                os_console_log("gno-sc: encode sign_resp failed");
                return -1;
            }
            char log[80];
            int cid_show = (int)(chain_id_len > 20 ? 20 : chain_id_len);
            snprintf(log, sizeof(log), "gno-sc: signed %.*s t=%d h=%lld r=%d",
                     cid_show, chain_id, (int)type,
                     (long long)height, (int)round);
            os_console_log(log);
        } else {
            os_console_log("gno-sc: unknown request type");
            return -1;
        }

    emit_response: ;
        uint8_t sealed[SC_SEALED_FRAME_SIZE];
        sc_seal_frame(&c->handshake.sc, resp_plain,
                      (uint32_t)resp_len, sealed);
        if (push_bytes(c->pcb, sealed, SC_SEALED_FRAME_SIZE) != 0) {
            os_console_log("gno-sc: tx response failed");
            return -1;
        }

        // Ready for the next request frame.
        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    return 0;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)err;
    gno_conn_t *c = (gno_conn_t *)arg;
    if (!p) {
        os_console_log("gno-sc: client disconnected");
        tcp_close(pcb);
        conn_free(c);
        return ERR_OK;
    }

    for (struct pbuf *q = p; q != NULL; q = q->next) {
        const uint8_t *bytes = (const uint8_t *)q->payload;
        uint16_t avail = q->len;
        uint16_t off   = 0;
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
    gno_conn_t *c = conn_alloc();
    if (!c) {
        os_console_log("gno-sc: pool full; rejecting");
        tcp_close(pcb);
        return ERR_MEM;
    }
    os_console_log("gno-sc: client connected");
    c->pcb = pcb;

    // Load the validator's long-term Ed25519 pubkey from the OS keystore.
    // We capture it now (in accept) but DON'T tcp_write from here -- see
    // [[reference_lwip_accept_no_write]]. All writes happen from on_recv.
    size_t  val_pub_len = 0;
    if (os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                             c->val_pub, sizeof(c->val_pub),
                             &val_pub_len) != 0
        || val_pub_len != 32) {
        os_console_log("gno-sc: get_pubkey failed");
        tcp_close(pcb);
        conn_free(c);
        return ERR_ABRT;
    }

    c->phase   = RX_EPH;
    c->rx_need = GNO_SC_EPH_MSG_SIZE;
    c->rx_got  = 0;
    tcp_arg(pcb,  c);
    tcp_recv(pcb, on_recv);
    return ERR_OK;
}

void gno_sc_driver_init(void) {
    memset(g_pool, 0, sizeof(g_pool));

    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) return;
    if (tcp_bind(pcb, IP_ADDR_ANY, GNO_SC_DRIVER_PORT) != ERR_OK) return;
    struct tcp_pcb *lpcb = tcp_listen(pcb);
    if (!lpcb) return;
    tcp_accept(lpcb, on_accept);
}
