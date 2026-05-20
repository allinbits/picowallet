// TCP listener for the gno.land SecretConnection handshake.
//
// One tcp_listen per configured gno chain slot (os/storage/chains.h).
// Each slot owns its own listening pcb, plus at-most-one active connection
// inline (gno validators only ever open a single signer connection per
// chain). The slot pointer rides on tcp_arg through accept/recv so slots
// stay isolated.
//
// 0 gno slots configured = no listeners bound. The driver is dormant.
//
// NOTE: we deliberately do NOT tcp_write inside tcp_accept -- pico-sdk's
// bundled lwIP returns ERR_MEM in that path. See [[reference_lwip_accept_no_write]].
// The peer is therefore required to send first. The Go reference protocol
// does both sides concurrently in goroutines, so this asymmetric ordering
// is compatible -- only one side blocks waiting, never both.

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"

#include "apps/gnoland/sc_driver.h"
#include "apps/gnoland/secret_connection_gno.h"
#include "apps/gnoland/gno_privval.h"
#include "os/api.h"
#include "os/storage/hwm_flash.h"
#if PICOWALLET_TRUSTZONE
#include "os/secure_api.h"
#endif
#include "os/storage/chains.h"

#define VALIDATOR_KEY_PATH "m/0'"

typedef enum {
    RX_NONE = 0,
    RX_EPH,             // accumulating peer's 35-byte ephemeral
    RX_AUTH,            // accumulating peer's 1044-byte sealed auth
    RX_PRIVVAL,         // handshake done; reading sealed privval frames
} rx_phase_t;

typedef struct gno_chain {
    const chain_slot_t *slot;       // NULL if this index is unconfigured
    uint8_t             hwm_slot_idx;
    struct tcp_pcb     *lpcb;       // listening pcb (bound at init)

    // Active connection (one at a time per slot; gno validators dial in
    // a single signer connection).
    bool                connected;
    struct tcp_pcb     *pcb;
    gno_sc_t            handshake;
    bool                handshake_init;
    rx_phase_t          phase;
    uint8_t             val_pub[32];
    uint8_t             rx_buf[GNO_SC_AUTH_SEALED_SIZE];
    uint16_t            rx_need;
    uint16_t            rx_got;
} gno_chain_t;

static gno_chain_t g_chains[CHAINS_MAX_PER_FAMILY];

static void reset_conn_state(gno_chain_t *c) {
    c->connected      = false;
    c->pcb            = NULL;
    c->handshake_init = false;
    c->phase          = RX_NONE;
    c->rx_need        = 0;
    c->rx_got         = 0;
    memset(&c->handshake, 0, sizeof(c->handshake));
    memset(c->rx_buf,     0, sizeof(c->rx_buf));
}

static int push_bytes(struct tcp_pcb *pcb, const uint8_t *bytes, uint16_t len,
                      const char *label) {
    err_t e = tcp_write(pcb, bytes, len, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) {
        char b[64];
        snprintf(b, sizeof(b), "gno-sc[%s]: tcp_write err=%d sndbuf=%u",
                 label, (int)e, (unsigned)tcp_sndbuf(pcb));
        os_console_log(b);
        return -1;
    }
    e = tcp_output(pcb);
    if (e != ERR_OK) {
        char b[56];
        snprintf(b, sizeof(b), "gno-sc[%s]: tcp_output err=%d", label, (int)e);
        os_console_log(b);
        return -1;
    }
    return 0;
}

static int advance(gno_chain_t *c) {
    if (c->rx_got < c->rx_need) return 0;
    const char *label = c->slot->label;

    if (c->phase == RX_EPH) {
        uint8_t eph_msg[GNO_SC_EPH_MSG_SIZE];
        gno_sc_start(&c->handshake, c->val_pub, eph_msg);
        c->handshake_init = true;
        if (push_bytes(c->pcb, eph_msg, GNO_SC_EPH_MSG_SIZE, label) != 0) {
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
        if (push_bytes(c->pcb, sealed, GNO_SC_AUTH_SEALED_SIZE, label) != 0) {
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
            char buf[64];
            snprintf(buf, sizeof(buf), "gno-sc[%s]: handle_auth rc=%d", label, rc);
            os_console_log(buf);
            return -1;
        }
        if (!c->slot->has_pinned_key) {
            char m[80];
            snprintf(m, sizeof(m),
                     "gno-sc[%s]: WARN no pinned peer key (permissive)",
                     c->slot->label);
            os_console_log(m);
        } else if (memcmp(c->slot->pinned_key, c->handshake.rem_pub,
                          CHAINS_PUBKEY_LEN) != 0) {
            char m[80];
            snprintf(m, sizeof(m),
                     "gno-sc[%s]: peer pubkey mismatch; closing",
                     c->slot->label);
            os_console_log(m);
            return -1;
        }
        char log[64];
        snprintf(log, sizeof(log), "gno-sc[%s]: handshake complete", label);
        os_console_log(log);
        c->phase   = RX_PRIVVAL;
        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    if (c->phase == RX_PRIVVAL) {
        uint8_t plain[SC_DATA_MAX_SIZE];
        uint32_t plain_len = 0;
        int rc = sc_open_frame(&c->handshake.sc, c->rx_buf, plain, &plain_len);
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
            char log[64];
            snprintf(log, sizeof(log), "gno-sc[%s]: served PubKeyRequest", label);
            os_console_log(log);
        } else if (req_type == GNO_PRIVVAL_REQ_SIGN) {
            int32_t      type   = 0;
            int64_t      height = 0;
            int32_t      round  = 0;
            const char  *chain_id     = NULL;
            size_t       chain_id_len = 0;
            if (gno_privval_parse_canonical_sign_bytes(
                    sign_bytes, sign_len, &type, &height, &round,
                    &chain_id, &chain_id_len) != 0) {
                os_console_log("gno-sc: bad canonical sign bytes");
                s_errors_log(M9_ERR_CAT_PARSER, "gno: bad canonical sign bytes");
                resp_len = gno_privval_encode_sign_response_error(
                    "bad_sign_bytes", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            // Strict chain_id binding: the slot is the ground truth.
            // Bounded scan (instead of strlen) -- if flash corruption or
            // a NS-side bug strips the NUL, we'd otherwise run off the
            // struct end into adjacent slot data or out of the CHAINS
            // sector entirely. The cosmos privval path uses the same
            // pattern in s_sign_and_advance.
            size_t expected_len = 0;
            while (expected_len < CHAINS_CHAIN_ID_MAX
                   && c->slot->chain_id[expected_len] != '\0') expected_len++;
            if (chain_id_len != expected_len
                || memcmp(chain_id, c->slot->chain_id, chain_id_len) != 0) {
                char m[96];
                int cid_show = (int)(chain_id_len > 24 ? 24 : chain_id_len);
                snprintf(m, sizeof(m),
                         "gno-sc[%s]: chain_id_mismatch got=%.*s",
                         c->slot->label, cid_show, chain_id);
                os_console_log(m);
                s_errors_log(M9_ERR_CAT_CHAIN_ID_MISMATCH, m);
                resp_len = gno_privval_encode_sign_response_error(
                    "chain_id_mismatch", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            uint8_t sig[64];
#if PICOWALLET_TRUSTZONE
            s_sign_and_advance_args_t sa_args = {
                .path         = VALIDATOR_KEY_PATH,
                .data         = sign_bytes,
                .data_len     = sign_len,
                .out_sig      = sig,
                .hwm_slot_idx = c->hwm_slot_idx,
                .curve        = OS_CURVE_ED25519,
                .type         = type,
                .round        = round,
                .height       = height,
            };
            int sa_rc = s_sign_and_advance(&sa_args);
            if (sa_rc == -1) {
                char log[96];
                int cid_show = (int)(chain_id_len > 20 ? 20 : chain_id_len);
                snprintf(log, sizeof(log),
                         "gno-sc[%s]: double_sign_refused %.*s t=%d h=%lld r=%d",
                         label, cid_show, chain_id, (int)type,
                         (long long)height, (int)round);
                os_console_log(log);
                resp_len = gno_privval_encode_sign_response_error(
                    "double_sign_refused", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            if (sa_rc != 0) {
                os_console_log("gno-sc: s_sign_and_advance failed");
                return -1;
            }
#else
            if (!hwm_advance(c->hwm_slot_idx, chain_id, chain_id_len,
                             type, height, round)) {
                char log[96];
                int cid_show = (int)(chain_id_len > 20 ? 20 : chain_id_len);
                snprintf(log, sizeof(log),
                         "gno-sc[%s]: double_sign_refused %.*s t=%d h=%lld r=%d",
                         label, cid_show, chain_id, (int)type,
                         (long long)height, (int)round);
                os_console_log(log);
                resp_len = gno_privval_encode_sign_response_error(
                    "double_sign_refused", resp_plain, sizeof(resp_plain));
                if (!resp_len) return -1;
                goto emit_response;
            }
            if (os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                               sign_bytes, sign_len, sig) != 0) {
                os_console_log("gno-sc: os_crypto_sign failed");
                return -1;
            }
#endif
            resp_len = gno_privval_encode_sign_response(
                sig, resp_plain, sizeof(resp_plain));
            if (!resp_len) {
                os_console_log("gno-sc: encode sign_resp failed");
                return -1;
            }
            char log[96];
            int cid_show = (int)(chain_id_len > 20 ? 20 : chain_id_len);
            snprintf(log, sizeof(log), "gno-sc[%s]: signed %.*s t=%d h=%lld r=%d",
                     label, cid_show, chain_id, (int)type,
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
        if (push_bytes(c->pcb, sealed, SC_SEALED_FRAME_SIZE, label) != 0) {
            return -1;
        }

        c->rx_got  = 0;
        c->rx_need = SC_SEALED_FRAME_SIZE;
        return 0;
    }

    return 0;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)err;
    gno_chain_t *c = (gno_chain_t *)arg;
    if (!p) {
        char log[64];
        snprintf(log, sizeof(log), "gno-sc[%s]: peer closed", c->slot->label);
        os_console_log(log);
        tcp_close(pcb);
        reset_conn_state(c);
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
                reset_conn_state(c);
                return ERR_ABRT;
            }
        }
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)err;
    gno_chain_t *c = (gno_chain_t *)arg;
    if (c->connected) {
        char log[64];
        snprintf(log, sizeof(log),
                 "gno-sc[%s]: refusing second connection", c->slot->label);
        os_console_log(log);
        tcp_close(pcb);
        return ERR_OK;
    }
    char log[64];
    snprintf(log, sizeof(log), "gno-sc[%s]: client connected", c->slot->label);
    os_console_log(log);
    c->connected = true;
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
        reset_conn_state(c);
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
    memset(g_chains, 0, sizeof(g_chains));
    size_t configured = 0;
    for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
        const chain_slot_t *slot = chains_get(CHAINS_FAMILY_GNO, i);
        if (!slot->in_use) continue;

        struct tcp_pcb *pcb = tcp_new();
        if (!pcb) continue;
        if (tcp_bind(pcb, IP_ADDR_ANY, slot->port) != ERR_OK) {
            char log[80];
            snprintf(log, sizeof(log),
                     "gno-sc[%s]: tcp_bind port %u failed",
                     slot->label, (unsigned)slot->port);
            os_console_log(log);
            continue;
        }
        struct tcp_pcb *lpcb = tcp_listen(pcb);
        if (!lpcb) {
            char log[80];
            snprintf(log, sizeof(log),
                     "gno-sc[%s]: tcp_listen port %u failed",
                     slot->label, (unsigned)slot->port);
            os_console_log(log);
            continue;
        }
        g_chains[i].slot         = slot;
        g_chains[i].hwm_slot_idx = chains_hwm_slot_idx(CHAINS_FAMILY_GNO, i);
        g_chains[i].lpcb         = lpcb;
        tcp_arg(lpcb,    &g_chains[i]);
        tcp_accept(lpcb, on_accept);
        configured++;

        char log[80];
        snprintf(log, sizeof(log),
                 "gno-sc[%s]: listening on port %u",
                 slot->label, (unsigned)slot->port);
        os_console_log(log);
    }
    char b[48];
    snprintf(b, sizeof(b), "gno-sc: %zu chain(s) configured", configured);
    os_console_log(b);
}
