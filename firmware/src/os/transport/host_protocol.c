#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "pico/stdlib.h"

#include "os/transport/host_protocol.h"
#include "os/transport/usb.h"
#include "os/app_registry.h"
#include "os/api.h"
#include "os/ui/console.h"
#include "os/hal/input.h"
#include "os/bench.h"
#include "os/crypto/keystore.h"
#include "os/mode.h"
#include "os/storage/chains.h"
#include "os/storage/hwm_flash.h"
#include "os/ui/factory_reset.h"

#if PICOWALLET_TRUSTZONE
#include "os/secure_api.h"
#include "os/storage/seed_flash.h"   // M9_PIN_* status codes + constants
#endif

#define LED_PIN PICO_DEFAULT_LED_PIN
#define REPLY_BUF 160

// Set by os.refresh to request a clean (multi-pass) render at end of dispatch.
static bool wanted_clean_refresh = false;

// Strict integer parse for slot indices etc. atoi("abc") silently
// returns 0, which would land slot commands on slot 0 instead of
// rejecting. Require the whole string to be digits, no leading
// whitespace, and value in [lo..hi]. Returns 0 on success.
static int parse_int_range(const char *s, int lo, int hi, int *out) {
    if (!s || !*s) return -1;
    char *endp;
    long val = strtol(s, &endp, 10);
    if (endp == s || *endp != '\0')  return -1;   // not entirely numeric
    if (val < (long)lo || val > (long)hi) return -1;
    *out = (int)val;
    return 0;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode a hex string into bytes. Returns 0 on success and sets *out_len.
static int hex_decode(const char *hex, uint8_t *out, size_t out_size, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)  return -1;
    size_t n = hex_len / 2;
    if (n > out_size)      return -2;
    for (size_t i = 0; i < n; i++) {
        int h = hex_nibble(hex[2*i]);
        int l = hex_nibble(hex[2*i + 1]);
        if (h < 0 || l < 0) return -3;
        out[i] = (uint8_t)((h << 4) | l);
    }
    *out_len = n;
    return 0;
}

static void hex_encode(const uint8_t *bytes, size_t n, char *out) {
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]     = HEX[bytes[i] >> 4];
        out[i*2 + 1] = HEX[bytes[i] & 0xF];
    }
    out[n*2] = '\0';
}

static void reply_ok(const char *payload) {
    if (payload && *payload) {
        usb_cdc_printf("ok %s\r\n", payload);
        char buf[REPLY_BUF];
        snprintf(buf, sizeof(buf), "ok %s", payload);
        os_console_log(buf);
    } else {
        usb_cdc_printf("ok\r\n");
        os_console_log("ok");
    }
}

static void reply_err(const char *reason) {
    if (reason && *reason) {
        usb_cdc_printf("err %s\r\n", reason);
        char buf[REPLY_BUF];
        snprintf(buf, sizeof(buf), "err %s", reason);
        os_console_log(buf);
    } else {
        usb_cdc_printf("err\r\n");
        os_console_log("err");
    }
}

void host_protocol_print_help(void) {
    usb_cdc_printf("OS commands (os.*):\r\n");
    usb_cdc_printf("  info                                   firmware version + SDK\r\n");
    usb_cdc_printf("  ping                                   liveness check\r\n");
    usb_cdc_printf("  mode                                   current mode (TMKMS/PrivVal)\r\n");
    usb_cdc_printf("  apps                                   list installed apps\r\n");
    usb_cdc_printf("  refresh                                queue a full e-paper refresh\r\n");
    usb_cdc_printf("  clear                                  clear on-device console history\r\n");
    usb_cdc_printf("  led on|off                             LED control\r\n");
    usb_cdc_printf("  btn                                    read button state\r\n");
    usb_cdc_printf("  pubkey <curve> [<path>]                derive pubkey (curve: ed25519|secp256k1; path defaults to m)\r\n");
#if !PICOWALLET_TRUSTZONE
    usb_cdc_printf("  sign <curve> <path> <hex_data>         sign raw bytes\r\n");
#endif
    usb_cdc_printf("  bench ed25519                          on-device sign+verify benchmark\r\n");
#if PICOWALLET_TRUSTZONE
    usb_cdc_printf("  seal_selftest <pin>                    M9.5 seal/unseal smoke test (4-16 chars)\r\n");
    usb_cdc_printf("  pin_status                             initialized + failed-attempt count\r\n");
    usb_cdc_printf("  slot_list                              dump all 16 slots (family/label/chain_id/source)\r\n");
    usb_cdc_printf("  errors                                 per-category counters + last error message\r\n");
    usb_cdc_printf("  errors_reset                           zero the counters (keeps boot_seq)\r\n");
    usb_cdc_printf("  slot_source <0..15>                    slot's seed source (DERIVED/MNEMONIC/RAW_KEY)\r\n");
    usb_cdc_printf("  slot_mnemonic <0..15>                  set slot mnemonic via on-device UI\r\n");
    usb_cdc_printf("  slot_import <0..15> <64-hex>           import 32B Ed25519 priv-key for slot\r\n");
    usb_cdc_printf("  slot_clear <0..15>                     drop slot override -> DERIVED\r\n");
#endif
    usb_cdc_printf("  cosmos.chain.add <label> <chain_id> <host> <port> [<pubkey_hex>]\r\n");
    usb_cdc_printf("  cosmos.chain.remove <label>\r\n");
    usb_cdc_printf("  cosmos.chain.list\r\n");
    usb_cdc_printf("  gno.chain.add <label> <chain_id> <port> [<pubkey_hex>]\r\n");
    usb_cdc_printf("  gno.chain.remove <label>\r\n");
    usb_cdc_printf("  gno.chain.list\r\n");
    usb_cdc_printf("  chain.wipe                             erase all chain config slots\r\n");
    usb_cdc_printf("  hwm.list                               per-slot HWM state + sign count\r\n");
    usb_cdc_printf("  hwm.wipe                               erase all HWM state\r\n");
    usb_cdc_printf("  metrics                                uptime, active slots, total signs\r\n");
    usb_cdc_printf("  factory_reset                          confirm-then-wipe chains + HWM\r\n");
    usb_cdc_printf("                                         (also: hold both buttons 5 s in TMKMS)\r\n");
    usb_cdc_printf("  help                                   show this message\r\n");
    usb_cdc_printf("\r\nApp commands (<app>.<cmd>):\r\n");
    usb_cdc_printf("  cosmos.info, cosmos.ping\r\n");
    usb_cdc_printf("  gnoland.info, gnoland.ping\r\n");
}

static int dispatch_os(const char *cmd, const char *args,
                       char *reply, size_t reply_size) {
    if (strcmp(cmd, "info") == 0) {
        snprintf(reply, reply_size, "PicoWallet RP2350 sdk-%d.%d.%d",
                 PICO_SDK_VERSION_MAJOR,
                 PICO_SDK_VERSION_MINOR,
                 PICO_SDK_VERSION_REVISION);
        return 0;
    }
    if (strcmp(cmd, "help") == 0) {
        host_protocol_print_help();
        snprintf(reply, reply_size, "help");
        return 0;
    }
    if (strcmp(cmd, "ping") == 0) {
        snprintf(reply, reply_size, "pong");
        return 0;
    }
    if (strcmp(cmd, "mode") == 0) {
        snprintf(reply, reply_size, "%s", os_mode_name(os_current_mode));
        return 0;
    }
    if (strcmp(cmd, "apps") == 0) {
        size_t pos = 0;
        reply[0] = '\0';
        for (size_t i = 0; i < app_registry_count(); i++) {
            const app_descriptor_t *a = app_registry_at(i);
            int n = snprintf(reply + pos, reply_size - pos,
                             "%s%s", i ? "," : "", a->name);
            if (n < 0 || pos + (size_t)n >= reply_size) break;
            pos += (size_t)n;
        }
        return 0;
    }
    if (strcmp(cmd, "refresh") == 0) {
        wanted_clean_refresh = true;
        snprintf(reply, reply_size, "queued");
        return 0;
    }
    if (strcmp(cmd, "clear") == 0) {
        console_clear_history();
        snprintf(reply, reply_size, "cleared");
        return 0;
    }
    if (strcmp(cmd, "led") == 0) {
        if (strcmp(args, "on") == 0) {
            gpio_put(LED_PIN, 1);
            snprintf(reply, reply_size, "on");
            return 0;
        }
        if (strcmp(args, "off") == 0) {
            gpio_put(LED_PIN, 0);
            snprintf(reply, reply_size, "off");
            return 0;
        }
        snprintf(reply, reply_size, "led: expected 'on' or 'off'");
        return -1;
    }
    if (strcmp(cmd, "btn") == 0) {
        snprintf(reply, reply_size, "left=%d right=%d",
                 input_pressed(INPUT_BTN_LEFT),
                 input_pressed(INPUT_BTN_RIGHT));
        return 0;
    }
    // ---- Per-chain config: os.{cosmos,gno}.chain.{add,remove,list}, os.chain.wipe
    if (strcmp(cmd, "cosmos.chain.add") == 0
        || strcmp(cmd, "gno.chain.add") == 0) {
        bool is_cosmos = (cmd[0] == 'c');
        chains_family_t fam = is_cosmos ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
        // args: cosmos -> "LABEL CHAIN_ID HOST PORT [PUBKEY_HEX]"
        //       gno    -> "LABEL CHAIN_ID PORT [PUBKEY_HEX]"
        char buf[256];
        strncpy(buf, args, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *saveptr = NULL;
        char *label_s    = strtok_r(buf,  " ", &saveptr);
        char *chain_id_s = strtok_r(NULL, " ", &saveptr);
        char *host_s     = is_cosmos ? strtok_r(NULL, " ", &saveptr) : NULL;
        char *port_s     = strtok_r(NULL, " ", &saveptr);
        char *pubkey_s   = strtok_r(NULL, " ", &saveptr);
        if (!label_s || !chain_id_s || !port_s
            || (is_cosmos && !host_s)) {
            snprintf(reply, reply_size,
                     is_cosmos
                       ? "usage: os.cosmos.chain.add <label> <chain_id> <host> <port> [<pubkey_hex>]"
                       : "usage: os.gno.chain.add <label> <chain_id> <port> [<pubkey_hex>]");
            return -1;
        }
        // Parse port
        unsigned long port_ul = strtoul(port_s, NULL, 10);
        if (port_ul == 0 || port_ul > 65535) {
            snprintf(reply, reply_size, "bad_port: %s", port_s);
            return -1;
        }
        // Parse host (cosmos only)
        uint8_t host_bytes[4] = {0};
        if (is_cosmos) {
            unsigned a, b, c, d;
            if (sscanf(host_s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4
                || a > 255 || b > 255 || c > 255 || d > 255) {
                snprintf(reply, reply_size, "bad_host: %s", host_s);
                return -1;
            }
            host_bytes[0] = (uint8_t)a; host_bytes[1] = (uint8_t)b;
            host_bytes[2] = (uint8_t)c; host_bytes[3] = (uint8_t)d;
        }
        // Parse optional pubkey
        uint8_t pubkey[CHAINS_PUBKEY_LEN];
        const uint8_t *pubkey_ptr = NULL;
        if (pubkey_s) {
            size_t pk_len = 0;
            if (hex_decode(pubkey_s, pubkey, sizeof(pubkey), &pk_len) != 0
                || pk_len != CHAINS_PUBKEY_LEN) {
                snprintf(reply, reply_size, "bad_pubkey (expected 64 hex chars)");
                return -1;
            }
            pubkey_ptr = pubkey;
        }
        int rc = chains_add(fam, label_s, chain_id_s,
                            is_cosmos ? host_bytes : NULL,
                            (uint16_t)port_ul, pubkey_ptr);
        if (rc == 0) {
            snprintf(reply, reply_size, "added");
            return 0;
        }
        snprintf(reply, reply_size,
                 rc == -1 ? "table_full" :
                 rc == -2 ? "duplicate_label" :
                 rc == -3 ? "duplicate_chain_id" :
                            "invalid_args");
        return -1;
    }
    if (strcmp(cmd, "cosmos.chain.remove") == 0
        || strcmp(cmd, "gno.chain.remove") == 0) {
        chains_family_t fam = (cmd[0] == 'c')
            ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
        if (!args || !*args) {
            snprintf(reply, reply_size, "usage: os.%s.chain.remove <label>",
                     (cmd[0] == 'c') ? "cosmos" : "gno");
            return -1;
        }
        if (!chains_remove(fam, args)) {
            snprintf(reply, reply_size, "no_such_label");
            return -1;
        }
        snprintf(reply, reply_size, "removed");
        return 0;
    }
    if (strcmp(cmd, "cosmos.chain.list") == 0
        || strcmp(cmd, "gno.chain.list") == 0) {
        bool is_cosmos = (cmd[0] == 'c');
        chains_family_t fam = is_cosmos ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
        size_t n = chains_count(fam);
        // One line per slot directly to CDC; reply summary at the end.
        // Reply buffer can't hold 8 entries (each is ~150 chars).
        for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
            const chain_slot_t *s = chains_get(fam, i);
            if (!s->in_use) continue;
            char pin[2 + CHAINS_PUBKEY_LEN * 2 + 1];
            if (s->has_pinned_key) {
                pin[0] = ' '; pin[1] = '\0';
                hex_encode(s->pinned_key, CHAINS_PUBKEY_LEN, pin + 1);
            } else {
                pin[0] = '\0';
            }
            if (is_cosmos) {
                usb_cdc_printf("  %s chain_id=%s %u.%u.%u.%u:%u%s%s\r\n",
                               s->label, s->chain_id,
                               s->dial_host[0], s->dial_host[1],
                               s->dial_host[2], s->dial_host[3],
                               (unsigned)s->port,
                               s->has_pinned_key ? " pubkey=" : "",
                               s->has_pinned_key ? pin + 1 : "");
            } else {
                usb_cdc_printf("  %s chain_id=%s port=%u%s%s\r\n",
                               s->label, s->chain_id, (unsigned)s->port,
                               s->has_pinned_key ? " pubkey=" : "",
                               s->has_pinned_key ? pin + 1 : "");
            }
        }
        snprintf(reply, reply_size, "%zu %s chain(s)",
                 n, is_cosmos ? "cosmos" : "gno");
        return 0;
    }
    if (strcmp(cmd, "chain.wipe") == 0) {
        chains_wipe();
        snprintf(reply, reply_size, "wiped");
        return 0;
    }
    if (strcmp(cmd, "hwm.wipe") == 0) {
        hwm_flash_wipe();
        snprintf(reply, reply_size, "hwm wiped");
        return 0;
    }
    if (strcmp(cmd, "factory_reset") == 0) {
        if (factory_reset_confirm()) {
            snprintf(reply, reply_size, "wiped (chains + hwm)");
            return 0;
        }
        snprintf(reply, reply_size, "cancelled");
        return -1;
    }
    if (strcmp(cmd, "metrics") == 0) {
        uint64_t total_signs = 0;
        size_t   active_slots = 0;
        for (int family = 0; family < 2; family++) {
            chains_family_t fam = (family == 0)
                ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
            for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
                const chain_slot_t *s = chains_get(fam, i);
                if (!s->in_use) continue;
                active_slots++;
                total_signs += hwm_sign_count(chains_hwm_slot_idx(fam, i));
            }
        }
        uint32_t uptime_ms = to_ms_since_boot(get_absolute_time());
        uint32_t up_s  = uptime_ms / 1000u;
        uint32_t hh = up_s / 3600u;
        uint32_t mm = (up_s % 3600u) / 60u;
        uint32_t ss = up_s % 60u;
        usb_cdc_printf("uptime:        %lu:%02lu:%02lu (%lu s)\r\n",
                       (unsigned long)hh, (unsigned long)mm,
                       (unsigned long)ss, (unsigned long)up_s);
        usb_cdc_printf("mode:          %s\r\n", os_mode_name(os_current_mode));
        usb_cdc_printf("active slots:  %zu\r\n", active_slots);
        usb_cdc_printf("total signs:   %llu\r\n",
                       (unsigned long long)total_signs);
        snprintf(reply, reply_size, "metrics");
        return 0;
    }
    if (strcmp(cmd, "hwm.list") == 0) {
        // One line per in-use chain config slot, in the same order as
        // os.cosmos.chain.list + os.gno.chain.list.
        static const char *step_name[] = {
            [0]    = "-",        // never signed
            [0x01] = "prevote",
            [0x02] = "precommit",
            [0x20] = "proposal",
        };
        size_t total = 0;
        for (int family = 0; family < 2; family++) {
            chains_family_t fam = (family == 0)
                ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
            const char *fam_name = (family == 0) ? "cosmos" : "gno";
            for (size_t i = 0; i < CHAINS_MAX_PER_FAMILY; i++) {
                const chain_slot_t *s = chains_get(fam, i);
                if (!s->in_use) continue;
                uint8_t hi = chains_hwm_slot_idx(fam, i);
                hwm_state_t st = hwm_current(hi);
                const char *step =
                    ((unsigned)st.type < sizeof(step_name)/sizeof(step_name[0])
                     && step_name[st.type]) ? step_name[st.type] : "?";
                uint64_t signs = hwm_sign_count(hi);
                if (st.height == 0 && st.round == 0 && st.type == 0) {
                    usb_cdc_printf("  %-6s %-16s chain_id=%s (no signs yet)\r\n",
                                   fam_name, s->label, s->chain_id);
                } else {
                    usb_cdc_printf("  %-6s %-16s chain_id=%s "
                                   "h=%lld r=%d t=%s signs=%llu\r\n",
                                   fam_name, s->label, s->chain_id,
                                   (long long)st.height, (int)st.round, step,
                                   (unsigned long long)signs);
                }
                total++;
            }
        }
        snprintf(reply, reply_size, "%zu active slot(s)", total);
        return 0;
    }
    if (strcmp(cmd, "pubkey") == 0) {
        // args: "<curve> <path>"  -- path defaults to "m"
        char curve_buf[16];
        const char *path = "m";
        const char *sp = strchr(args, ' ');
        size_t curve_len = sp ? (size_t)(sp - args) : strlen(args);
        if (curve_len == 0 || curve_len >= sizeof(curve_buf)) {
            snprintf(reply, reply_size, "usage: os.pubkey <curve> [<path>]");
            return -1;
        }
        memcpy(curve_buf, args, curve_len);
        curve_buf[curve_len] = '\0';
        if (sp) path = sp + 1;

        os_curve_t curve;
        if      (strcmp(curve_buf, "ed25519")   == 0) curve = OS_CURVE_ED25519;
        else if (strcmp(curve_buf, "secp256k1") == 0) curve = OS_CURVE_SECP256K1;
        else {
            snprintf(reply, reply_size, "unknown_curve: %s", curve_buf);
            return -1;
        }

        uint8_t pubkey[64];
        size_t  pubkey_len = 0;
        int rc = os_crypto_get_pubkey(curve, path, pubkey, sizeof(pubkey), &pubkey_len);
        if (rc != 0) {
            snprintf(reply, reply_size, "%s", os_crypto_status_str(rc));
            return -1;
        }

        // Hex-encode pubkey into reply
        if (pubkey_len * 2 + 1 > reply_size) {
            snprintf(reply, reply_size, "reply_buffer_too_small");
            return -1;
        }
        static const char HEX[] = "0123456789abcdef";
        for (size_t i = 0; i < pubkey_len; i++) {
            reply[i*2]     = HEX[pubkey[i] >> 4];
            reply[i*2 + 1] = HEX[pubkey[i] & 0xF];
        }
        reply[pubkey_len * 2] = '\0';
        return 0;
    }
#if !PICOWALLET_TRUSTZONE
    // Generic signing oracle for the TMKMS REPL. Under TZ this command
    // is gone: the only NS-reachable signing paths are
    //   - s_sign_sc_challenge: length-locked to 32 bytes (SC challenge),
    //   - s_sign_and_advance:  fuses HWM strict-advance with the sign.
    // A free-form REPL sign would have to be a third veneer that did
    // not enforce HWM, i.e. exactly the s_sign_privval oracle we are
    // retiring. Pre-TZ builds keep the command for debug ergonomics.
    if (strcmp(cmd, "sign") == 0) {
        // args: "<curve> <path> <hex_data>"
        char buf[512];
        strncpy(buf, args, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *curve_s = buf;
        char *sp1 = strchr(curve_s, ' ');
        if (!sp1) { snprintf(reply, reply_size, "usage: os.sign <curve> <path> <hex_data>"); return -1; }
        *sp1 = '\0';
        char *path_s = sp1 + 1;
        char *sp2 = strchr(path_s, ' ');
        if (!sp2) { snprintf(reply, reply_size, "usage: os.sign <curve> <path> <hex_data>"); return -1; }
        *sp2 = '\0';
        char *hex_s = sp2 + 1;

        os_curve_t curve;
        if      (strcmp(curve_s, "ed25519")   == 0) curve = OS_CURVE_ED25519;
        else if (strcmp(curve_s, "secp256k1") == 0) curve = OS_CURVE_SECP256K1;
        else { snprintf(reply, reply_size, "unknown_curve: %s", curve_s); return -1; }

        uint8_t data[256];
        size_t  data_len = 0;
        int dec = hex_decode(hex_s, data, sizeof(data), &data_len);
        if (dec != 0) {
            snprintf(reply, reply_size,
                     dec == -2 ? "hex_too_long" :
                     dec == -3 ? "bad_hex_char" : "odd_hex_len");
            return -1;
        }

        uint8_t sig[64];
        int rc = os_crypto_sign(curve, path_s, data, data_len, sig);
        if (rc != 0) {
            snprintf(reply, reply_size, "%s", os_crypto_status_str(rc));
            return -1;
        }

        if (reply_size < 130) {
            snprintf(reply, reply_size, "reply_buffer_too_small");
            return -1;
        }
        hex_encode(sig, 64, reply);
        return 0;
    }
#endif  // !PICOWALLET_TRUSTZONE
#if PICOWALLET_TRUSTZONE
    if (strcmp(cmd, "slot_mnemonic") == 0) {
        // os.slot_mnemonic <0..15>  -- Secure-side UI picks gen/restore
        int slot_idx;
        if (parse_int_range(args, 0, 15, &slot_idx) != 0) {
            snprintf(reply, reply_size, "usage: os.slot_mnemonic <0..15>");
            return -1;
        }
        int rc = s_slot_setup_mnemonic((uint8_t)slot_idx);
        if (rc == 0) snprintf(reply, reply_size, "ok: slot %d mnemonic set", slot_idx);
        else if (rc == -2) snprintf(reply, reply_size, "FAIL: device locked");
        else               snprintf(reply, reply_size, "FAIL rc=%d", rc);
        return rc == 0 ? 0 : -1;
    }
    if (strcmp(cmd, "slot_import") == 0) {
        // os.slot_import <0..15> <64-hex>
        char buf[200];
        strncpy(buf, args, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *sp = strchr(buf, ' ');
        if (!sp) {
            snprintf(reply, reply_size, "usage: os.slot_import <0..15> <64-hex>");
            return -1;
        }
        *sp = '\0';
        int slot_idx;
        if (parse_int_range(buf, 0, 15, &slot_idx) != 0) {
            snprintf(reply, reply_size, "slot out of range");
            return -1;
        }
        const char *hex = sp + 1;
        if (strlen(hex) != 64) {
            snprintf(reply, reply_size, "expected 64 hex chars (32 bytes)");
            return -1;
        }
        uint8_t key[32];
        size_t  klen = 0;
        if (hex_decode(hex, key, sizeof(key), &klen) != 0 || klen != 32) {
            snprintf(reply, reply_size, "bad hex");
            return -1;
        }
        int rc = s_slot_import_raw_key((uint8_t)slot_idx, key);
        // wipe local copy promptly
        for (size_t i = 0; i < sizeof(key); i++) key[i] = 0;
        if (rc == 0) snprintf(reply, reply_size, "ok: slot %d raw key sealed", slot_idx);
        else if (rc == -2) snprintf(reply, reply_size, "FAIL: device locked");
        else               snprintf(reply, reply_size, "FAIL rc=%d", rc);
        return rc == 0 ? 0 : -1;
    }
    if (strcmp(cmd, "slot_clear") == 0) {
        int slot_idx;
        if (parse_int_range(args, 0, 15, &slot_idx) != 0) {
            snprintf(reply, reply_size, "usage: os.slot_clear <0..15>");
            return -1;
        }
        int rc = s_slot_clear_override((uint8_t)slot_idx);
        if (rc == 0) snprintf(reply, reply_size, "ok: slot %d -> DERIVED", slot_idx);
        else         snprintf(reply, reply_size, "FAIL rc=%d", rc);
        return rc == 0 ? 0 : -1;
    }
    if (strcmp(cmd, "errors") == 0) {
        m9_error_state_t st;
        s_errors_get(&st);
        static const char *const NAMES[] = {
            "hwm_reject", "slot_not_configured", "slot_unseal",
            "pin_bad", "pin_wiped", "seal_fail",
            "sc_handshake", "chain_id_mismatch", "parser",
            "tcp", "internal",
        };
        usb_cdc_printf("boot_seq: %u   total: %u\r\n",
                       (unsigned)st.boot_seq, (unsigned)st.total);
        for (size_t i = 0; i < M9_ERR_CAT_COUNT; i++) {
            if (st.counters[i] != 0) {
                usb_cdc_printf("  %-22s %u\r\n", NAMES[i],
                               (unsigned)st.counters[i]);
            }
        }
        if (st.last_msg[0] != '\0') {
            usb_cdc_printf("last: [%s] %.*s\r\n",
                           (st.last_cat < M9_ERR_CAT_COUNT ? NAMES[st.last_cat] : "?"),
                           (int)M9_ERROR_MSG_MAX, st.last_msg);
        }
        snprintf(reply, reply_size, "ok");
        return 0;
    }
    if (strcmp(cmd, "errors_reset") == 0) {
        s_errors_reset();
        snprintf(reply, reply_size, "ok: errors cleared");
        return 0;
    }
    if (strcmp(cmd, "slot_list") == 0) {
        // One-shot dump of all 16 HWM slots with family / label /
        // chain_id / seed-source. Single-call summary instead of
        // cross-referencing chain.list per family + slot_source per
        // index.
        usb_cdc_printf("slot family   label                chain_id                                  source\r\n");
        usb_cdc_printf("---- -------- -------------------- ----------------------------------------  --------\r\n");
        for (uint8_t i = 0; i < 16; i++) {
            chains_family_t fam = (i < 8) ? CHAINS_FAMILY_COSMOS : CHAINS_FAMILY_GNO;
            size_t          si  = (i < 8) ? i : (size_t)(i - 8);
            const chain_slot_t *cs = chains_get(fam, si);
            uint8_t src = s_slot_seed_source(i);
            const char *src_s = (src == 1) ? "MNEMONIC" : (src == 2) ? "RAW_KEY" : "DERIVED";
            if (cs && cs->in_use) {
                usb_cdc_printf("%-4u %-8s %-20s %-40s  %s\r\n",
                               (unsigned)i,
                               fam == CHAINS_FAMILY_COSMOS ? "cosmos" : "gno",
                               cs->label, cs->chain_id, src_s);
            } else {
                usb_cdc_printf("%-4u %-8s (empty)                                                       %s\r\n",
                               (unsigned)i,
                               fam == CHAINS_FAMILY_COSMOS ? "cosmos" : "gno",
                               src_s);
            }
        }
        snprintf(reply, reply_size, "ok");
        return 0;
    }
    if (strcmp(cmd, "slot_source") == 0) {
        // os.slot_source <0..15>
        int slot_idx;
        if (parse_int_range(args, 0, 15, &slot_idx) != 0) {
            snprintf(reply, reply_size, "usage: os.slot_source <0..15>");
            return -1;
        }
        uint8_t src = s_slot_seed_source((uint8_t)slot_idx);
        const char *name = (src == 1) ? "MNEMONIC"
                         : (src == 2) ? "RAW_KEY"
                                      : "DERIVED";
        snprintf(reply, reply_size, "slot %d: %s", slot_idx, name);
        return 0;
    }
    if (strcmp(cmd, "pin_status") == 0) {
        snprintf(reply, reply_size, "initialized=%d attempts=%u/%u",
                 (int)s_pin_is_initialized(),
                 (unsigned)s_pin_attempts(),
                 (unsigned)M9_PIN_MAX_ATTEMPTS);
        return 0;
    }
    // os.pin_setup / os.pin_unlock dropped in 7.2b: the PIN is now
    // collected on the Secure side via buttons + e-paper. NS has no
    // way to send a PIN to Secure. os.pin_status remains for
    // diagnostic readback (initialized + attempts), which leak no
    // secrets.
    if (strcmp(cmd, "seal_selftest") == 0) {
        // Phase 7.1 smoke test. Operator types a PIN (4-16 chars) and
        // the Secure side round-trips a random 64-byte payload through
        // seal/unseal + verifies wrong-PIN rejection. NS never sees the
        // payload or the derived KEK.
        size_t pin_len = strlen(args);
        if (pin_len < 4 || pin_len > 16) {
            snprintf(reply, reply_size, "usage: os.seal_selftest <pin 4-16 chars>");
            return -1;
        }
        int rc = s_seal_selftest((const uint8_t *)args, pin_len);
        if (rc == 0) {
            snprintf(reply, reply_size, "ok: seal/unseal round-trip + wrong-PIN reject");
            return 0;
        }
        snprintf(reply, reply_size, "FAIL rc=%d", rc);
        return -1;
    }
#endif
    if (strcmp(cmd, "bench") == 0) {
        if (strcmp(args, "ed25519") == 0) {
            return bench_ed25519(reply, reply_size);
        }
        snprintf(reply, reply_size, "bench: unknown target '%s'", args);
        return -1;
    }
    snprintf(reply, reply_size, "unknown_os_cmd: %s", cmd);
    return -1;
}

void host_protocol_dispatch(char *line) {
    // Log the raw input to the on-device console first
    {
        char buf[REPLY_BUF];
        snprintf(buf, sizeof(buf), "> %s", line);
        os_console_log(buf);
    }

    // Empty line: just give a fresh prompt and skip the refresh cycle
    if (line[0] == '\0') {
        usb_cdc_printf("> ");
        return;
    }

    // Split off args at first space (mutates `line`)
    char *args = (char *)"";
    char *sp = strchr(line, ' ');
    if (sp) {
        *sp = '\0';
        args = sp + 1;
    }

    // Split "<app>.<cmd>"
    char *dot = strchr(line, '.');
    if (!dot) {
        reply_err("bad_format: expected <app>.<cmd>");
        goto refresh;
    }
    *dot = '\0';
    const char *app_name = line;
    const char *cmd_name = dot + 1;

    char reply[REPLY_BUF];
    reply[0] = '\0';
    int rc;

    if (strcmp(app_name, "os") == 0) {
        rc = dispatch_os(cmd_name, args, reply, sizeof(reply));
    } else {
        const app_descriptor_t *app = app_registry_find(app_name);
        if (!app) {
            reply_err("no_such_app");
            goto refresh;
        }
        rc = app->handle_cmd(cmd_name, args, reply, sizeof(reply));
    }

    if (rc == 0) {
        reply_ok(reply);
    } else {
        reply_err(reply[0] ? reply : "app_error");
    }

refresh:
    if (wanted_clean_refresh) {
        wanted_clean_refresh = false;
        usb_cdc_printf("(full refresh, ~9 s)...\r\n");
        console_render_clean();
    } else {
        usb_cdc_printf("(refreshing display...)\r\n");
        console_render();
    }
    usb_cdc_printf("> ");
}
