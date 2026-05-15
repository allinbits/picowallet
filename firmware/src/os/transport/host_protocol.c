#include <stdio.h>
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
#include "os/storage/auth_keys.h"

#define LED_PIN PICO_DEFAULT_LED_PIN
#define REPLY_BUF 160

// Set by os.refresh to request a clean (multi-pass) render at end of dispatch.
static bool wanted_clean_refresh = false;

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

static int dispatch_os(const char *cmd, const char *args,
                       char *reply, size_t reply_size) {
    if (strcmp(cmd, "info") == 0) {
        snprintf(reply, reply_size, "PicoWallet RP2350 sdk-%d.%d.%d",
                 PICO_SDK_VERSION_MAJOR,
                 PICO_SDK_VERSION_MINOR,
                 PICO_SDK_VERSION_REVISION);
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
    if (strcmp(cmd, "auth_list") == 0) {
        size_t n = auth_keys_count();
        if (n == 0) {
            snprintf(reply, reply_size, "0 (permissive)");
            return 0;
        }
        size_t pos = 0;
        int wrote = snprintf(reply + pos, reply_size - pos, "%zu", n);
        if (wrote < 0) return -1;
        pos += (size_t)wrote;
        for (size_t i = 0; i < n && pos + 66 < reply_size; i++) {
            uint8_t pk[AUTH_KEYS_PUBKEY_LEN];
            if (!auth_keys_get(i, pk)) break;
            reply[pos++] = ' ';
            hex_encode(pk, AUTH_KEYS_PUBKEY_LEN, reply + pos);
            pos += AUTH_KEYS_PUBKEY_LEN * 2;
        }
        return 0;
    }
    if (strcmp(cmd, "auth_add") == 0) {
        uint8_t pk[AUTH_KEYS_PUBKEY_LEN];
        size_t  pk_len = 0;
        if (hex_decode(args, pk, sizeof(pk), &pk_len) != 0
            || pk_len != AUTH_KEYS_PUBKEY_LEN) {
            snprintf(reply, reply_size, "usage: os.auth_add <64-hex-pubkey>");
            return -1;
        }
        if (!auth_keys_add(pk)) {
            snprintf(reply, reply_size,
                     "rejected (duplicate, zero, or full)");
            return -1;
        }
        snprintf(reply, reply_size, "added (now %zu)", auth_keys_count());
        return 0;
    }
    if (strcmp(cmd, "auth_clear") == 0) {
        auth_keys_clear();
        snprintf(reply, reply_size, "cleared (back to permissive)");
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
