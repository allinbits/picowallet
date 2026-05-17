#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "pico/stdlib.h"
#include "tusb.h"

#include "os/hal/display.h"
#include "os/hal/input.h"
#include "os/hal/usb_console.h"
#include "os/ui/console.h"
#include "os/ui/splash.h"
#include "os/ui/mode_select.h"
#include "os/app_registry.h"
#include "os/transport/host_protocol.h"
#include "os/transport/usb.h"
#include "os/transport/eth.h"
#include "os/version.h"
#include "os/mode.h"

#include "apps/cosmos/sc_driver_cosmos.h"
#include "apps/gnoland/sc_driver.h"
#include "os/api.h"
#include "os/storage/hwm_flash.h"
#include "os/storage/chains.h"

#define LED_PIN PICO_DEFAULT_LED_PIN

int main(void) {
    // NOTE: usb_init() is deferred until AFTER mode selection so the USB
    // device enumerates with the right descriptor set the first time.

    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    display_init();
    input_init();
    usb_console_init();
    console_init();

    // Boot sequence: splash -> hold -> mode-selection prompt -> main screen.
    splash_render();          // clears + multi-pass refresh, ~9 s
    sleep_ms(4500);           // hold splash on screen

    os_current_mode = mode_select_prompt();

    // Bring USB up now that we know the mode; descriptors will be correct.
    usb_init();

    if (os_current_mode == OS_MODE_PRIVVAL) {
        hwm_init();             // shared per-chain HWM cache across signing apps
        chains_init();          // per-chain config (dial targets, listen ports, pinned keys)
        eth_init();

        // Log the consensus pubkey so it can be reconciled against the
        // chain's genesis (cometbft verifies votes against the genesis
        // pubkey, NOT what the device returns at runtime).
        {
            uint8_t pub[32];
            size_t  pub_len = 0;
            if (os_crypto_get_pubkey(OS_CURVE_ED25519, "m/0'",
                                     pub, sizeof(pub), &pub_len) == 0
                && pub_len == 32) {
                char line[64];
                snprintf(line, sizeof(line),
                         "val: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                         pub[0],  pub[1],  pub[2],  pub[3],
                         pub[4],  pub[5],  pub[6],  pub[7],
                         pub[8],  pub[9],  pub[10], pub[11],
                         pub[12], pub[13], pub[14], pub[15]);
                console_log(line);
                snprintf(line, sizeof(line),
                         "     %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                         pub[16], pub[17], pub[18], pub[19],
                         pub[20], pub[21], pub[22], pub[23],
                         pub[24], pub[25], pub[26], pub[27],
                         pub[28], pub[29], pub[30], pub[31]);
                console_log(line);
            }
        }

        gno_sc_driver_init();       // gno SecretConnection: one listener per gno chain slot
        cosmos_sc_driver_init();    // cometbft SecretConnection+Merlin: one dialer per cosmos chain slot
    }

    int failures = app_registry_init_all();

    // Build the main screen content
    {
        char buf[40];
        snprintf(buf, sizeof(buf), "mode: %s%s", os_mode_name(os_current_mode),
                 os_current_mode == OS_MODE_PRIVVAL ? " (USB-ETH)" : " (USB-CDC)");
        console_log(buf);
    }
    console_log("Installed apps:");
    for (size_t i = 0; i < app_registry_count(); i++) {
        const app_descriptor_t *a = app_registry_at(i);
        char buf[40];
        snprintf(buf, sizeof(buf), "  - %s", a->name);
        console_log(buf);
    }
    if (failures) {
        char buf[40];
        snprintf(buf, sizeof(buf), "[warn] %d app init failure(s)", failures);
        console_log(buf);
    }

    console_render_clean();   // multi-pass refresh into main screen
    sleep_ms(300);

    char line[512];
    bool prev_connected = false;

    while (1) {
        // tud_task is pumped by the 1 kHz timer registered in usb_init.

        if (os_current_mode == OS_MODE_PRIVVAL) {
            // PrivVal: service lwIP -- frames in, TCP responses out. No CDC.
            eth_service();
            cosmos_sc_driver_service(); // dialer retries; no-op in listener mode

            // Lazily refresh the on-device console at most every 10 s,
            // and only when there's something new to draw. Full refresh
            // blocks lwIP for ~3 s, so we keep it rare.
            static uint32_t last_render_ms = 0;
            uint32_t now_ms = to_ms_since_boot(get_absolute_time());
            if (console_is_dirty() && (now_ms - last_render_ms) > 10000) {
                console_render();
                last_render_ms = now_ms;
            }
            continue;
        }

        // TMKMS: text-protocol REPL over CDC.
        // Re-send banner whenever a new host connects (so you don't have to
        // reset the device just because `screen` was started after boot).
        bool now_connected = tud_cdc_connected();
        if (now_connected && !prev_connected) {
            sleep_ms(50);  // let the host settle before sending bytes
            usb_cdc_printf("\r\n=== PicoWallet " PICOWALLET_BUILD " ===\r\n");
            usb_cdc_printf("Mode: %s (admin REPL)\r\n", os_mode_name(os_current_mode));
            usb_cdc_printf("Protocol: <namespace>.<cmd> [args]\r\n\r\n");
            host_protocol_print_help();
            usb_cdc_printf("\r\n> ");
        }
        prev_connected = now_connected;

        int n = usb_console_poll_line(line, sizeof(line));
        if (n >= 0) {
            host_protocol_dispatch(line);
        }
    }
}
