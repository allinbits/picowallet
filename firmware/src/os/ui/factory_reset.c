#include <stdbool.h>

#include "os/ui/factory_reset.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD

// NS side: keep the long-hold trigger state machine local (it polls
// input_pressed which is already veneered through s_input_pressed),
// but route the confirm UI + flash wipe entirely through the Secure
// image. NS cannot influence what text the user sees on the confirm
// screen -- it is baked into the Secure binary.

#include "pico/time.h"

#include "os/hal/input.h"
#include "os/secure_api.h"
#include "os/storage/chains.h"
#include "os/storage/hwm_flash.h"

bool factory_reset_confirm(void) {
    bool ok = s_factory_reset_with_consent();
    if (ok) {
        // Repopulate NS's RAM caches from flash so they converge with
        // Secure's (now-empty) caches. Without this, NS's stale slot
        // table would survive the wipe.
        chains_init();
        hwm_init();
    }
    return ok;
}

void factory_reset_check_trigger(void) {
    static bool             active = false;
    static absolute_time_t  since;

    bool both = input_pressed(INPUT_BTN_LEFT)
             && input_pressed(INPUT_BTN_RIGHT);
    if (!both) {
        active = false;
        return;
    }
    if (!active) {
        active = true;
        since  = get_absolute_time();
        return;
    }
    int64_t held_us = absolute_time_diff_us(since, get_absolute_time());
    if (held_us < (int64_t)FACTORY_RESET_HOLD_MS * 1000) return;

    // Threshold reached. Clear the trigger so we don't re-fire while the
    // operator is still holding the buttons after the confirm flow ends.
    active = false;
    factory_reset_confirm();
}

#else

// Secure build (or pre-TZ single-image build): the actual confirm UI +
// flash wipe lives here. Under PICOWALLET_SECURE_BUILD this is invoked
// from the s_factory_reset_with_consent veneer body. The trigger
// detector (factory_reset_check_trigger) is NS-only and not compiled
// into the Secure image.

#include "os/api.h"
#include "os/ui/console.h"
#include "os/storage/chains.h"
#include "os/storage/hwm_flash.h"
#if PICOWALLET_SECURE_BUILD
#include <stdio.h>
#include "pico/time.h"               // sleep_ms
#include "hardware/watchdog.h"
#include "os/hal/input.h"            // INPUT_BTN_LEFT/RIGHT, input_pressed
#include "os/storage/seed_flash.h"   // m9_factory_wipe_all (Phase 7.2)
#include "os/ui/pin_ui.h"            // pin_ui_show_status (Secure side)
#endif

bool factory_reset_confirm(void) {
#if PICOWALLET_SECURE_BUILD
    // The 5-second both-button hold that summoned us is the consent
    // gesture (FACTORY_RESET_HOLD_MS in factory_reset.h). Instead of a
    // second confirm screen -- which has its own button-input UX
    // hazards on top of an already-deliberate gesture -- show a
    // 3-second cancel-window countdown. If the operator releases either
    // button before the count expires, we bail. Otherwise wipe and
    // reboot.
    for (int i = 3; i >= 1; i--) {
        char msg[24];
        snprintf(msg, sizeof(msg), "WIPE in %d", i);
        pin_ui_show_busy(msg);
        // Sample at 50ms over the 1-sec window so a release cancels
        // promptly.
        for (int j = 0; j < 20; j++) {
            if (!input_pressed(INPUT_BTN_LEFT) ||
                !input_pressed(INPUT_BTN_RIGHT)) {
                pin_ui_show_status("Cancelled");
                return false;
            }
            sleep_ms(50);
        }
    }
    pin_ui_show_status("Wiping...");
    m9_factory_wipe_all();
    pin_ui_show_status("Wiped - rebooting");
    // After wipe the device has no PIN, no seed, no chains. Reboot so
    // the boot path lands on the PIN-setup + mnemonic-generate flow.
    watchdog_reboot(0, 0, 0);
    while (1) { __asm__ volatile("wfi"); }
#else
    // Pre-TZ: keep the confirm-screen flow (still uses os_display_confirm).
    static const char CONFIRM_SCREEN[] =
        "FACTORY RESET\n\n"
        "Erases chain config "
        "and HWM state.\n\n"
        "LEFT to cancel, "
        "RIGHT to confirm.";
    const char *screens[1] = { CONFIRM_SCREEN };
    os_confirm_t r = os_display_confirm(screens, 1);
    if (r != OS_CONFIRM_ACCEPTED) {
        os_console_log("factory reset: cancelled");
        return false;
    }
    chains_wipe();
    hwm_flash_wipe();
    os_console_log("factory reset: chains + HWM wiped");
    return true;
#endif
}

#if !PICOWALLET_TRUSTZONE
// Pre-TZ single-image: trigger detector lives here too. Under TZ it's
// in the NS branch above so it can poll the veneered input without
// crossing the boundary on every iteration.
#include "pico/time.h"
#include "os/hal/input.h"

void factory_reset_check_trigger(void) {
    static bool             active = false;
    static absolute_time_t  since;

    bool both = input_pressed(INPUT_BTN_LEFT)
             && input_pressed(INPUT_BTN_RIGHT);
    if (!both) {
        active = false;
        return;
    }
    if (!active) {
        active = true;
        since  = get_absolute_time();
        return;
    }
    int64_t held_us = absolute_time_diff_us(since, get_absolute_time());
    if (held_us < (int64_t)FACTORY_RESET_HOLD_MS * 1000) return;
    active = false;
    factory_reset_confirm();
}
#endif

#endif  // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
