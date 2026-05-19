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
#if PICOWALLET_TRUSTZONE
#include "os/storage/seed_flash.h"   // m9_factory_wipe_all (Phase 7.2)
#endif

static const char CONFIRM_SCREEN[] =
    "FACTORY RESET\n\n"
    "This erases ALL chain "
    "config, HWM, and the "
    "stored seed + PIN.\n\n"
    "Restore from your "
    "mnemonic to recover.\n\n"
    "LEFT to cancel, "
    "RIGHT to confirm.";

bool factory_reset_confirm(void) {
    const char *screens[1] = { CONFIRM_SCREEN };
    os_confirm_t r = os_display_confirm(screens, 1);
    if (r != OS_CONFIRM_ACCEPTED) {
        os_console_log("factory reset: cancelled");
        return false;
    }
#if PICOWALLET_TRUSTZONE
    // Single helper wipes SEED + CHAINS + HWM (and the PIN attempt
    // counter, which lives in the SEED sector).
    m9_factory_wipe_all();
#else
    chains_wipe();
    hwm_flash_wipe();
#endif
    os_console_log("factory reset: SEED + chains + HWM wiped");
    return true;
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
