#include <stdbool.h>

#include "pico/time.h"

#include "os/ui/factory_reset.h"
#include "os/hal/input.h"
#include "os/api.h"
#include "os/ui/console.h"
#include "os/storage/chains.h"
#include "os/storage/hwm_flash.h"

static const char CONFIRM_SCREEN[] =
    "FACTORY RESET\n\n"
    "This erases ALL chain "
    "config slots and HWM "
    "state.\n\n"
    "The validator key is NOT "
    "affected.\n\n"
    "LEFT to cancel, "
    "RIGHT to confirm.";

bool factory_reset_confirm(void) {
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
