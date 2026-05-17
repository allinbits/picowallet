#pragma once
#include <stdbool.h>

// Factory reset UX. Wipes the chain config table (os/storage/chains.h)
// and the entire HWM region (os/storage/hwm_flash.h). The validator
// keystore is NOT touched -- it lives in firmware (and on PIN-protected
// flash once that milestone lands), not in the regions reset here.
//
// Two triggers, both leading through the same confirm screen on the
// e-paper:
//
//   1. Hold both buttons for FACTORY_RESET_HOLD_MS in TMKMS mode.
//      factory_reset_check_trigger() is polled from the TMKMS main loop.
//   2. The `os.factory_reset` REPL command, which calls
//      factory_reset_confirm() directly.
//
// PrivVal-mode signing is too risky for an accidental button press to
// wipe state, so factory_reset_check_trigger() is wired only from the
// TMKMS branch.

#define FACTORY_RESET_HOLD_MS  5000

// Poll buttons; if both have been held continuously for
// FACTORY_RESET_HOLD_MS, run the confirm flow. Cheap when buttons are
// not pressed (one GPIO read per call).
void factory_reset_check_trigger(void);

// Show the confirm screen and, on accept, wipe chains + HWM.
// Returns true if the operator confirmed.
bool factory_reset_confirm(void);
