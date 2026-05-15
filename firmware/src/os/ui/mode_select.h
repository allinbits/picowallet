#pragma once

#include "os/mode.h"

// Render the boot mode-selection screen and block on a button press.
// Returns the chosen mode. Performs a single full-image refresh (not the
// multi-pass clean kind) so transition from the splash is quick.
os_mode_t mode_select_prompt(void);
