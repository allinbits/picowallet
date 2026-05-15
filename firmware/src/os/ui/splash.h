#pragma once

// Render the boot splash to the e-paper. Performs a full clean refresh so
// the panel ends in a known state. Blocks until refresh completes (~9 s).
void splash_render(void);
