#pragma once

#define DISPLAY_WIDTH  480
#define DISPLAY_HEIGHT 280

void display_init(void);
void display_clear(void);
void display_render_full(void);   // ~1s: full-LUT image refresh from current state
void display_render_clean(void);  // ~9s: multi-pass refresh, removes ghosting
void display_render_fast(void);   // ~300ms: partial-LUT refresh (slight ghosting, fine for
                                  // interactive UI like PIN entry between full refreshes)
