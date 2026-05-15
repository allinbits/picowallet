#pragma once

#define DISPLAY_WIDTH  480
#define DISPLAY_HEIGHT 280

void display_init(void);
void display_clear(void);
void display_render_full(void);   // fast: panel does an image refresh from current state
void display_render_clean(void);  // slow: full clear cycle then image refresh -- removes ghosting
