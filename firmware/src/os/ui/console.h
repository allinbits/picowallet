#pragma once
#include <stdbool.h>

void console_init(void);
void console_log(const char *line);
void console_clear_history(void);
void console_render(void);         // fast refresh
void console_render_clean(void);   // slow refresh, removes ghosting

// Has any line been appended since the last render? Used by the PrivVal
// main loop to lazily redraw -- a full refresh blocks lwIP ~3 s, so we
// only do it occasionally when there's something new to show.
bool console_is_dirty(void);
