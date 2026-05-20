#pragma once
#include <stdbool.h>

void console_init(void);
void console_log(const char *line);
void console_clear_history(void);
void console_render(void);         // fast refresh
void console_render_clean(void);   // slow refresh, removes ghosting

// Scroll the visible window through the history buffer. The buffer
// holds 32 lines; only 10 fit on the e-paper at once. New lines snap
// the view to the bottom, so scroll-back is best-effort and gets
// invalidated by any subsequent push.
void console_scroll_up(void);      // toward older entries
void console_scroll_down(void);    // toward newer entries

// Has any line been appended since the last render? Used by the PrivVal
// main loop to lazily redraw -- a full refresh blocks lwIP ~3 s, so we
// only do it occasionally when there's something new to show.
bool console_is_dirty(void);
