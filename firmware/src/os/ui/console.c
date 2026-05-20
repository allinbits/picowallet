#include "os/ui/console.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD

#include <string.h>

#include "os/secure_api.h"

void console_init(void)            { s_console_init(); }
void console_clear_history(void)   { s_console_clear_history(); }
void console_render(void)          { s_console_render(); }
void console_render_clean(void)    { s_console_render_clean(); }
bool console_is_dirty(void)        { return s_console_is_dirty(); }
void console_scroll_up(void)       { s_console_scroll_up(); }
void console_scroll_down(void)     { s_console_scroll_down(); }
void console_log(const char *line) {
    if (!line) return;
    s_console_log(line, strlen(line) + 1);
}

#else

#include <stdbool.h>
#include <string.h>

#include "os/hal/display.h"
#include "os/version.h"

#include "GUI_Paint.h"
#include "fonts.h"

// History buffer holds 32 lines; the e-paper shows up to VISIBLE_LINES
// at a time, anchored at `view_top`. New lines snap the view to the
// bottom so fresh logs are always immediately visible; the operator
// can scroll back with the console_scroll_* veneers.
#define MAX_LINES      32
#define MAX_LINE_LEN   40
#define VISIBLE_LINES  10

static char history[MAX_LINES][MAX_LINE_LEN + 1];
static int  n_lines = 0;
static int  view_top = 0;            // first history index rendered
static volatile bool dirty = false;

bool console_is_dirty(void) { return dirty; }

void console_init(void) {
    n_lines  = 0;
    view_top = 0;
}

void console_clear_history(void) {
    n_lines  = 0;
    view_top = 0;
}

// Snap the view so the most-recent line is visible.
static void view_snap_to_bottom(void) {
    view_top = (n_lines > VISIBLE_LINES) ? (n_lines - VISIBLE_LINES) : 0;
}

void console_scroll_up(void) {
    if (view_top == 0) return;
    view_top--;
    dirty = true;
}

void console_scroll_down(void) {
    int max_top = (n_lines > VISIBLE_LINES) ? (n_lines - VISIBLE_LINES) : 0;
    if (view_top >= max_top) return;
    view_top++;
    dirty = true;
}

static void push_one(const char *line) {
    dirty = true;
    if (n_lines < MAX_LINES) {
        strncpy(history[n_lines], line, MAX_LINE_LEN);
        history[n_lines][MAX_LINE_LEN] = '\0';
        n_lines++;
    } else {
        for (int i = 0; i < MAX_LINES - 1; i++) {
            strcpy(history[i], history[i + 1]);
        }
        strncpy(history[MAX_LINES - 1], line, MAX_LINE_LEN);
        history[MAX_LINES - 1][MAX_LINE_LEN] = '\0';
    }
    // New line arrived -- always snap so it's visible; this overrides
    // any previous scroll-back position. Operators scrolling back to
    // read history have to refrain from triggering more log lines.
    view_snap_to_bottom();
}

void console_log(const char *line) {
    const char *p = line;
    while (*p) {
        size_t remaining = strlen(p);
        if (remaining <= MAX_LINE_LEN) {
            push_one(p);
            return;
        }

        // Try to break at the last space at or before MAX_LINE_LEN.
        size_t cut = 0;
        for (size_t i = MAX_LINE_LEN; i > 0; i--) {
            if (p[i] == ' ') { cut = i; break; }
        }
        if (cut == 0) cut = MAX_LINE_LEN;  // no space found -> hard break

        char chunk[MAX_LINE_LEN + 1];
        memcpy(chunk, p, cut);
        chunk[cut] = '\0';
        push_one(chunk);

        p += cut;
        while (*p == ' ') p++;
    }
}

static void paint_framebuffer(void) {
    display_clear();

    // Header: "PicoWallet" left-aligned, "build M1.0.0" right-aligned.
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    {
        const char *build = "build " PICOWALLET_BUILD;
        int w = (int)strlen(build) * 11;          // Font16 = ~11 px/char
        int x = DISPLAY_WIDTH - w - 8;            // 8 px right margin
        Paint_DrawString_EN(x, 8, build, &Font16, WHITE, BLACK);
    }
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    int y = 38;
    int end = view_top + VISIBLE_LINES;
    if (end > n_lines) end = n_lines;
    for (int i = view_top; i < end; i++) {
        Paint_DrawString_EN(8, y, history[i], &Font16, WHITE, BLACK);
        y += 20;
    }
    // Scroll-position hint in the bottom-right if the buffer has more
    // lines than fit on one screen.
    if (n_lines > VISIBLE_LINES) {
        char hint[24];
        snprintf(hint, sizeof(hint), "%d-%d/%d",
                 view_top + 1, end, n_lines);
        int w = (int)strlen(hint) * 11;
        Paint_DrawString_EN(DISPLAY_WIDTH - w - 8, DISPLAY_HEIGHT - 18,
                            hint, &Font16, WHITE, BLACK);
    }
}

void console_render(void) {
    paint_framebuffer();
    display_render_full();
    dirty = false;
}

void console_render_clean(void) {
    paint_framebuffer();
    display_render_clean();
    dirty = false;
}

#endif  // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
