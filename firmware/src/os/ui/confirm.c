#include <stdio.h>
#include <string.h>

#include "os/api.h"
#include "os/hal/display.h"
#include "os/hal/input.h"
#include "os/version.h"

#include "GUI_Paint.h"
#include "fonts.h"

#define BODY_MAX_LINE_LEN 40   // Font16 ~11 px/char -> ~42 per line, keep some slack
#define BODY_LINE_HEIGHT  20
#define BODY_Y_START      48
#define BODY_Y_END        220

// Word-wrap `content` into <= BODY_MAX_LINE_LEN-character lines and render
// them starting at (8, BODY_Y_START), one above the other, Font16.
static void draw_body(const char *content) {
    const char *p = content;
    int y = BODY_Y_START;
    while (*p && y < BODY_Y_END) {
        size_t remaining = strlen(p);
        size_t take;
        if (remaining <= BODY_MAX_LINE_LEN) {
            take = remaining;
        } else {
            take = 0;
            for (size_t i = BODY_MAX_LINE_LEN; i > 0; i--) {
                if (p[i] == ' ') { take = i; break; }
            }
            if (take == 0) take = BODY_MAX_LINE_LEN; // hard break
        }
        char chunk[BODY_MAX_LINE_LEN + 1];
        memcpy(chunk, p, take);
        chunk[take] = '\0';
        Paint_DrawString_EN(8, y, chunk, &Font16, WHITE, BLACK);
        y += BODY_LINE_HEIGHT;
        p += take;
        while (*p == ' ') p++;
    }
}

static void render_screen(int i, int n, const char *content) {
    display_clear();

    // Header: "PicoWallet" left, "<i>/<n>" right
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    char step[16];
    snprintf(step, sizeof(step), "%d/%d", i + 1, n);
    int step_w = (int)strlen(step) * 14;  // Font20 ~14 px/char
    Paint_DrawString_EN(DISPLAY_WIDTH - step_w - 8, 4, step, &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    // Body
    draw_body(content);

    // Footer separator
    Paint_DrawLine(0, 240, DISPLAY_WIDTH - 1, 240, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    // Footer labels
    const char *left_label  = (i == 0)     ? "< DENY"  : "< back";
    const char *right_label = (i == n - 1) ? "ACCEPT >" : "next >";
    Paint_DrawString_EN(8, 252, left_label, &Font20, WHITE, BLACK);
    int right_w = (int)strlen(right_label) * 14;
    Paint_DrawString_EN(DISPLAY_WIDTH - right_w - 8, 252, right_label,
                        &Font20, WHITE, BLACK);

    display_render_full();
}

os_confirm_t os_display_confirm(const char * const *screens, int n_screens) {
    if (n_screens <= 0 || screens == NULL) return OS_CONFIRM_DENIED;

    int idx = 0;
    while (1) {
        render_screen(idx, n_screens, screens[idx]);
        int btn = input_wait_press();
        if (btn == INPUT_BTN_LEFT) {
            if (idx == 0) return OS_CONFIRM_DENIED;
            idx--;
        } else if (btn == INPUT_BTN_RIGHT) {
            if (idx == n_screens - 1) return OS_CONFIRM_ACCEPTED;
            idx++;
        }
    }
}
