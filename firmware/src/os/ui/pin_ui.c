// M9.5 Phase 7.2b -- Secure-side PIN entry UI (button + e-paper).

#if PICOWALLET_SECURE_BUILD

#include "os/ui/pin_ui.h"

#include <stdio.h>
#include <string.h>

#include "pico/time.h"

#include "os/crypto/monocypher.h"   // crypto_wipe
#include "os/hal/display.h"
#include "os/hal/input.h"

#include "GUI_Paint.h"
#include "fonts.h"

// Selection wheel: 0..9, DONE.
#define PIN_SEL_DONE   10
#define PIN_SEL_COUNT  11

// Single-button vs both-button detection. After any edge we wait a
// short window for the second button to come down (debounce + co-press
// detection); if both are seen during the window we emit BOTH,
// otherwise the original single button.
#define PIN_BTN_DEBOUNCE_MS  60
#define PIN_BTN_POLL_MS       5

typedef enum {
    PIN_BTN_NONE = 0,
    PIN_BTN_LEFT,
    PIN_BTN_RIGHT,
    PIN_BTN_BOTH,
} pin_btn_evt_t;

static pin_btn_evt_t wait_button(void) {
    // No leading drain: e-paper refreshes take 300ms-1s and the
    // operator typically presses during the refresh; the drain would
    // make those presses count as "leftover" and discard them. Instead
    // emit on the first observed press (already pressed = OK) and
    // wait for release at the end so the next call starts with all
    // buttons up regardless of how this one returns.
    while (1) {
        bool L = input_pressed(INPUT_BTN_LEFT);
        bool R = input_pressed(INPUT_BTN_RIGHT);
        if (L || R) {
            sleep_ms(PIN_BTN_DEBOUNCE_MS);    // window for both-down
            L = input_pressed(INPUT_BTN_LEFT);
            R = input_pressed(INPUT_BTN_RIGHT);
            pin_btn_evt_t evt = (L && R) ? PIN_BTN_BOTH
                              : L         ? PIN_BTN_LEFT
                                          : PIN_BTN_RIGHT;
            // Wait for release before returning so the next call sees
            // a fresh button state.
            while (input_pressed(INPUT_BTN_LEFT) || input_pressed(INPUT_BTN_RIGHT)) {
                sleep_ms(PIN_BTN_POLL_MS);
            }
            return evt;
        }
        sleep_ms(PIN_BTN_POLL_MS);
    }
}

// Re-baseline the panel every PIN_UI_FULL_REFRESH_EVERY render calls,
// otherwise use the fast partial-LUT path. Each PIN unlock takes ~12
// renders (4 digits * scroll-then-commit + DONE); doing a full at the
// start of the flow and one every 16 partials keeps ghosting in check
// without making the UX feel slow.
#define PIN_UI_FULL_REFRESH_EVERY 16
static int s_renders_since_full;

static void render_entry(const char *header, int n_entered, int cur_sel) {
    display_clear();

    // Header bar
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    // Title
    Paint_DrawString_EN(8, 38, header, &Font24, WHITE, BLACK);

    // PIN display: "* * _ _ _ _ _ _"
    char dots[PIN_UI_MAX_DIGITS * 2 + 1];
    int i;
    for (i = 0; i < PIN_UI_MAX_DIGITS; i++) {
        dots[i * 2]     = (i < n_entered) ? '*' : '_';
        dots[i * 2 + 1] = ' ';
    }
    dots[PIN_UI_MAX_DIGITS * 2] = '\0';
    Paint_DrawString_EN(8, 100, dots, &Font24, WHITE, BLACK);

    // Current selection
    Paint_DrawString_EN(8, 160, "Now:", &Font20, WHITE, BLACK);
    char sel_str[16];
    if (cur_sel == PIN_SEL_DONE) {
        snprintf(sel_str, sizeof(sel_str), "[ DONE ]");
    } else {
        snprintf(sel_str, sizeof(sel_str), "[ %d ]", cur_sel);
    }
    Paint_DrawString_EN(120, 160, sel_str, &Font24, WHITE, BLACK);

    // Footer
    Paint_DrawLine(0, 230, DISPLAY_WIDTH - 1, 230, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 246, "< LEFT  RIGHT >    BOTH = commit",
                        &Font16, WHITE, BLACK);

    if (s_renders_since_full >= PIN_UI_FULL_REFRESH_EVERY) {
        display_render_full();
        s_renders_since_full = 0;
    } else {
        display_render_fast();
        s_renders_since_full++;
    }
}

void pin_ui_show_busy(const char *msg) {
    display_clear();
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 100, msg, &Font24, WHITE, BLACK);
    display_render_full();
}

void pin_ui_show_status(const char *msg) {
    display_clear();
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 100, msg, &Font24, WHITE, BLACK);
    display_render_full();
    sleep_ms(1500);    // hold so operator reads it before the next render
}

int pin_ui_collect(const char *header, char *out_pin, size_t out_size) {
    if (!out_pin || out_size < PIN_UI_MAX_DIGITS + 1) return 0;

    char pin[PIN_UI_MAX_DIGITS + 1];
    memset(pin, 0, sizeof(pin));
    int n = 0;
    int sel = 0;
    // First render of each entry session uses the full LUT to re-baseline
    // the panel after whatever the previous flow (splash, mode_select)
    // left on screen.
    s_renders_since_full = PIN_UI_FULL_REFRESH_EVERY;

    while (1) {
        render_entry(header, n, sel);
        pin_btn_evt_t e = wait_button();
        if (e == PIN_BTN_LEFT) {
            sel = (sel + PIN_SEL_COUNT - 1) % PIN_SEL_COUNT;
        } else if (e == PIN_BTN_RIGHT) {
            sel = (sel + 1) % PIN_SEL_COUNT;
        } else if (e == PIN_BTN_BOTH) {
            if (sel == PIN_SEL_DONE) {
                if (n >= PIN_UI_MIN_DIGITS) break;
                // Too few digits -- ignore the commit, stay on DONE.
            } else {
                if (n < PIN_UI_MAX_DIGITS) {
                    pin[n++] = (char)('0' + sel);
                }
                sel = 0;   // reset wheel for next digit
            }
        }
    }
    pin[n] = '\0';

    memcpy(out_pin, pin, (size_t)n + 1u);
    crypto_wipe(pin, sizeof(pin));
    return n;
}

#endif  // PICOWALLET_SECURE_BUILD
