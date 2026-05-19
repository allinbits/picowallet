// M9.5 Phase 7.2b -- Secure-side PIN entry UI (button + e-paper).

#if PICOWALLET_SECURE_BUILD

#include "os/ui/pin_ui.h"

#include <stdio.h>
#include <string.h>

#include "pico/time.h"

#include "os/crypto/bip39.h"         // bip39_check_checksum
#include "os/crypto/bip39_wordlist.h"
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

// --- Phase 7.4: setup-mode chooser + button-driven mnemonic restore -----

int pin_ui_setup_mode(void) {
    // Simple two-option chooser. Left button = restore, right = generate.
    // Inverted on display: "< restore | generate >" so the mapping reads
    // naturally next to the button labels.
    display_clear();
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 60, "First-boot setup", &Font24, WHITE, BLACK);
    Paint_DrawString_EN(8, 110,
                        "How do you want to provision the seed?",
                        &Font16, WHITE, BLACK);
    Paint_DrawString_EN(20, 160, "< RESTORE",  &Font24, WHITE, BLACK);
    Paint_DrawString_EN(260, 160, "GENERATE >", &Font24, WHITE, BLACK);
    Paint_DrawLine(0, 230, DISPLAY_WIDTH - 1, 230, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 246, "LEFT = restore from paper   RIGHT = generate new",
                        &Font16, WHITE, BLACK);
    s_renders_since_full = PIN_UI_FULL_REFRESH_EVERY;
    display_render_full();

    while (1) {
        pin_btn_evt_t e = wait_button();
        if (e == PIN_BTN_LEFT)  return PIN_UI_SETUP_RESTORE;
        if (e == PIN_BTN_RIGHT) return PIN_UI_SETUP_GENERATE;
        // BOTH ignored -- force an explicit pick.
    }
}

#define RESTORE_PREFIX_MAX 4

// Wheel slots used for restore. The letter slots are populated
// dynamically per-prefix from the BIP-39 wordlist -- only letters that
// can actually extend the current prefix to a real word appear. The
// fixed slots (del, pick) live at the end and are only present when
// the prefix is non-empty.
typedef struct {
    char letters[26];   // valid extension letters, alphabetical, no dupes
    int  n_letters;
    bool has_del;       // backspace slot present
    bool has_pick;      // "switch to candidate-pick mode" slot present
} restore_wheel_t;

#define RW_INDEX_DEL(w)  ((w)->n_letters)
#define RW_INDEX_PICK(w) ((w)->n_letters + ((w)->has_del ? 1 : 0))
#define RW_COUNT(w)      ((w)->n_letters + ((w)->has_del ? 1 : 0) + ((w)->has_pick ? 1 : 0))

// Find the contiguous range of BIP-39 wordlist entries that start with
// the typed prefix (the list is alphabetically sorted, so the matches
// form a contiguous slice).
static void find_prefix_range(const char *prefix, int prefix_len,
                              int *out_start, int *out_count) {
    int start = -1;
    int count = 0;
    for (int i = 0; i < BIP39_WORD_COUNT; i++) {
        bool match = (prefix_len == 0) ||
                     (memcmp(bip39_wordlist[i], prefix, (size_t)prefix_len) == 0);
        if (match) {
            if (start < 0) start = i;
            count++;
        } else if (start >= 0) {
            break;
        }
    }
    *out_start = (start >= 0) ? start : 0;
    *out_count = count;
}

// Build the dynamic wheel for the current prefix: enumerate the set of
// distinct letters at position `prefix_len` across the BIP-39 words
// that match the prefix. The list is alphabetical and de-duplicated;
// because the wordlist is alphabetically sorted, identical chars at the
// scan position are contiguous so a single pass suffices.
static void build_restore_wheel(const char *prefix, int prefix_len,
                                int cand_start, int cand_count,
                                restore_wheel_t *out) {
    out->n_letters = 0;
    char last = '\0';
    for (int i = 0; i < cand_count; i++) {
        char c = bip39_wordlist[cand_start + i][prefix_len];
        if (c == '\0') continue;           // word ends exactly here
        if (c == last) continue;           // already added (contiguous)
        out->letters[out->n_letters++] = c;
        last = c;
    }
    // del + pick only make sense after the operator has typed at least
    // one letter. pick is meaningful even at cand_count == 1 (it just
    // immediately confirms), but the auto-advance path already handles
    // that without entering the wheel.
    out->has_del  = (prefix_len > 0);
    out->has_pick = (prefix_len > 0) && (cand_count > 0);
}

static void render_word_typing(int word_num, const char *typed, int typed_len,
                               int candidates,
                               const restore_wheel_t *wheel, int wheel_pos) {
    display_clear();
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    char header[40];
    snprintf(header, sizeof(header), "Word %d of 24", word_num);
    Paint_DrawString_EN(8, 36, header, &Font20, WHITE, BLACK);

    // Typed prefix with dots for unfilled slots
    char shown[16];
    int  i;
    for (i = 0; i < typed_len; i++) shown[i] = typed[i];
    for (     ; i < RESTORE_PREFIX_MAX; i++) shown[i] = '_';
    shown[RESTORE_PREFIX_MAX] = '\0';
    char prefix_line[24];
    snprintf(prefix_line, sizeof(prefix_line), "Typed: %s", shown);
    Paint_DrawString_EN(8, 70, prefix_line, &Font24, WHITE, BLACK);

    char cand_line[24];
    snprintf(cand_line, sizeof(cand_line), "%d match%s",
             candidates, candidates == 1 ? "" : "es");
    Paint_DrawString_EN(8, 110, cand_line, &Font20, WHITE, BLACK);

    char wheel_str[16];
    if (wheel->has_del && wheel_pos == RW_INDEX_DEL(wheel)) {
        snprintf(wheel_str, sizeof(wheel_str), "[ del ]");
    } else if (wheel->has_pick && wheel_pos == RW_INDEX_PICK(wheel)) {
        snprintf(wheel_str, sizeof(wheel_str), "[ pick ]");
    } else if (wheel_pos >= 0 && wheel_pos < wheel->n_letters) {
        snprintf(wheel_str, sizeof(wheel_str), "[ %c ]",
                 wheel->letters[wheel_pos]);
    } else {
        snprintf(wheel_str, sizeof(wheel_str), "[?]");
    }
    Paint_DrawString_EN(8, 150, "Now:", &Font20, WHITE, BLACK);
    Paint_DrawString_EN(120, 150, wheel_str, &Font24, WHITE, BLACK);

    Paint_DrawLine(0, 230, DISPLAY_WIDTH - 1, 230, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 246, "L/R scroll   BOTH commit",
                        &Font16, WHITE, BLACK);
    if (s_renders_since_full >= PIN_UI_FULL_REFRESH_EVERY) {
        display_render_full();
        s_renders_since_full = 0;
    } else {
        display_render_fast();
        s_renders_since_full++;
    }
}

static void render_word_pick(int word_num, const char *typed,
                             int cand_pos, int cand_count, const char *cand) {
    display_clear();
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    char header[40];
    snprintf(header, sizeof(header), "Word %d of 24  pick", word_num);
    Paint_DrawString_EN(8, 36, header, &Font20, WHITE, BLACK);

    char tline[24];
    snprintf(tline, sizeof(tline), "Prefix: %s", typed);
    Paint_DrawString_EN(8, 70, tline, &Font20, WHITE, BLACK);

    char pick[40];
    snprintf(pick, sizeof(pick), "%s  (%d/%d)", cand, cand_pos + 1, cand_count);
    Paint_DrawString_EN(8, 130, pick, &Font24, WHITE, BLACK);

    Paint_DrawLine(0, 230, DISPLAY_WIDTH - 1, 230, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(8, 246, "L/R scroll   BOTH select",
                        &Font16, WHITE, BLACK);
    if (s_renders_since_full >= PIN_UI_FULL_REFRESH_EVERY) {
        display_render_full();
        s_renders_since_full = 0;
    } else {
        display_render_fast();
        s_renders_since_full++;
    }
}

static uint16_t pick_from_candidates(int word_num, const char *typed,
                                     int start, int count) {
    int pos = 0;
    while (1) {
        render_word_pick(word_num, typed, pos, count,
                         bip39_wordlist[start + pos]);
        pin_btn_evt_t e = wait_button();
        if (e == PIN_BTN_LEFT)       pos = (pos + count - 1) % count;
        else if (e == PIN_BTN_RIGHT) pos = (pos + 1)         % count;
        else if (e == PIN_BTN_BOTH)  return (uint16_t)(start + pos);
    }
}

static uint16_t collect_one_word(int word_num) {
    char typed[RESTORE_PREFIX_MAX + 1] = {0};
    int  typed_len = 0;
    int  wheel_pos = 0;

    while (1) {
        int cand_start, cand_count;
        find_prefix_range(typed, typed_len, &cand_start, &cand_count);

        // Auto-advance when the typed prefix uniquely identifies a
        // word: skip the pick step entirely.
        if (typed_len > 0 && cand_count == 1) {
            char msg[40];
            snprintf(msg, sizeof(msg), "Word %d: %s",
                     word_num, bip39_wordlist[cand_start]);
            pin_ui_show_status(msg);
            return (uint16_t)cand_start;
        }

        restore_wheel_t wheel;
        build_restore_wheel(typed, typed_len, cand_start, cand_count, &wheel);
        int wheel_count = RW_COUNT(&wheel);
        if (wheel_count == 0) {
            // Pathological: no extensions and no del/pick. Shouldn't
            // happen in practice -- bail with the first candidate.
            return (uint16_t)cand_start;
        }
        if (wheel_pos >= wheel_count) wheel_pos = 0;

        render_word_typing(word_num, typed, typed_len, cand_count,
                           &wheel, wheel_pos);
        pin_btn_evt_t e = wait_button();
        if (e == PIN_BTN_LEFT) {
            wheel_pos = (wheel_pos + wheel_count - 1) % wheel_count;
        } else if (e == PIN_BTN_RIGHT) {
            wheel_pos = (wheel_pos + 1) % wheel_count;
        } else if (e == PIN_BTN_BOTH) {
            if (wheel.has_del && wheel_pos == RW_INDEX_DEL(&wheel)) {
                if (typed_len > 0) {
                    typed_len--;
                    typed[typed_len] = '\0';
                }
                wheel_pos = 0;
            } else if (wheel.has_pick && wheel_pos == RW_INDEX_PICK(&wheel)) {
                return pick_from_candidates(word_num, typed,
                                            cand_start, cand_count);
            } else if (wheel_pos >= 0 && wheel_pos < wheel.n_letters) {
                if (typed_len < RESTORE_PREFIX_MAX) {
                    typed[typed_len++] = wheel.letters[wheel_pos];
                    typed[typed_len] = '\0';
                }
                wheel_pos = 0;
            }
        }
    }
}

int pin_ui_restore_mnemonic(uint16_t out_words[24]) {
    for (int i = 0; i < 24; i++) {
        out_words[i] = collect_one_word(i + 1);
    }
    if (!bip39_check_checksum(out_words)) {
        pin_ui_show_status("Bad mnemonic - retry");
        return -1;
    }
    return 0;
}

void pin_ui_show_mnemonic(const uint16_t word_indices[24]) {
    // Layout: 4 pages, 6 words each. RIGHT advances; BOTH on the final
    // page confirms the operator has written it down. LEFT is ignored
    // (no "go back"; we don't want the operator skipping forward and
    // then accidentally backing out without seeing each page).
    for (int page = 0; page < 4; page++) {
        display_clear();
        Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
        Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                       DOT_PIXEL_1X1, LINE_STYLE_SOLID);

        char header[40];
        snprintf(header, sizeof(header), "Write down (%d/4)", page + 1);
        Paint_DrawString_EN(8, 36, header, &Font20, WHITE, BLACK);

        for (int i = 0; i < 6; i++) {
            int idx = page * 6 + i;
            char line[24];
            snprintf(line, sizeof(line), "%2d. %s",
                     idx + 1, bip39_wordlist[word_indices[idx]]);
            Paint_DrawString_EN(8, 70 + i * 26, line, &Font20, WHITE, BLACK);
        }

        Paint_DrawLine(0, 230, DISPLAY_WIDTH - 1, 230, BLACK,
                       DOT_PIXEL_1X1, LINE_STYLE_SOLID);
        if (page < 3) {
            Paint_DrawString_EN(8, 246, "RIGHT > next page",
                                &Font16, WHITE, BLACK);
        } else {
            Paint_DrawString_EN(8, 246, "BOTH = confirm written down",
                                &Font16, WHITE, BLACK);
        }
        // Force-full on every page so each one is rendered cleanly --
        // operator MUST read these accurately, no ghosting.
        s_renders_since_full = PIN_UI_FULL_REFRESH_EVERY;
        display_render_full();

        // Wait for the right action: RIGHT to advance pages 0..2, BOTH
        // to confirm on page 3. Other inputs are ignored.
        while (1) {
            pin_btn_evt_t e = wait_button();
            if (page < 3) {
                if (e == PIN_BTN_RIGHT) break;
            } else {
                if (e == PIN_BTN_BOTH)  break;
            }
        }
    }
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
