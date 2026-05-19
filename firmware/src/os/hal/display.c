#include "os/hal/display.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD

// NS build under M9 TrustZone -- SPI1, the e-paper panel, the framebuffer
// and the Pico_ePaper_Code library all live in the Secure image. NS just
// forwards through the veneers; no paint API is exposed on this side.

#include "os/secure_api.h"

void display_init(void)         { s_display_init(); }
void display_clear(void)        { /* unused on NS under TZ -- canned screens only */ }
void display_render_full(void)  { /* unused on NS under TZ */ }
void display_render_fast(void)  { /* unused on NS under TZ */ }
void display_render_clean(void) { /* unused on NS under TZ */ }

#else

// Secure build (M9 PICOWALLET_SECURE_BUILD=1) OR pre-TZ single-image build.
// Both paths drive the panel directly.

#include <stdlib.h>
#include <string.h>

#include "DEV_Config.h"
#include "EPD_3in7.h"
#include "GUI_Paint.h"

static UBYTE *framebuffer;
static UBYTE *swap_buf;
static UWORD  framebuffer_size;

void display_init(void) {
    DEV_Module_Init();
    EPD_3IN7_1Gray_Init();

    UWORD width_bytes = (EPD_3IN7_WIDTH + 7) / 8;
    framebuffer_size = width_bytes * EPD_3IN7_HEIGHT;
    framebuffer = (UBYTE *)malloc(framebuffer_size);
    swap_buf    = (UBYTE *)malloc(framebuffer_size);
    if (framebuffer == NULL || swap_buf == NULL) {
        while (1) { }
    }
    Paint_NewImage(framebuffer, EPD_3IN7_WIDTH, EPD_3IN7_HEIGHT, 90, WHITE);
    Paint_SelectImage(framebuffer);
    Paint_Clear(WHITE);
}

void display_clear(void) {
    Paint_SelectImage(framebuffer);
    Paint_Clear(WHITE);
}

void display_render_full(void) {
    EPD_3IN7_1Gray_Display(framebuffer);
}

void display_render_fast(void) {
    // Drive the whole panel through the partial-update LUT. Same
    // framebuffer coverage as display_render_full but ~3x faster (the
    // partial LUT skips the deep-clear waveform), at the cost of some
    // ghosting after several cycles. Callers should periodically fall
    // back to display_render_full (or _clean) to refresh the baseline.
    EPD_3IN7_1Gray_Display_Part(framebuffer,
                                0, 0,
                                EPD_3IN7_WIDTH, EPD_3IN7_HEIGHT);
}

void display_render_clean(void) {
    // Multi-pass refresh: black flash, white flash, then real content.
    // Each pass is a full ~2-3 s panel refresh, so the whole thing is visibly
    // dramatic and wipes accumulated ghosting.
    memcpy(swap_buf, framebuffer, framebuffer_size);

    memset(framebuffer, 0x00, framebuffer_size);
    EPD_3IN7_1Gray_Display(framebuffer);

    memset(framebuffer, 0xFF, framebuffer_size);
    EPD_3IN7_1Gray_Display(framebuffer);

    memcpy(framebuffer, swap_buf, framebuffer_size);
    EPD_3IN7_1Gray_Display(framebuffer);
}

#endif  // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
