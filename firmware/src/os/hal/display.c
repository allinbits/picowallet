#include <stdlib.h>
#include <string.h>

#include "os/hal/display.h"

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
