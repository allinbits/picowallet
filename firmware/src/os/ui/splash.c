#include "os/ui/splash.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD

#include "os/secure_api.h"

void splash_render(void) { s_splash_render(); }

#else

#include <stdint.h>
#include <string.h>

#include "os/ui/splash_image.h"
#include "os/hal/display.h"
#include "os/version.h"

#include "GUI_Paint.h"
#include "fonts.h"

// Stamp a 1-bit packed bitmap (MSB-first, row-major, black=1) at logical
// (x_off, y_off). Walks black pixels only and uses Paint_DrawPoint so the
// existing rotation math handles native-vs-logical layout for us.
static void draw_bitmap(const uint8_t *img, int img_w, int img_h,
                        int x_off, int y_off) {
    int bytes_per_row = (img_w + 7) / 8;
    for (int y = 0; y < img_h; y++) {
        const uint8_t *row = img + y * bytes_per_row;
        for (int byte_x = 0; byte_x < bytes_per_row; byte_x++) {
            uint8_t b = row[byte_x];
            if (b == 0) continue;
            for (int bit = 0; bit < 8; bit++) {
                if (b & (1 << (7 - bit))) {
                    int x = byte_x * 8 + bit;
                    if (x < img_w) {
                        Paint_DrawPoint(x_off + x, y_off + y,
                                        BLACK, DOT_PIXEL_1X1, DOT_STYLE_DFT);
                    }
                }
            }
        }
    }
}

void splash_render(void) {
    display_clear();

    // Center the image vertically; image already 480 px wide so x_off = 0.
    int x_off = (DISPLAY_WIDTH  - SPLASH_IMG_WIDTH)  / 2;
    int y_off = (DISPLAY_HEIGHT - SPLASH_IMG_HEIGHT) / 2;
    draw_bitmap(SPLASH_IMG, SPLASH_IMG_WIDTH, SPLASH_IMG_HEIGHT, x_off, y_off);

    // Build version, small, bottom-right corner.
    const char *build = "build " PICOWALLET_BUILD;
    int build_w = (int)strlen(build) * 7;  // Font12 ~7 px/char
    int build_x = DISPLAY_WIDTH  - build_w - 6;
    int build_y = DISPLAY_HEIGHT - 14;
    Paint_DrawString_EN(build_x, build_y, build, &Font12, WHITE, BLACK);

    display_render_clean();
}

#endif  // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
