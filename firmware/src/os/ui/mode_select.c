#include "os/ui/mode_select.h"

#if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD

#include "os/secure_api.h"

os_mode_t mode_select_prompt(void) {
    return (os_mode_t)s_mode_select_prompt();
}

#else

#include <string.h>

#include "os/hal/display.h"
#include "os/hal/input.h"
#include "os/version.h"

#include "GUI_Paint.h"
#include "fonts.h"

os_mode_t mode_select_prompt(void) {
    display_clear();

    // Header (same as main screen)
    Paint_DrawString_EN(8, 4, "PicoWallet", &Font20, WHITE, BLACK);
    {
        const char *build = "build " PICOWALLET_BUILD;
        int w = (int)strlen(build) * 11;
        Paint_DrawString_EN(DISPLAY_WIDTH - w - 8, 8, build, &Font16, WHITE, BLACK);
    }
    Paint_DrawLine(0, 30, DISPLAY_WIDTH - 1, 30, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);

    // Title
    Paint_DrawString_EN(110, 50, "Select operation mode", &Font20, WHITE, BLACK);

    // Left option box
    Paint_DrawRectangle(30, 90, 220, 195, BLACK, DOT_PIXEL_1X1, DRAW_FILL_EMPTY);
    Paint_DrawString_EN(66,  105, "PrivVal",      &Font24, WHITE, BLACK);
    Paint_DrawString_EN(54,  150, "USB-Ethernet", &Font16, WHITE, BLACK);
    Paint_DrawString_EN(82,  173, "gadget",       &Font16, WHITE, BLACK);

    // Right option box
    Paint_DrawRectangle(260, 90, 450, 195, BLACK, DOT_PIXEL_1X1, DRAW_FILL_EMPTY);
    Paint_DrawString_EN(313, 105, "TMKMS",   &Font24, WHITE, BLACK);
    Paint_DrawString_EN(310, 150, "USB-CDC", &Font16, WHITE, BLACK);
    Paint_DrawString_EN(305, 173, "adapter", &Font16, WHITE, BLACK);

    // Footer hints
    Paint_DrawLine(0, 220, DISPLAY_WIDTH - 1, 220, BLACK,
                   DOT_PIXEL_1X1, LINE_STYLE_SOLID);
    Paint_DrawString_EN(20, 240, "< LEFT", &Font20, WHITE, BLACK);
    {
        const char *r = "RIGHT >";
        int w = (int)strlen(r) * 14;
        Paint_DrawString_EN(DISPLAY_WIDTH - w - 20, 240, r, &Font20, WHITE, BLACK);
    }

    display_render_full();

    int btn = input_wait_press();
    return (btn == INPUT_BTN_LEFT) ? OS_MODE_PRIVVAL : OS_MODE_TMKMS;
}

#endif  // PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD
