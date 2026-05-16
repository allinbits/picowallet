#include <string.h>

#include "os/hal/usb_console.h"
#include "os/transport/usb.h"

#include "pico/stdlib.h"

#define LINE_BUF_SIZE 512

static char   line_buf[LINE_BUF_SIZE];
static size_t line_pos = 0;

void usb_console_init(void) {
    // stdio_init_all() is called from main before this; nothing else to do for now.
}

int usb_console_poll_line(char *out, size_t maxlen) {
    int c = usb_cdc_read_byte();
    if (c < 0) {
        return -1;
    }

    if (c == '\r' || c == '\n') {
        usb_cdc_putchar('\r');
        usb_cdc_putchar('\n');
        line_buf[line_pos] = '\0';

        size_t n = line_pos;
        if (n >= maxlen) n = maxlen - 1;
        memcpy(out, line_buf, n);
        out[n] = '\0';

        line_pos = 0;
        return (int)n;
    }

    if (c == 0x7F || c == 0x08) {
        if (line_pos > 0) {
            line_pos--;
            usb_cdc_printf("\b \b");
        }
        return -1;
    }

    if (line_pos < LINE_BUF_SIZE - 1) {
        line_buf[line_pos++] = (char)c;
        usb_cdc_putchar(c);
    }
    return -1;
}
