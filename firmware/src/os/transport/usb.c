#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "tusb.h"
#include "pico/time.h"

#include "os/transport/usb.h"

static repeating_timer_t s_tud_task_timer;
static bool tud_task_timer_cb(repeating_timer_t *t) {
    (void)t;
    tud_task();
    return true;
}

void usb_init(void) {
    tud_init(0);
    // tud_task at 1 kHz in the background so USB enumeration completes even
    // while the main thread is blocked in slow e-paper refreshes. Without
    // this macOS times out on control transfers during the ~20 s boot.
    add_repeating_timer_us(-1000, tud_task_timer_cb, NULL, &s_tud_task_timer);
}

// Note: ECM network callbacks (tud_network_recv_cb, tud_network_xmit_cb,
// tud_network_init_cb) live in eth.c with real lwIP-backed implementations.
// They're only invoked in PrivVal mode (when the ECM descriptor is active);
// TMKMS mode never triggers them.

void usb_task(void) {
    tud_task();
}

int usb_cdc_read_byte(void) {
    if (!tud_cdc_available()) return -1;
    char c;
    if (tud_cdc_read(&c, 1) == 1) return (int)(uint8_t)c;
    return -1;
}

size_t usb_cdc_write(const void *buf, size_t len) {
    if (!tud_cdc_connected()) return len;   // pretend success; host not listening
    size_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < len) {
        uint32_t avail = tud_cdc_write_available();
        if (avail == 0) {
            tud_cdc_write_flush();
            tud_task();
            avail = tud_cdc_write_available();
            if (avail == 0) break;  // give up rather than block forever
        }
        size_t to_write = (len - total) < avail ? (len - total) : avail;
        uint32_t w = tud_cdc_write(p + total, to_write);
        total += w;
    }
    tud_cdc_write_flush();
    return total;
}

// printf-compatible wrapper that goes through TinyUSB CDC directly.
// pico_stdio --wrap=printf intercepts the regular printf and dispatches to
// its driver list; that's a different mechanism and not the one we use here.
void usb_cdc_printf(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if ((size_t)n > sizeof(buf)) n = (int)sizeof(buf);
    usb_cdc_write(buf, (size_t)n);
}

void usb_cdc_putchar(int c) {
    char b = (char)c;
    usb_cdc_write(&b, 1);
}
