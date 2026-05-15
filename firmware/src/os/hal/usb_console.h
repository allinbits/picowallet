#pragma once
#include <stddef.h>

void usb_console_init(void);

// Polls stdin. If a full line has been received (terminated by \r or \n),
// copies it (without terminator) into `out` and returns its length (>= 0).
// If no line is ready yet, returns -1. Echoes characters and handles backspace.
int usb_console_poll_line(char *out, size_t maxlen);

void usb_console_printf(const char *fmt, ...);
