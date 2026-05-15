#pragma once
#include <stddef.h>
#include <stdint.h>

// Initialize TinyUSB device stack with our custom descriptors. Replaces
// the SDK's stdio_init_all() + auto-CDC. Call once at boot.
void usb_init(void);

// Pump the TinyUSB event loop. Call regularly from main().
void usb_task(void);

// Returns the next byte from CDC RX, or -1 if no data is currently buffered.
int usb_cdc_read_byte(void);

// Write up to `len` bytes to CDC TX. Returns the number actually written
// (may be less than `len` if the TX buffer is full). Drops silently if no
// host is connected to CDC.
size_t usb_cdc_write(const void *buf, size_t len);

// printf-style helper that goes straight through CDC, bypassing the SDK's
// pico_stdio --wrap=printf indirection (we don't link a stdio driver).
void usb_cdc_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void usb_cdc_putchar(int c);
