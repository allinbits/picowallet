#pragma once

// Boot-selected operation mode. Determines the USB stack shape and which
// transport is exposed to the host.
typedef enum {
    OS_MODE_TMKMS   = 0,  // USB CDC (text protocol; current behavior).
    OS_MODE_PRIVVAL = 1,  // USB Ethernet gadget + TCP privval server (Stage 2+).
} os_mode_t;

// The mode the operator picked on this boot. Set once during boot, read-only
// afterwards.
extern os_mode_t os_current_mode;

const char *os_mode_name(os_mode_t m);
