#pragma once

#define CFG_TUSB_OS         OPT_OS_PICO

#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined
#endif

#ifndef CFG_TUSB_DEBUG
#define CFG_TUSB_DEBUG 0
#endif

#define CFG_TUD_ENABLED     1
#define CFG_TUD_MAX_SPEED   OPT_MODE_DEFAULT_SPEED
#define CFG_TUD_ENDPOINT0_SIZE 64

// Classes -- both CDC and ECM are compiled in. Which one is exposed to the
// host is decided at runtime by tud_descriptor_configuration_cb based on
// os_current_mode (TMKMS -> CDC, PrivVal -> ECM).
#define CFG_TUD_CDC         1
#define CFG_TUD_ECM_RNDIS   1
#define CFG_TUD_NCM         0
#define CFG_TUD_HID         0
#define CFG_TUD_MSC         0
#define CFG_TUD_MIDI        0
#define CFG_TUD_VENDOR      0

// CDC buffer sizes -- 256 each, generous for text protocol
#define CFG_TUD_CDC_RX_BUFSIZE  256
#define CFG_TUD_CDC_TX_BUFSIZE  256

#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN __attribute__((aligned(4)))
#endif
