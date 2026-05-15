// PicoWallet manual TinyUSB descriptors. Replaces pico_stdio_usb's
// auto-generated descriptors so we have control over what the USB device
// exposes (currently CDC only; later this file gains an ECM alternative
// for PrivVal mode).
//
// Based on the SDK's pico_stdio_usb/stdio_usb_descriptors.c with the
// RPi-reset interface and MS OS descriptors stripped.

#include "tusb.h"
#include "pico/unique_id.h"

#include "os/mode.h"

#define USBD_VID            0x2E8A   // Raspberry Pi
#define USBD_PID            0x0009
#define USBD_MANUFACTURER   "PicoWallet"
#define USBD_PRODUCT        "PicoWallet"

// --- CDC config (used in TMKMS mode) ---
#define CFG_LEN_CDC         (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)
#define ITF_CDC             0
#define ITF_MAX_CDC         2
#define EP_CDC_CMD          0x81
#define EP_CDC_OUT          0x02
#define EP_CDC_IN           0x82
#define CDC_CMD_MAX         8
#define CDC_DATA_MAX        64

// --- ECM config (used in PrivVal mode) ---
#define CFG_LEN_ECM         (TUD_CONFIG_DESC_LEN + TUD_CDC_ECM_DESC_LEN)
#define ITF_ECM             0
#define ITF_MAX_ECM         2
#define EP_ECM_NOTIF        0x83
#define EP_ECM_OUT          0x04
#define EP_ECM_IN           0x84
#define ECM_NOTIF_MAX       64
#define ECM_DATA_MAX        64

#define USBD_STR_0          0
#define USBD_STR_MANUF      1
#define USBD_STR_PRODUCT    2
#define USBD_STR_SERIAL     3
#define USBD_STR_CDC        4
#define USBD_STR_ECM        5
#define USBD_STR_ECM_MAC    6

static const tusb_desc_device_t usbd_desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USBD_VID,
    .idProduct          = USBD_PID,
    .bcdDevice          = 0x0100,
    .iManufacturer      = USBD_STR_MANUF,
    .iProduct           = USBD_STR_PRODUCT,
    .iSerialNumber      = USBD_STR_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t usbd_desc_cfg_cdc[CFG_LEN_CDC] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_MAX_CDC, USBD_STR_0, CFG_LEN_CDC, 0, 250),
    TUD_CDC_DESCRIPTOR(ITF_CDC, USBD_STR_CDC,
                       EP_CDC_CMD, CDC_CMD_MAX,
                       EP_CDC_OUT, EP_CDC_IN, CDC_DATA_MAX),
};

static const uint8_t usbd_desc_cfg_ecm[CFG_LEN_ECM] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_MAX_ECM, USBD_STR_0, CFG_LEN_ECM, 0, 250),
    TUD_CDC_ECM_DESCRIPTOR(ITF_ECM, USBD_STR_ECM, USBD_STR_ECM_MAC,
                           EP_ECM_NOTIF, ECM_NOTIF_MAX,
                           EP_ECM_OUT, EP_ECM_IN, ECM_DATA_MAX,
                           CFG_TUD_NET_MTU),
};

static char usbd_serial_str[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 1];

static const char *const usbd_desc_str[] = {
    [USBD_STR_MANUF]    = USBD_MANUFACTURER,
    [USBD_STR_PRODUCT]  = USBD_PRODUCT,
    [USBD_STR_SERIAL]   = usbd_serial_str,
    [USBD_STR_CDC]      = "PicoWallet CDC",
    [USBD_STR_ECM]      = "PicoWallet ETH",
    // USBD_STR_ECM_MAC is dynamically generated from tud_network_mac_address
    // in tud_descriptor_string_cb. Slot kept here only to size the array.
    [USBD_STR_ECM_MAC]  = NULL,
};

// Required by TinyUSB's ECM/RNDIS class driver. Set to a locally-administered
// MAC (bit 1 of first byte set). The corresponding netif MAC differs by one
// bit and is configured by the lwIP init in Stage 2c step 3.
uint8_t tud_network_mac_address[6] = { 0x02, 0x02, 0x84, 0x6A, 0x96, 0x00 };

const uint8_t *tud_descriptor_device_cb(void) {
    return (const uint8_t *)&usbd_desc_device;
}

const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return (os_current_mode == OS_MODE_PRIVVAL) ? usbd_desc_cfg_ecm : usbd_desc_cfg_cdc;
}

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t desc_str[32];

    if (!usbd_serial_str[0]) {
        pico_get_unique_board_id_string(usbd_serial_str, sizeof(usbd_serial_str));
    }

    uint8_t len;
    if (index == 0) {
        desc_str[1] = 0x0409;  // English (US)
        len = 1;
    } else if (index == USBD_STR_ECM_MAC) {
        // 12 ASCII hex chars, no separators -- per CDC-ECM iMACAddress spec.
        static const char hex[] = "0123456789ABCDEF";
        for (int i = 0; i < 6; i++) {
            desc_str[1 + i*2]     = hex[(tud_network_mac_address[i] >> 4) & 0xF];
            desc_str[1 + i*2 + 1] = hex[(tud_network_mac_address[i]     ) & 0xF];
        }
        len = 12;
    } else {
        if (index >= sizeof(usbd_desc_str) / sizeof(usbd_desc_str[0])) return NULL;
        const char *str = usbd_desc_str[index];
        if (!str) return NULL;
        for (len = 0; len < 31 && str[len]; len++) {
            desc_str[1 + len] = str[len];
        }
    }
    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * len + 2));
    return desc_str;
}
