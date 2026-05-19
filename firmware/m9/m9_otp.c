// M9.5 Phase 7.5 -- per-device OTP secret for KEK derivation.

#include "m9_otp.h"

#include <stdbool.h>
#include <string.h>

#include "pico/bootrom.h"
#include "boot/bootrom_constants.h"

#include "os/crypto/monocypher.h"
#include "trng.h"

// Picked once, permanent for the lifetime of every device. Row 2048
// is the start of OTP page 32 (RP2350 has 64 pages * 64 rows = 4096
// rows; pages 0-7 are reserved by the bootrom for boot/secure-boot
// keys, the rest are user-available). ECC mode packs 16 bits per row,
// so 32 bytes = 16 consecutive ECC rows: 2048..2063.
#define M9_OTP_DEVICE_SECRET_ROW  2048u

// Module-level cache. The OTP secret is invariant for the device's
// lifetime, so reading it once per boot is sufficient.
static bool    s_cached = false;
static uint8_t s_cache[M9_OTP_DEVICE_SECRET_LEN];

static int otp_read_rows(uint8_t *buf, size_t len) {
    otp_cmd_t cmd = { .flags = M9_OTP_DEVICE_SECRET_ROW | OTP_CMD_ECC_BITS };
    return rom_func_otp_access(buf, (uint32_t)len, cmd);
}

static int otp_write_rows(uint8_t *buf, size_t len) {
    otp_cmd_t cmd = {
        .flags = M9_OTP_DEVICE_SECRET_ROW | OTP_CMD_WRITE_BITS | OTP_CMD_ECC_BITS
    };
    return rom_func_otp_access(buf, (uint32_t)len, cmd);
}

int m9_otp_get_device_secret(uint8_t out[M9_OTP_DEVICE_SECRET_LEN]) {
    if (s_cached) {
        memcpy(out, s_cache, M9_OTP_DEVICE_SECRET_LEN);
        return 0;
    }

    uint8_t buf[M9_OTP_DEVICE_SECRET_LEN];
    int rc = otp_read_rows(buf, sizeof(buf));
    if (rc != 0) return rc;

    bool any_set = false;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { any_set = true; break; }
    }

    if (!any_set) {
        // First boot on this chip: generate, burn, re-read to verify.
        m9_trng_fill(buf, sizeof(buf));
        rc = otp_write_rows(buf, sizeof(buf));
        if (rc != 0) {
            crypto_wipe(buf, sizeof(buf));
            return rc;
        }
        rc = otp_read_rows(buf, sizeof(buf));
        if (rc != 0) {
            crypto_wipe(buf, sizeof(buf));
            return rc;
        }
    }

    memcpy(s_cache, buf, sizeof(buf));
    memcpy(out,     buf, sizeof(buf));
    s_cached = true;
    crypto_wipe(buf, sizeof(buf));
    return 0;
}
