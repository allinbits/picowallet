#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/clocks.h"

#include "os/bench.h"
#include "os/api.h"
#include "os/transport/usb.h"

#include "os/crypto/monocypher.h"
#include "os/crypto/monocypher-ed25519.h"

static void emit(const char *line) {
    usb_cdc_printf("%s\r\n", line);
    os_console_log(line);
}

int bench_ed25519(char *reply, size_t reply_size) {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0xA0 + i);
    uint8_t msg[32];
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)i;

    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t signature[64];

    crypto_ed25519_key_pair(secret_key, public_key, seed);

    const int N = 10000;
    const int PROGRESS = 1000;
    char buf[80];

    uint32_t cpu_hz = clock_get_hz(clk_sys);
    snprintf(buf, sizeof(buf), "clk_sys = %u MHz", (unsigned)(cpu_hz / 1000000u));
    emit(buf);
    usb_cdc_printf("running %d sign + %d verify iters (may take ~2 min)...\r\n", N, N);

    uint64_t t0 = time_us_64();
    for (int i = 0; i < N; i++) {
        crypto_ed25519_sign(signature, secret_key, msg, sizeof(msg));
        if ((i + 1) % PROGRESS == 0) usb_cdc_printf("  sign   %d/%d\r\n", i + 1, N);
    }
    uint64_t t1 = time_us_64();
    uint64_t sign_total = t1 - t0;

    uint64_t t2 = time_us_64();
    int ok = 0;
    for (int i = 0; i < N; i++) {
        if (crypto_ed25519_check(signature, public_key, msg, sizeof(msg)) == 0) ok++;
        if ((i + 1) % PROGRESS == 0) usb_cdc_printf("  verify %d/%d\r\n", i + 1, N);
    }
    uint64_t t3 = time_us_64();
    uint64_t verify_total = t3 - t2;

    snprintf(buf, sizeof(buf), "ed25519 sign:   %u us avg",
             (unsigned)(sign_total / (uint64_t)N));
    emit(buf);
    snprintf(buf, sizeof(buf), "ed25519 verify: %u us avg",
             (unsigned)(verify_total / (uint64_t)N));
    emit(buf);
    snprintf(buf, sizeof(buf), "verify ok: %d/%d", ok, N);
    emit(buf);

    snprintf(reply, reply_size, "bench_done iters=%d", N);
    return 0;
}
