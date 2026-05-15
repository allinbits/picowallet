// Host-side verification harness for firmware/src/os/crypto/keccak.c.
// Builds with: cc tools/test_keccak.c firmware/src/os/crypto/keccak.c -o test_keccak
// Verifies SHA3-256("") against the FIPS 202 test vector.

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../firmware/src/os/crypto/keccak.h"

int main(void) {
    uint64_t state[25] = {0};

    // SHA3-256 padding for an empty message: 0x06 in the first byte, 0x80
    // in byte 135 (the last byte of the 1088-bit rate region).
    state[0]  ^= 0x06ULL;
    state[16] ^= 0x80ULL << 56;

    keccak_f1600(state);

    // First 32 bytes of state (4 lanes, little-endian).
    uint8_t out[32];
    for (int i = 0; i < 4; i++) {
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(state[i] >> (8 * b));
        }
    }

    static const uint8_t expected[32] = {
        0xa7,0xff,0xc6,0xf8, 0xbf,0x1e,0xd7,0x66,
        0x51,0xc1,0x47,0x56, 0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d, 0xe4,0x3b,0x49,0xfa,
        0x82,0xd8,0x0a,0x4b, 0x80,0xf8,0x43,0x4a,
    };

    printf("SHA3-256(\"\") = ");
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    printf("expected      = ");
    for (int i = 0; i < 32; i++) printf("%02x", expected[i]);
    printf("\n");

    if (memcmp(out, expected, 32) != 0) {
        printf("FAIL\n");
        return 1;
    }
    printf("PASS\n");
    return 0;
}
