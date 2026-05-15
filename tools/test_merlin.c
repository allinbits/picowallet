// Host-side verification harness for firmware/src/os/crypto/{keccak,strobe,merlin}.c.
// Builds with:
//   cc -Ifirmware/src tools/test_merlin.c \
//      firmware/src/os/crypto/{keccak,strobe,merlin}.c -o test_merlin
//
// Verifies the canonical Merlin test vector from oasisprotocol/curve25519-voi
// (which is what cometbft v0.38+ links against):
//
//   NewTranscript("test protocol")
//     .AppendMessage("some label", "some data")
//     .ExtractBytes("challenge", 32)
//     == d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "os/crypto/merlin.h"

static void hexprint(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void) {
    int fails = 0;

    // ---- Test 1: TestSimpleTranscript ----
    {
        merlin_t t;
        merlin_init(&t, "test protocol");
        merlin_append(&t, "some label", (const uint8_t *)"some data", 9);

        uint8_t buf[32];
        merlin_challenge(&t, "challenge", buf, sizeof(buf));

        static const uint8_t want[32] = {
            0xd5,0xa2,0x19,0x72, 0xd0,0xd5,0xfe,0x32,
            0x0c,0x0d,0x26,0x3f, 0xac,0x7f,0xff,0xb8,
            0x14,0x5a,0xa6,0x40, 0xaf,0x6e,0x9b,0xca,
            0x17,0x7c,0x03,0xc7, 0xef,0xcf,0x06,0x15,
        };

        printf("simple   got : "); hexprint(buf, 32); printf("\n");
        printf("simple   want: "); hexprint(want, 32); printf("\n");
        if (memcmp(buf, want, 32) != 0) { printf("FAIL\n"); fails++; }
        else printf("PASS\n");
    }

    // ---- Test 2: TestComplexTranscript ----
    {
        merlin_t t;
        merlin_init(&t, "test protocol");
        merlin_append(&t, "step1", (const uint8_t *)"some data", 9);

        uint8_t data[1024];
        memset(data, 99, sizeof(data));

        uint8_t chl[32];
        for (int i = 0; i < 32; i++) {
            merlin_challenge(&t, "challenge", chl, sizeof(chl));
            merlin_append(&t, "bigdata", data, sizeof(data));
            merlin_append(&t, "challengedata", chl, sizeof(chl));
        }

        static const uint8_t want[32] = {
            0xa8,0xc9,0x33,0xf5, 0x4f,0xae,0x76,0xe3,
            0xf9,0xbe,0xa9,0x36, 0x48,0xc1,0x30,0x8e,
            0x7d,0xfa,0x21,0x52, 0xdd,0x51,0x67,0x4f,
            0xf3,0xca,0x43,0x83, 0x51,0xcf,0x00,0x3c,
        };

        printf("complex  got : "); hexprint(chl, 32); printf("\n");
        printf("complex  want: "); hexprint(want, 32); printf("\n");
        if (memcmp(chl, want, 32) != 0) { printf("FAIL\n"); fails++; }
        else printf("PASS\n");
    }

    return fails == 0 ? 0 : 1;
}
