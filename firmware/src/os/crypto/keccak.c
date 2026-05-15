// Keccak-f[1600] permutation, FIPS 202 §3.2.
//
// Reference implementation -- not optimized for speed. The whole cometbft
// SecretConnection handshake fits in a handful of permutation invocations,
// so this is not on a hot path.

#include "os/crypto/keccak.h"

// Round constants RC[t] = iota offset for round t. Generated from the LFSR
// described in FIPS 202 §3.2.5.
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Rho rotation offsets: ROTL(lane, RHO[t]) for the t-th step of the
// combined rho-pi loop. Lane 0 (x=0, y=0) doesn't rotate; the other 24
// lanes are visited in pi order.
static const uint8_t RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};

// Pi destination indices: after rotation, the t-th lane in the rho-pi walk
// moves to state[PI[t]]. Starting position is state[1].
static const uint8_t PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1,
};

static inline uint64_t ROTL64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

void keccak_f1600(uint64_t s[25]) {
    for (int round = 0; round < 24; round++) {
        // --- Theta: column-parity diffusion ---
        uint64_t C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        uint64_t D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            s[i] ^= D[i % 5];
        }

        // --- Rho + Pi (combined): rotate lanes and permute positions ---
        // Walk: state[1] -> state[PI[0]] -> state[PI[1]] -> ... -> state[1]
        uint64_t prev = s[1];
        for (int t = 0; t < 24; t++) {
            uint64_t tmp = s[PI[t]];
            s[PI[t]] = ROTL64(prev, RHO[t]);
            prev = tmp;
        }

        // --- Chi: nonlinear S-box on each row ---
        for (int y = 0; y < 25; y += 5) {
            uint64_t t0 = s[y + 0], t1 = s[y + 1], t2 = s[y + 2];
            uint64_t t3 = s[y + 3], t4 = s[y + 4];
            s[y + 0] = t0 ^ ((~t1) & t2);
            s[y + 1] = t1 ^ ((~t2) & t3);
            s[y + 2] = t2 ^ ((~t3) & t4);
            s[y + 3] = t3 ^ ((~t4) & t0);
            s[y + 4] = t4 ^ ((~t0) & t1);
        }

        // --- Iota: XOR round constant into lane 0 ---
        s[0] ^= RC[round];
    }
}
