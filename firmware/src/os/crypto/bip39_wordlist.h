#pragma once
#include <stddef.h>

// BIP-39 English wordlist exported as a fixed-stride array. Implementation
// is in bip39_wordlist.c (Secure-only). See that file for the rodata
// layout properties this header documents.

#define BIP39_WORD_COUNT    2048
#define BIP39_WORD_MAX_LEN  8

extern const char bip39_wordlist[BIP39_WORD_COUNT][BIP39_WORD_MAX_LEN + 1];
