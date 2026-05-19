#pragma once
#include <stddef.h>
#include <stdint.h>

// M9.5 Phase 7.2b -- Secure-side PIN entry UI.
//
// Implementation is gated on PICOWALLET_SECURE_BUILD so the symbols
// compile only into picowallet_secure. NS reaches them only through
// the s_pin_setup / s_pin_unlock veneers, which never expose the PIN.

#define PIN_UI_MAX_DIGITS  8
#define PIN_UI_MIN_DIGITS  4

// Render the PIN entry screen with the given header and collect digits
// via the LEFT/RIGHT buttons. Returns the digit count (>= PIN_UI_MIN_DIGITS)
// on success. Operator advances the scroll wheel through 0..9 and a
// DONE token; pressing both buttons commits the current selection. The
// returned `out_pin` is NUL-terminated and contains '0'..'9' digit chars.
int pin_ui_collect(const char *header, char *out_pin, size_t out_size);

// Show a brief "Working..." screen so the operator knows the device
// hasn't hung during the ~3s Argon2id compute.
void pin_ui_show_busy(const char *msg);

// Render a one-screen status (e.g. "PIN mismatch", "Unlocked"); blocks
// briefly so the operator sees the message before the next prompt.
void pin_ui_show_status(const char *msg);

// Phase 7.3: walk the operator through the 24-word mnemonic in four
// 6-word pages, forcing them to advance through each page (RIGHT button)
// and confirm on the final page (BOTH). Used during PIN setup, when a
// fresh mnemonic has just been generated and must be written down.
//
// `word_indices` is the 24-entry index array from bip39_generate.
void pin_ui_show_mnemonic(const uint16_t word_indices[24]);
