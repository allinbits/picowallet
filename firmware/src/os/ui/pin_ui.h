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

// Phase 7.4: button-driven restore of an existing 24-word mnemonic.
// Each word is entered via prefix-narrow: type 1-4 letters (a..z, with
// backspace + "done"), with the live count of matching BIP-39 words
// shown after each letter. When the prefix uniquely identifies a word
// (count == 1) the device auto-advances; otherwise the operator hits
// "done" to switch to candidate-pick mode and scrolls through the
// remaining candidates.
//
// Returns 0 on success (and writes the 24 word indices to out_words);
// returns -1 if the final mnemonic fails the BIP-39 checksum -- caller
// is expected to retry from word 1.
int pin_ui_restore_mnemonic(uint16_t out_words[24]);

// Phase 7.4: ask the operator whether to generate a fresh mnemonic or
// restore one from paper. Returns 0 for generate, 1 for restore.
int pin_ui_setup_mode(void);

#define PIN_UI_SETUP_GENERATE 0
#define PIN_UI_SETUP_RESTORE  1
