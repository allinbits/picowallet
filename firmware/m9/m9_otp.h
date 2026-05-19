#pragma once
#include <stddef.h>
#include <stdint.h>

// M9.5 Phase 7.5: per-device OTP secret. A 32-byte value written into a
// fixed OTP row at first KEK derivation, then mixed into the Argon2id
// input alongside the PIN. Pinning the KEK to the chip means a flash
// dump alone can't be brute-forced offline -- the attacker also needs
// chip-level access.
//
// Implementation lives in firmware/m9/m9_otp.c and is Secure-only.
// ACCESSCTRL_OTP is locked Secure-only (Phase 4), and the OTP row used
// here is unreadable from NS.

#define M9_OTP_DEVICE_SECRET_LEN  32u

// Returns 0 on success and fills `out` with the device secret.
// If the OTP row is blank, generates a fresh random secret from TRNG
// and burns it (one-time). Subsequent calls read back the same value.
// Non-zero return indicates a bootrom failure; caller should bail.
int m9_otp_get_device_secret(uint8_t out[M9_OTP_DEVICE_SECRET_LEN]);
