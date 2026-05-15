#pragma once
#include <stddef.h>
#include <stdint.h>

// ============================================================================
// OS API exposed to apps.
//
// M1 surface (this header): just on-device logging.
// M2 will add: display confirmation flow, crypto primitives, random.
// M5 will move these across the TrustZone boundary as Secure Gateway calls.
// ============================================================================

// Append a line to the on-device console (e-paper). Long lines are wrapped.
void os_console_log(const char *line);

// Display N text screens in sequence with [< back / next >] navigation.
// Each `screens[i]` is one screen of body content (word-wrapped to fit).
// LEFT on the first screen   -> OS_CONFIRM_DENIED.
// RIGHT on the last screen   -> OS_CONFIRM_ACCEPTED.
// LEFT/RIGHT mid-stream navigates between screens.
// Blocks until the user makes a decision.
typedef enum {
    OS_CONFIRM_DENIED   = 0,
    OS_CONFIRM_ACCEPTED = 1,
} os_confirm_t;

os_confirm_t os_display_confirm(const char * const *screens, int n_screens);

// Supported signing curves. Apps and the host protocol agree on these names.
typedef enum {
    OS_CURVE_ED25519   = 0,
    OS_CURVE_SECP256K1 = 1,
} os_curve_t;

// Derive a public key for the given curve and BIP-32 / SLIP-10 path from the
// OS-owned seed. The OS chooses the curve-appropriate derivation scheme
// (SLIP-10 for Ed25519, BIP-32 for secp256k1) and validates the path.
//
// Path syntax: "m" (master) or "m/n[']/n[']/..." with ' meaning hardened.
//
// On success:  returns 0, fills out_pubkey, sets *out_len.
// On failure:  returns a negative status (see keystore_status_t for codes).
int os_crypto_get_pubkey(os_curve_t curve, const char *path,
                         uint8_t *out_pubkey, size_t out_size,
                         size_t *out_len);

const char *os_crypto_status_str(int status);

// Sign `data` with the key derived at `path` for the given curve.
//   - Ed25519:   accepts any length; the curve hashes the message internally.
//                Caller passes the raw message bytes.
//   - secp256k1: requires data_len == 32; the bytes must be the 32-byte
//                hash the caller wants signed (e.g. SHA-256 of a SignDoc).
//
// `out_sig` must point to at least 64 bytes. Signature layout:
//   - Ed25519:   64 bytes R || S
//   - secp256k1: 64 bytes R || S (compact, low-S form, no DER)
//
// On success returns 0; otherwise a negative keystore_status_t.
//
// NOTE: this is a low-level primitive. It does NOT prompt for confirmation.
// Apps that want a user-visible confirmation flow must call
// os_display_confirm first and only call this on accept. The trust
// boundary that enforces confirmation lives at the secure gateway (M5),
// not here.
int os_crypto_sign(os_curve_t curve, const char *path,
                   const uint8_t *data, size_t data_len,
                   uint8_t out_sig[64]);

// --- Future M2 surface ---
// int os_random(uint8_t *out, size_t n);
