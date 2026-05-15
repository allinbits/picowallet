#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Allowlist of validator pubkeys this device will sign for. Applies to peers
// reached over an authenticated channel (SecretConnection). Without pinning,
// any peer that can complete the handshake can request signatures -- HWM
// still prevents double-signs at a given (chain, height, round, type) but
// nothing prevents a misbehaving peer from extracting a sig over a vote
// they constructed.
//
// Default state: empty list -> permissive (accept any handshake-authenticated
// peer; caller is expected to log a warning). Once any key is added the list
// becomes strict: only listed peers are accepted.
//
// This module is RAM-only for now. Persistence + provisioning UX is tracked
// separately -- adding keys requires a trusted channel (TMKMS-mode REPL via
// USB CDC, which requires physical access).

#define AUTH_KEYS_MAX           8u
#define AUTH_KEYS_PUBKEY_LEN   32u

void auth_keys_init(void);

// Number of currently-pinned validator pubkeys. 0 means permissive mode.
size_t auth_keys_count(void);

// Add a pubkey to the allowlist. Returns false if already present, full,
// or the input is malformed. Idempotent on duplicates (returns false but
// safe).
bool auth_keys_add(const uint8_t pubkey[AUTH_KEYS_PUBKEY_LEN]);

// Wipe the allowlist (returns to permissive mode).
void auth_keys_clear(void);

// True if `pubkey` is on the allowlist OR the allowlist is empty
// (permissive). Callers that want strict-only behaviour should also check
// auth_keys_count() > 0 to detect the empty/permissive case.
bool auth_keys_check(const uint8_t pubkey[AUTH_KEYS_PUBKEY_LEN]);

// Read the i-th pinned key into `out`. Returns false if i is out of range.
bool auth_keys_get(size_t i, uint8_t out[AUTH_KEYS_PUBKEY_LEN]);
