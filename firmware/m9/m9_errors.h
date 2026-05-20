#pragma once

// Public types live in os/secure_api.h so NS can see the struct shape
// for the s_errors_get veneer. This header only declares the
// Secure-side internal helpers.

#include "os/secure_api.h"

// Increment the per-category counter and update last-error. `msg` may
// be NULL (no message update); the buffer is truncated to fit. Safe
// to call from any Secure-side error path.
void m9_error_log(uint8_t category, const char *msg);

// Copy the current state into `out`.
void m9_error_get(m9_error_state_t *out);

// Zero all counters + clear last-error.
void m9_error_reset(void);
