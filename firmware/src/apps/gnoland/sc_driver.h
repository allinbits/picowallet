#pragma once

// Install the TCP listener that drives the gno.land SecretConnection
// handshake. Mirrors the pattern in apps/cosmos/privval.c. Must be called
// after eth_init() in PrivVal mode.
void gno_sc_driver_init(void);

// Port the listener binds. Distinct from cosmos's 26658 so both apps can be
// installed simultaneously in a build that supports both chain families.
#define GNO_SC_DRIVER_PORT  26659
