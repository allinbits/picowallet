#pragma once

// Install the TCP listener that drives the cometbft SecretConnection
// handshake (Merlin variant). Must be called after eth_init() in PrivVal
// mode. Mirrors apps/gnoland/sc_driver.h.
void cosmos_sc_driver_init(void);

// Port the listener binds. Distinct from 26658 (cosmos plaintext privval)
// and 26659 (gno SecretConnection); the three coexist while we transition.
#define COSMOS_SC_DRIVER_PORT  26660
