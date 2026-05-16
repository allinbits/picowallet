#pragma once

// Install the TCP driver for the cometbft SecretConnection handshake
// (Merlin variant). Default: TCP listener on COSMOS_SC_DRIVER_PORT.
//
// Built with -DCOSMOS_SC_DIAL_HOST=..., the driver instead DIALS that host
// (cometbft's priv_validator_laddr). In dialer mode init() is non-blocking
// -- the actual outbound connection attempt is driven from the main loop
// by cosmos_sc_driver_service(), which waits for USB enumeration before
// the first SYN. See sc_driver_cosmos.c for the rationale.
void cosmos_sc_driver_init(void);

// Main-loop tick. No-op in listener mode; in dialer mode, evaluates whether
// to issue the next dial (USB up? not currently connected? retry interval
// elapsed?) and does so.
void cosmos_sc_driver_service(void);

// Port the listener binds. Distinct from 26658 (cosmos plaintext privval)
// and 26659 (gno SecretConnection); the three coexist while we transition.
#define COSMOS_SC_DRIVER_PORT  26660
