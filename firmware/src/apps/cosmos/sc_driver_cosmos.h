#pragma once

// Install per-chain dialers for cometbft's SecretConnection handshake
// (Merlin variant). One outbound dialer is started for each configured
// cosmos chain slot (see os/storage/chains.h); a slot's port + host come
// from its config. 0 cosmos slots configured = no dialers.
//
// Each dialer connects out to its chain's cometbft `priv_validator_laddr`
// listener. cometbft is the server, the signer is the client.
void cosmos_sc_driver_init(void);

// Main-loop tick. Evaluates each per-slot dial FSM and issues retries.
void cosmos_sc_driver_service(void);
