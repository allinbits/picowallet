#pragma once

// Install per-chain SecretConnection listeners for gno.land validators.
// One tcp_listen is bound for each configured gno chain slot (see
// os/storage/chains.h); the slot's port determines which port that chain's
// validator should dial. 0 gno slots configured = no listeners bound.
void gno_sc_driver_init(void);
