// Cosmos / Tendermint validator signer app.
//
// Signs CanonicalVote / CanonicalProposal messages for cometbft-class
// chains. Signing logic lives in apps/cosmos/privval.c, driven by the
// per-chain SC dialer in apps/cosmos/sc_driver_cosmos.c. This file is
// the OS-facing app descriptor + the small TMKMS-REPL command surface.

#include <string.h>
#include <stdio.h>

#include "apps/cosmos/app.h"
#include "os/api.h"

static int cosmos_init(void) {
    return 0;
}

static int cosmos_handle_cmd(const char *cmd, const char *args,
                             char *reply, size_t reply_size) {
    (void)args;
    if (strcmp(cmd, "ping") == 0) {
        snprintf(reply, reply_size, "pong-from-cosmos-validator");
        return 0;
    }
    if (strcmp(cmd, "info") == 0) {
        snprintf(reply, reply_size,
                 "cometbft validator signer (SC dialer + protobuf privval)");
        return 0;
    }
    snprintf(reply, reply_size, "unknown_cmd: %s", cmd);
    return -1;
}

const app_descriptor_t cosmos_app = {
    .name       = "cosmos",
    .init       = cosmos_init,
    .handle_cmd = cosmos_handle_cmd,
};
