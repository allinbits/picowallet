// Cosmos / Tendermint validator signer app.
//
// Long-term: implements Tendermint privval secret-connection over USB,
// signs CanonicalVote / CanonicalProposal messages with HWM protection.
// Today (M2): stub. Text commands only.

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
                 "Cosmos/Tendermint validator (privval pending M3)");
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
