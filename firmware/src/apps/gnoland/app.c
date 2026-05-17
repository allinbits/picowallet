// Gno.land validator signer app.
//
// Signs gno.land CanonicalVote / CanonicalProposal messages over the gno
// SecretConnection variant (HKDF challenge, no Merlin). Wire encoding is
// amino; the per-chain listener + parser live in apps/gnoland/sc_driver.c
// and apps/gnoland/gno_privval.c. This file is the OS-facing descriptor.

#include <string.h>
#include <stdio.h>

#include "apps/gnoland/app.h"
#include "os/api.h"

static int gnoland_init(void) {
    return 0;
}

static int gnoland_handle_cmd(const char *cmd, const char *args,
                              char *reply, size_t reply_size) {
    (void)args;
    if (strcmp(cmd, "ping") == 0) {
        snprintf(reply, reply_size, "pong-from-gnoland-validator");
        return 0;
    }
    if (strcmp(cmd, "info") == 0) {
        snprintf(reply, reply_size,
                 "gno.land validator signer (SC listener + amino privval)");
        return 0;
    }
    snprintf(reply, reply_size, "unknown_cmd: %s", cmd);
    return -1;
}

const app_descriptor_t gnoland_app = {
    .name       = "gnoland",
    .init       = gnoland_init,
    .handle_cmd = gnoland_handle_cmd,
};
