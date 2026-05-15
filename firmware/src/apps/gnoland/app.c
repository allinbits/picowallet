// Gno.land validator signer app.
//
// Long-term: signs Gno consensus messages. Note: Gno does NOT use protobuf
// for consensus messages -- exact format to be verified in source before M4.
// Today (M2): stub. Text commands only.

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
                 "Gno.land validator (canonical format research pending M4)");
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
