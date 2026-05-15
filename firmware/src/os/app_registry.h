#pragma once
#include <stddef.h>

typedef struct {
    // Identifier used in USB commands: "<name>.<cmd>"
    const char *name;

    // Called once at boot. Returns 0 on success.
    int (*init)(void);

    // Called for each USB command targeted at this app.
    //   cmd:        the command name (after "<app>.")
    //   args:       the argument string (everything after the first space; "")
    //   reply:      buffer to write a single-line response into; caller passes
    //               an empty buffer of `reply_size` bytes
    //   reply_size: size of `reply`
    // Returns 0 on success (-> host gets "ok <reply>"), <0 on error
    // (-> host gets "err <reply>" if reply is set, else "err app_error").
    int (*handle_cmd)(const char *cmd, const char *args, char *reply, size_t reply_size);
} app_descriptor_t;

const app_descriptor_t *app_registry_find(const char *name);
const app_descriptor_t *app_registry_at(size_t idx);
size_t                  app_registry_count(void);
int                     app_registry_init_all(void);
