#include <string.h>

#include "os/app_registry.h"

#include "apps/cosmos/app.h"
#include "apps/gnoland/app.h"

static const app_descriptor_t * const REGISTRY[] = {
    &cosmos_app,
    &gnoland_app,
};

#define REGISTRY_COUNT (sizeof(REGISTRY) / sizeof(REGISTRY[0]))

const app_descriptor_t *app_registry_find(const char *name) {
    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (strcmp(REGISTRY[i]->name, name) == 0) return REGISTRY[i];
    }
    return NULL;
}

const app_descriptor_t *app_registry_at(size_t idx) {
    if (idx >= REGISTRY_COUNT) return NULL;
    return REGISTRY[idx];
}

size_t app_registry_count(void) {
    return REGISTRY_COUNT;
}

int app_registry_init_all(void) {
    int failures = 0;
    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (REGISTRY[i]->init && REGISTRY[i]->init() != 0) failures++;
    }
    return failures;
}
