#ifndef MHGEEK_BRIDGE_SNAPSHOT_H
#define MHGEEK_BRIDGE_SNAPSHOT_H

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "app.h"

/* Every field that a Bridge route reads is copied into one bounded value.
 * The scheduler builds it without a lock after its network work; publication
 * and request-local capture hold the mutex only for a struct assignment. */
struct mhg_app_bridge_snapshot {
    struct mhg_runtime_status status;
    struct mhg_catalog_stats catalog;
    struct mhg_app_target_state target;
    struct mhg_app_auth_state auth;
    struct mhg_app_maintenance maintenance;
    size_t catalog_device_count;
    enum mhg_resource_state resource_state;
    uint64_t synced_config_generation;
    char lan_error[160];
    char resource_error[200];
    char config_error[200];
    double absent_seconds[MHG_PRESENCE_SLOT_COUNT];
    char prefix[MHG_EVENT_PREFIX_LIMIT + 1u];
    char texts[MHG_RESOURCE_VARIABLE_COUNT][MHG_EVENT_PREFIX_LIMIT +
                                             MHG_EVENT_TEXT_LIMIT + 1u];
};

struct mhg_app_bridge_publisher {
    pthread_mutex_t lock;
    struct mhg_app_bridge_snapshot value;
};

static inline int mhg_app_bridge_publisher_init(
    struct mhg_app_bridge_publisher *owner)
{
    if (!owner) return -1;
    memset(owner, 0, sizeof(*owner));
    return pthread_mutex_init(&owner->lock, NULL);
}

static inline void mhg_app_bridge_publisher_destroy(
    struct mhg_app_bridge_publisher *owner)
{
    if (owner) pthread_mutex_destroy(&owner->lock);
}

static inline void mhg_app_bridge_publish(
    struct mhg_app_bridge_publisher *owner,
    const struct mhg_app_bridge_snapshot *next)
{
    pthread_mutex_lock(&owner->lock);
    owner->value = *next;
    pthread_mutex_unlock(&owner->lock);
}

static inline void mhg_app_bridge_take(
    struct mhg_app_bridge_publisher *owner,
    struct mhg_app_bridge_snapshot *out)
{
    pthread_mutex_lock(&owner->lock);
    *out = owner->value;
    pthread_mutex_unlock(&owner->lock);
}

#endif
