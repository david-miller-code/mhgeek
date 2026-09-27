#include "presence_source.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct mhg_presence_source {
    struct mhg_presence_source_config config;
    pthread_mutex_t lock;
    struct mhg_presence_state latest;
    uint64_t sequence;      /* bumped by the callback */
    uint64_t taken;         /* the sequence the scheduler already applied */
    bool have_latest;
    int stop_requested;
};

static int source_stop(void *userdata)
{
    struct mhg_presence_source *owner = userdata;
    int stopped;

    pthread_mutex_lock(&owner->lock);
    stopped = owner->stop_requested ||
              (owner->config.should_stop &&
               owner->config.should_stop(owner->config.stop_userdata));
    pthread_mutex_unlock(&owner->lock);
    return stopped;
}

int mhg_presence_source_callback(const ainice_presence_snapshot_t *snapshot,
                                 void *userdata)
{
    struct mhg_presence_source *owner = userdata;
    size_t zone;

    if (!owner || !snapshot) return 1;
    /* Copy only the final flags; no hold arithmetic and no borrowed pointer. */
    pthread_mutex_lock(&owner->lock);
    owner->latest.on[MHG_PRESENCE_GLOBAL] = snapshot->global_present;
    for (zone = 0u; zone < AINICE_VISION_ZONE_COUNT; ++zone)
        owner->latest.on[MHG_PRESENCE_ZONE_A + zone] =
            snapshot->zone_present[zone];
    owner->have_latest = true;
    owner->sequence += 1u;
    pthread_mutex_unlock(&owner->lock);
    return 0;
}

int mhg_presence_source_create(struct mhg_presence_source **owner_out,
                               const struct mhg_presence_source_config *config)
{
    struct mhg_presence_source *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || !config->ops.subscribe) return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->config = *config;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_presence_source_destroy(struct mhg_presence_source *owner)
{
    if (!owner) return;
    pthread_mutex_destroy(&owner->lock);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

int mhg_presence_source_run(struct mhg_presence_source *owner,
                            struct mhg_error *error)
{
    int result;

    if (!owner) return -1;
    result = owner->config.ops.subscribe(mhg_presence_source_callback, owner,
                                         source_stop, owner);
    if (result != 0) {
        mhg_errorf(error, EIO, "presence subscription failed");
        return -1;
    }
    return 0;
}

int mhg_presence_source_take(struct mhg_presence_source *owner,
                             struct mhg_presence_state *state)
{
    int fresh = 0;

    if (!owner || !state) return 0;
    pthread_mutex_lock(&owner->lock);
    if (owner->have_latest && owner->sequence != owner->taken) {
        *state = owner->latest;
        owner->taken = owner->sequence;
        fresh = 1;
    }
    pthread_mutex_unlock(&owner->lock);
    return fresh;
}

int mhg_presence_source_pump(struct mhg_presence_source *owner,
                             struct mhg_delivery *delivery)
{
    struct mhg_presence_state state;

    if (!owner || !delivery) return 0;
    if (!mhg_presence_source_take(owner, &state)) return 0;
    mhg_delivery_apply_presence(delivery, &state);
    return 1;
}

int mhg_presence_source_peek(struct mhg_presence_source *owner,
                             struct mhg_presence_state *state)
{
    int known = 0;

    if (!owner || !state) return 0;
    pthread_mutex_lock(&owner->lock);
    if (owner->have_latest) {
        *state = owner->latest;
        known = 1;
    }
    pthread_mutex_unlock(&owner->lock);
    return known;
}

void mhg_presence_source_request_stop(struct mhg_presence_source *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    owner->stop_requested = 1;
    pthread_mutex_unlock(&owner->lock);
}

uint64_t mhg_presence_source_snapshots(const struct mhg_presence_source *owner)
{
    uint64_t sequence;
    struct mhg_presence_source *mutable = (struct mhg_presence_source *)owner;

    if (!owner) return 0u;
    pthread_mutex_lock(&mutable->lock);
    sequence = mutable->sequence;
    pthread_mutex_unlock(&mutable->lock);
    return sequence;
}
