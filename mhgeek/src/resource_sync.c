#include "resource_sync.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct mhg_resource_sync {
    struct mhg_resource_sync_config config;
    struct mhg_resource_record record;
    bool has_record;
    enum mhg_resource_state state;
    struct mhg_resource_sync_stats stats;
};

static int commit_record(struct mhg_resource_sync *owner,
                         const struct mhg_resource_record *record)
{
    return owner->config.ops.commit_record
               ? owner->config.ops.commit_record(owner->config.userdata,
                                                 owner->config.path, record)
               : mhg_resource_store_commit(owner->config.path, record);
}

static int commit_seed_state(struct mhg_resource_sync *owner,
                             enum mhg_resource_seed_state state, bool global,
                             struct mhg_error *error)
{
    struct mhg_resource_record next = MHG_RESOURCE_RECORD_INIT;

    if (owner->record.resource_generation >= 9007199254740991ull ||
        mhg_resource_record_clone(&next, &owner->record) != 0) {
        mhg_errorf(error, ENOMEM, "seed state copy failed");
        return -1;
    }
    if (global)
        next.global_seed_state = state;
    else
        next.seed_state = state;
    next.resource_generation += 1u;
    if (commit_record(owner, &next) != MHG_RESOURCE_STORE_COMMITTED_DURABLE) {
        mhg_errorf(error, EIO, "seed state is not durable");
        mhg_resource_record_clear(&next);
        return -1;
    }
    mhg_resource_record_clear(&owner->record);
    owner->record = next;
    return 0;
}

static enum mhg_resource_state seed_drift(struct mhg_resource_sync *owner)
{
    owner->stats.failures += 1u;
    owner->stats.drifts += 1u;
    owner->state = MHG_RESOURCE_DRIFTED;
    return MHG_RESOURCE_DRIFTED;
}

static enum mhg_resource_state seed_retry(struct mhg_resource_sync *owner)
{
    owner->stats.failures += 1u;
    owner->state = MHG_RESOURCE_NONE;
    return MHG_RESOURCE_NONE;
}

static enum mhg_resource_state probe_seed(struct mhg_resource_sync *owner, bool global,
                                          bool after_ack, struct mhg_error *error)
{
    enum mhg_resource_seed_probe_result probed =
        (global ? owner->config.ops.global_seed_probe : owner->config.ops.seed_probe)(
            owner->config.userdata, &owner->record, error);

    if (probed == MHG_RESOURCE_SEED_PRESENT) {
        if (commit_seed_state(owner, MHG_RESOURCE_SEED_VERIFIED, global, error))
            return seed_retry(owner);
        owner->state = MHG_RESOURCE_NONE;
        return MHG_RESOURCE_NONE;
    }
    if (probed == MHG_RESOURCE_SEED_DRIFTED)
        return seed_drift(owner);
    /* An ACK followed by a lost readback is still uncertain. In particular,
     * an auth-style error may have ended this generation; never issue a
     * second create on it. The next generation probes first. */
    if (after_ack || probed == MHG_RESOURCE_SEED_RETRY)
        return seed_retry(owner);
    if (probed == MHG_RESOURCE_SEED_MISSING ||
        probed == MHG_RESOURCE_SEED_SESSION_UNCERTAIN) {
        /* End the captured LAN generation before the durable retry marker.
         * A crash or commit failure then resumes with a probe, and a live
         * generation can never retry createVar on the next 1s slow pass. */
        if (owner->config.ops.seed_end_generation(owner->config.userdata, error))
            return seed_retry(owner);
        if (commit_seed_state(owner, MHG_RESOURCE_SEED_RETRY_CREATE, global, error))
            return seed_retry(owner);
        return seed_retry(owner);
    }
    mhg_errorf(error, EPROTO, "unknown seed probe result");
    return seed_retry(owner);
}

static enum mhg_resource_state run_seed_scope(struct mhg_resource_sync *owner,
                                              bool global, struct mhg_error *error)
{
    enum mhg_resource_reconcile_result guard;
    enum mhg_resource_seed_state state =
        global ? owner->record.global_seed_state : owner->record.seed_state;

    if (!owner->config.ops.seed_guard || !owner->config.ops.seed_create ||
        !owner->config.ops.seed_probe || !owner->config.ops.global_seed_create ||
        !owner->config.ops.global_seed_probe ||
        !owner->config.ops.seed_end_generation) {
        mhg_errorf(error, EAGAIN, "resource seed is not configured");
        return seed_retry(owner);
    }
    switch (state) {
    case MHG_RESOURCE_SEED_VERIFIED:
        return MHG_RESOURCE_NONE;
    case MHG_RESOURCE_SEED_CREATE_UNCERTAIN:
        return probe_seed(owner, global, false, error);
    case MHG_RESOURCE_SEED_UNSTARTED:
        return probe_seed(owner, global, false, error);
    case MHG_RESOURCE_SEED_RETRY_CREATE:
        /* The guard is a generation positive control (getDevList target). A stale
         * generation cannot write the marker or send createVar. */
        guard =
            owner->config.ops.seed_guard(owner->config.userdata, &owner->record, error);
        if (guard == MHG_RESOURCE_RECONCILE_DRIFTED)
            return seed_drift(owner);
        if (guard != MHG_RESOURCE_RECONCILE_OK)
            return seed_retry(owner);
        if (commit_seed_state(owner, MHG_RESOURCE_SEED_CREATE_UNCERTAIN, global, error))
            return seed_retry(owner);
        if ((global ? owner->config.ops.global_seed_create
                    : owner->config.ops.seed_create)(owner->config.userdata,
                                                     &owner->record, error))
            return seed_retry(owner);
        return probe_seed(owner, global, true, error);
    }
    mhg_errorf(error, EPROTO, "invalid resource seed state");
    return seed_retry(owner);
}

int mhg_resource_sync_create(struct mhg_resource_sync **owner_out,
                             const struct mhg_resource_sync_config *config)
{
    struct mhg_resource_sync *owner;

    if (owner_out)
        *owner_out = NULL;
    if (!owner_out || !config || !config->path || !config->ops.plan ||
        !config->ops.create_disabled || !config->ops.readback || !config->ops.enable ||
        !config->ops.reconcile_config || !config->ops.seed_probe ||
        !config->ops.global_seed_probe)
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner)
        return -1;
    owner->config = *config;
    owner->record = (struct mhg_resource_record)MHG_RESOURCE_RECORD_INIT;
    owner->stats = (struct mhg_resource_sync_stats)MHG_RESOURCE_SYNC_STATS_INIT;
    *owner_out = owner;
    return 0;
}

void mhg_resource_sync_destroy(struct mhg_resource_sync *owner)
{
    if (!owner)
        return;
    mhg_resource_record_clear(&owner->record);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

static int load_record(struct mhg_resource_sync *owner, struct mhg_error *error)
{
    struct mhg_resource_record loaded = MHG_RESOURCE_RECORD_INIT;
    int result = mhg_resource_store_load(owner->config.path, &loaded);

    if (result == MHG_RESOURCE_STORE_ABSENT ||
        (result == MHG_RESOURCE_STORE_ERROR && errno == EPROTO)) {
        /* IDs are deterministic for the verified target. A damaged derived
         * cache is rebuilt by plan + read-before-create, never migrated. */
        owner->has_record = false;
        mhg_resource_record_clear(&loaded);
        return 0;
    }
    if (result != MHG_RESOURCE_STORE_PRESENT) {
        mhg_errorf(error, EIO, "resource record is unreadable");
        return -1;
    }
    mhg_resource_record_clear(&owner->record);
    owner->record = loaded;
    owner->has_record = true;
    return 0;
}

enum mhg_resource_state mhg_resource_sync_run(struct mhg_resource_sync *owner,
                                              struct mhg_error *error)
{
    if (!owner)
        return MHG_RESOURCE_NONE;
    if (owner->config.stop && *owner->config.stop)
        return seed_retry(owner);
    if (load_record(owner, error))
        return seed_retry(owner);
    if (!owner->has_record) {
        struct mhg_resource_record next = MHG_RESOURCE_RECORD_INIT;
        ++owner->stats.provisions;
        if (owner->config.ops.plan(owner->config.userdata, &next, error) ||
            commit_record(owner, &next) != MHG_RESOURCE_STORE_COMMITTED_DURABLE) {
            mhg_resource_record_clear(&next);
            return seed_retry(owner);
        }
        mhg_resource_record_clear(&owner->record);
        owner->record = next;
        owner->has_record = true;
    }
    if (mhg_resource_store_confirm_durable(owner->config.path, &owner->record)) {
        mhg_errorf(error, EIO, "resource intent not durable");
        return seed_retry(owner);
    }
    if (owner->record.stage == MHG_RESOURCE_STAGE_PROVISIONING) {
        if (owner->record.seed_state != MHG_RESOURCE_SEED_VERIFIED)
            return run_seed_scope(owner, false, error);
        if (owner->record.global_seed_state != MHG_RESOURCE_SEED_VERIFIED)
            return run_seed_scope(owner, true, error);
        /* Resume by reading first: an enabled desired graph can be the result of a
         * previous successful write whose ACK or local READY commit was lost. */
        if (owner->config.ops.readback(owner->config.userdata, &owner->record, true,
                                       error)) {
            if (owner->config.ops.create_disabled(owner->config.userdata,
                                                  &owner->record, error)) {
                /* Removing a wrongly typed final variable can make its scope
                 * empty. Re-enter the durable first-variable barrier; never
                 * retry createVar directly after an auth-style scope result. */
                if (error && error->code == EACCES) {
                    if (commit_seed_state(owner, MHG_RESOURCE_SEED_CREATE_UNCERTAIN,
                                          false, error) == 0)
                        (void)commit_seed_state(
                            owner, MHG_RESOURCE_SEED_CREATE_UNCERTAIN, true, error);
                }
                return seed_retry(owner);
            }
            if (owner->config.ops.readback(owner->config.userdata, &owner->record, true,
                                           error)) {
                if (owner->config.ops.readback(owner->config.userdata, &owner->record,
                                               false, error) ||
                    owner->config.ops.enable(owner->config.userdata, &owner->record,
                                             error) ||
                    owner->config.ops.readback(owner->config.userdata, &owner->record,
                                               true, error))
                    return seed_retry(owner);
            }
        }
        owner->record.stage = MHG_RESOURCE_STAGE_READY;
        if (commit_record(owner, &owner->record) !=
            MHG_RESOURCE_STORE_COMMITTED_DURABLE) {
            mhg_errorf(error, EIO, "ready record not durable");
            return seed_retry(owner);
        }
    }
    bool changed = false;
    ++owner->stats.rechecks;
    enum mhg_resource_reconcile_result result = owner->config.ops.reconcile_config(
        owner->config.userdata, &owner->record, &changed, error);
    if (changed &&
        commit_record(owner, &owner->record) != MHG_RESOURCE_STORE_COMMITTED_DURABLE) {
        mhg_errorf(error, EIO, "resource convergence not durable");
        return seed_retry(owner);
    }
    if (result == MHG_RESOURCE_RECONCILE_PRESENTATION_PENDING) {
        owner->state = MHG_RESOURCE_PRESENTATION_PENDING;
        return owner->state;
    }
    if (result == MHG_RESOURCE_RECONCILE_DRIFTED)
        return seed_drift(owner);
    if (result != MHG_RESOURCE_RECONCILE_OK ||
        owner->record.stage != MHG_RESOURCE_STAGE_READY)
        return seed_retry(owner);
    owner->state = MHG_RESOURCE_READY;
    return owner->state;
}
enum mhg_resource_state mhg_resource_sync_state(const struct mhg_resource_sync *owner)
{
    return owner ? owner->state : MHG_RESOURCE_NONE;
}

void mhg_resource_sync_stats_get(const struct mhg_resource_sync *owner,
                                 struct mhg_resource_sync_stats *stats)
{
    if (!stats)
        return;
    *stats = owner ? owner->stats
                   : (struct mhg_resource_sync_stats)MHG_RESOURCE_SYNC_STATS_INIT;
}

const char *mhg_resource_state_name(enum mhg_resource_state state)
{
    switch (state) {
    case MHG_RESOURCE_NONE:
        return "none";
    case MHG_RESOURCE_READY:
        return "ready";
    case MHG_RESOURCE_DRIFTED:
        return "drifted";
    case MHG_RESOURCE_PRESENTATION_PENDING:
        return "presentation_pending";
    }
    return NULL;
}
