#ifndef MHGEEK_RESOURCE_SYNC_H
#define MHGEEK_RESOURCE_SYNC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cloud_wire_types.h"
#include "common.h"
#include "resource_store.h"

/* Creates and re-checks the plugin-owned hub resources (§7.1) without ever
 * trusting a display name:
 *
 *   generate ids -> persist them -> create DISABLED -> read back every item and
 *   compare the content digest -> enable -> read back again
 *
 * A ready record converges to durable local configuration. Functional repair
 * first closes delivery; presentation repair leaves validated delivery open. The
 * injected calls cover the failure paths offline. */
enum mhg_resource_state {
    MHG_RESOURCE_NONE = 0,
    MHG_RESOURCE_READY,
    MHG_RESOURCE_DRIFTED,
    MHG_RESOURCE_PRESENTATION_PENDING,
};

enum mhg_resource_reconcile_result {
    MHG_RESOURCE_RECONCILE_RETRY = -1,
    MHG_RESOURCE_RECONCILE_OK = 0,
    MHG_RESOURCE_RECONCILE_DRIFTED = 1,
    MHG_RESOURCE_RECONCILE_PRESENTATION_PENDING = 2,
};

enum mhg_resource_seed_probe_result {
    MHG_RESOURCE_SEED_RETRY = -1,
    MHG_RESOURCE_SEED_PRESENT = 0,
    MHG_RESOURCE_SEED_MISSING = 1,
    MHG_RESOURCE_SEED_DRIFTED = 2,
    /* An unknown scope can look like an auth rejection and end the LAN
     * generation. It is not proof that the variable is absent. */
    MHG_RESOURCE_SEED_SESSION_UNCERTAIN = 3,
};

struct mhg_resource_sync_ops {
    int (*plan)(void *userdata, struct mhg_resource_record *record,
                struct mhg_error *error);
    enum mhg_resource_reconcile_result (*seed_guard)(
        void *userdata, const struct mhg_resource_record *record,
        struct mhg_error *error);
    int (*seed_create)(void *userdata, const struct mhg_resource_record *record,
                       struct mhg_error *error);
    enum mhg_resource_seed_probe_result (*seed_probe)(
        void *userdata, const struct mhg_resource_record *record,
        struct mhg_error *error);
    int (*global_seed_create)(void *userdata, const struct mhg_resource_record *record,
                              struct mhg_error *error);
    enum mhg_resource_seed_probe_result (*global_seed_probe)(
        void *userdata, const struct mhg_resource_record *record,
        struct mhg_error *error);
    int (*seed_end_generation)(void *userdata, struct mhg_error *error);
    int (*create_disabled)(void *userdata, const struct mhg_resource_record *record,
                           struct mhg_error *error);
    int (*readback)(void *userdata, const struct mhg_resource_record *record,
                    bool enabled, struct mhg_error *error);
    int (*enable)(void *userdata, const struct mhg_resource_record *record,
                  struct mhg_error *error);
    enum mhg_resource_reconcile_result (*reconcile_config)(
        void *userdata, struct mhg_resource_record *record, bool *changed,
        struct mhg_error *error);
    int (*commit_record)(void *userdata, const char *path,
                         const struct mhg_resource_record *record);
};

struct mhg_resource_sync_config {
    struct mhg_resource_sync_ops ops;
    void *userdata;
    /* `<data_root>/resources.json`, built by mhg_resource_store_prepare. */
    const char *path;
    const volatile sig_atomic_t *stop;
};

#define MHG_RESOURCE_SYNC_CONFIG_INIT {{0}, NULL, NULL, NULL}

struct mhg_resource_sync_stats {
    uint64_t provisions;
    uint64_t rechecks;
    uint64_t drifts;
    uint64_t failures;
};

#define MHG_RESOURCE_SYNC_STATS_INIT {0u, 0u, 0u, 0u}

struct mhg_resource_sync;

int mhg_resource_sync_create(struct mhg_resource_sync **owner_out,
                             const struct mhg_resource_sync_config *config);
void mhg_resource_sync_destroy(struct mhg_resource_sync *owner);

/* One synchronous pass: provision when no record exists, otherwise re-check it.
 * Returns the resulting state; a failure leaves delivery frozen and reports the
 * reason through `error`. */
enum mhg_resource_state mhg_resource_sync_run(struct mhg_resource_sync *owner,
                                              struct mhg_error *error);
enum mhg_resource_state mhg_resource_sync_state(const struct mhg_resource_sync *owner);
void mhg_resource_sync_stats_get(const struct mhg_resource_sync *owner,
                                 struct mhg_resource_sync_stats *stats);
const char *mhg_resource_state_name(enum mhg_resource_state state);

#endif
