#ifndef MHGEEK_RESOURCE_LAN_H
#define MHGEEK_RESOURCE_LAN_H

#include <cjson/cJSON.h>

#include "cloud_wire_types.h"
#include "common.h"
#include "resource_store.h"
#include "resource_sync.h"

/* The real §7.1 resource operations against the hub: create 18 number variables
 * and one graph that holds one varChange -> deviceOutput pair per slot and
 * direction, verify it by readback and a content digest, and enable it. Every
 * call goes through the RPC hook, so the same code runs offline against a fake
 * hub and online against the LAN owner. */
struct mhg_resource_lan_ops {
    int (*call)(void *userdata, const char *method, const cJSON *params, cJSON **reply,
                struct mhg_error *error);
    /* End only the generation captured by userdata. Never close a newer
     * connection because an old scope probe completed late. */
    int (*end_generation)(void *userdata, struct mhg_error *error);
};

/* Strings, texts and durations are copied at create; userdata remains borrowed. */
struct mhg_resource_lan_config {
    struct mhg_resource_lan_ops ops;
    void *userdata;
    const char *target_did;
    const char *target_model;
    uint64_t spec_generation;
    uint64_t resource_generation;
    /* Action target resolved from the device Spec for this target. */
    const char *urn;
    int siid;
    int aiid;
    int piid;
    /* Final text per slot/direction, index slot * 2 + (present ? 0 : 1). */
    const char *const *texts;
    const double *absent_seconds;
    uint64_t config_generation;
};

#define MHG_RESOURCE_LAN_CONFIG_INIT                                                   \
    {{NULL}, NULL, NULL, NULL, 1u, 1u, NULL, 0, 0, 0, NULL, NULL, 0u}

struct mhg_resource_lan;

int mhg_resource_lan_create(struct mhg_resource_lan **owner_out,
                            const struct mhg_resource_lan_config *config);
void mhg_resource_lan_destroy(struct mhg_resource_lan *owner);

/* Durable synchronization operations; all ownership is by exact ID. */
int mhg_resource_lan_plan(void *userdata, struct mhg_resource_record *record,
                          struct mhg_error *error);
enum mhg_resource_reconcile_result
mhg_resource_lan_seed_guard(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error);
int mhg_resource_lan_seed_create(void *userdata,
                                 const struct mhg_resource_record *record,
                                 struct mhg_error *error);
enum mhg_resource_seed_probe_result
mhg_resource_lan_seed_probe(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error);
int mhg_resource_lan_global_seed_create(void *userdata,
                                        const struct mhg_resource_record *record,
                                        struct mhg_error *error);
enum mhg_resource_seed_probe_result mhg_resource_lan_global_seed_probe(
    void *userdata, const struct mhg_resource_record *record, struct mhg_error *error);
int mhg_resource_lan_seed_end_generation(void *userdata, struct mhg_error *error);
int mhg_resource_lan_create_disabled(void *userdata,
                                     const struct mhg_resource_record *record,
                                     struct mhg_error *error);
int mhg_resource_lan_readback(void *userdata, const struct mhg_resource_record *record,
                              bool enabled, struct mhg_error *error);
int mhg_resource_lan_enable(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error);
enum mhg_resource_reconcile_result
mhg_resource_lan_reconcile_config(void *userdata, struct mhg_resource_record *record,
                                  bool *changed, struct mhg_error *error);
#endif
