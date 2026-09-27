#ifndef MHGEEK_RUNTIME_H
#define MHGEEK_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cloud_wire_types.h"
#include "common.h"
#include "lan_driver.h"
#include "lan_owner.h"
#include "presence_delivery.h"
#include "presence_source.h"

/* The §8.1 app owner: one process, one 30ms scheduler lane (§6.7), no hidden
 * worker threads. The runtime sequences the persisted records, the cloud/LAN
 * refresh, the plugin-owned hub resources, the presence hand-off and the event
 * delivery, and exposes one status snapshot for the Bridge:
 *
 *   1. gate      - no account record -> CREDENTIALS_REQUIRED, no network work;
 *                  account but no target -> TARGET_REQUIRED, still no network.
 *   2. driver    - keeps the LAN session warm: a drop is refreshed from the
 *                  cloud and re-attempted on the §6.3 schedule; a cloud
 *                  failure stops in CLOUD_REQUIRED instead of looping silently.
 *   3. resources - §7.1: create or re-verify the plugin's own resources in the
 *                  live generation; only then does the resource phase open.
 *   4. presence  - the newest authoritative snapshot is applied to delivery.
 *   5. delivery  - the nine-slot plan runs on the same lane (§7.3).
 *
 * A LAN recovery, a resource re-check or an explicit request re-arms the full
 * replay, so the hub converges on the newest desired state.
 *
 * Every cloud, LAN and resource step is injected, so the whole lifecycle is
 * exercised offline; production binds them to xiaomi_session + target_resolver,
 * lan_owner + resource_sync. */

enum mhg_runtime_gate {
    MHG_RUNTIME_GATE_CREDENTIALS = 0,
    MHG_RUNTIME_GATE_TARGET = 1,
    MHG_RUNTIME_GATE_OPEN = 2,
};

enum mhg_runtime_state {
    MHG_RUNTIME_CREDENTIALS_REQUIRED = 0,
    MHG_RUNTIME_TARGET_REQUIRED = 1,
    MHG_RUNTIME_OFFLINE = 2,
    MHG_RUNTIME_CLOUD_REQUIRED = 3,
    MHG_RUNTIME_CONNECTING = 4,
    MHG_RUNTIME_RESOURCES = 5,
    MHG_RUNTIME_READY = 6,
    MHG_RUNTIME_STOPPED = 7,
    MHG_RUNTIME_DELIVERY_PAUSED = 8,
};

#define MHG_RUNTIME_RESOURCE_CHECK_MS 60000u

struct mhg_runtime_ops {
    uint64_t (*now_ms)(void *userdata);
    /* §9.1: which persisted records exist. No network work happens until both
     * the account and the target record are present. */
    int (*gate)(void *userdata, enum mhg_runtime_gate *gate, struct mhg_error *error);
    /* Service idle transport traffic before checking liveness. Must leave any
     * pending business reply to its request owner. Optional for no-I/O fakes. */
    void (*lan_service_idle)(void *userdata, uint64_t now_ms);
    /* LAN liveness and the LAN owner's own §6.3 schedule. */
    bool (*lan_connected)(void *userdata);
    uint64_t (*lan_next_attempt_ms)(void *userdata, uint64_t now_ms);
    /* Optional: the live generation and binding, for the status snapshot. */
    void (*lan_snapshot)(void *userdata, uint64_t *generation,
                         enum mhg_lan_state *state, enum mhg_lan_binding *binding);
    /* §5/§6.5: one fresh cloud bootstrap for the persisted target. */
    int (*cloud_refresh)(void *userdata, struct mhg_lan_bootstrap *out,
                         struct mhg_error *error);
    /* §6.5: one LAN attempt that must reach the verified binding. */
    int (*lan_attempt)(void *userdata, const struct mhg_lan_bootstrap *bootstrap,
                       size_t *device_count, struct mhg_error *error);
    /* §7.1: create or re-verify the plugin's own resources. */
    /* 0 fully synchronized, 1 presentation retry (delivery remains safe), -1 frozen. */
    int (*resources_sync)(void *userdata, struct mhg_error *error);
};

struct mhg_runtime_config {
    struct mhg_runtime_ops ops;
    void *userdata;
    /* §6.3 schedule the injected LAN owner uses for its own attempts. */
    unsigned int backoff_initial_ms;
    unsigned int backoff_max_ms;
    /* How long CLOUD_REQUIRED waits before asking the cloud again. */
    unsigned int cloud_retry_ms;
    /* Slow lane: gate re-probe and resource re-try interval. */
    unsigned int slow_ms;
    /* Borrowed: the caller owns both objects. `presence` may be NULL (no
     * subscription wired yet); `delivery` is required. */
    struct mhg_presence_source *presence;
    struct mhg_delivery *delivery;
    const volatile sig_atomic_t *stop;
};

#define MHG_RUNTIME_CONFIG_INIT                                                        \
    {{0}, NULL, 1000u, 30000u, 30000u, 1000u, NULL, NULL, NULL}

struct mhg_runtime_status {
    enum mhg_runtime_state state;
    enum mhg_lan_driver_state driver;
    enum mhg_lan_state lan;
    enum mhg_lan_binding binding;
    bool resources_ready;
    uint64_t lan_generation;
    uint64_t device_count;
    uint64_t presence_snapshots;
    uint64_t presence_ms;
    struct mhg_presence_state presence;
    /* True when presence has been seen at least once. */
    bool presence_known;
    enum mhg_delivery_state delivery;
    struct mhg_delivery_stats delivery_stats;
    struct mhg_lan_driver_stats driver_stats;
    enum mhg_cloud_error last_error;
};

struct mhg_runtime;

int mhg_runtime_create(struct mhg_runtime **owner_out,
                       const struct mhg_runtime_config *config);
void mhg_runtime_destroy(struct mhg_runtime *owner);

/* One scheduler step (the caller wakes at most every 30ms). Never blocks on a
 * confirmation window: the delivery polls its own in-flight events. */
int mhg_runtime_service(struct mhg_runtime *owner, uint64_t now_ms);

/* Marks the plugin stopped: no further refresh, attempt, resource or event
 * work happens, and the driver is stopped. */
void mhg_runtime_stop(struct mhg_runtime *owner);

/* Frontend action (target saved or cleared, repair requested): re-probe the
 * gate and re-verify the resources on the next step. */
void mhg_runtime_request_recheck(struct mhg_runtime *owner);

void mhg_runtime_status_get(const struct mhg_runtime *owner,
                            struct mhg_runtime_status *status);
const char *mhg_runtime_state_name(enum mhg_runtime_state state);
const char *mhg_runtime_gate_name(enum mhg_runtime_gate gate);

#endif
