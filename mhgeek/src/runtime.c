#include "runtime.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct mhg_runtime {
    struct mhg_runtime_config config;
    struct mhg_lan_driver *driver;
    enum mhg_runtime_gate gate;
    enum mhg_runtime_state state;
    bool stopped;
    bool resources_ready;
    /* The generation whose resources were verified; a new generation always
     * re-check before any event is sent on it. */
    uint64_t resources_generation;
    uint64_t device_count;
    uint64_t presence_snapshots;
    uint64_t presence_ms;
    uint64_t next_gate_ms;
    uint64_t next_resources_ms;
    enum mhg_cloud_error last_error;
};

static uint64_t runtime_clock(void *userdata)
{
    struct mhg_runtime *owner = userdata;
    return owner->config.ops.now_ms(owner->config.userdata);
}

static int runtime_refresh(void *userdata, struct mhg_lan_bootstrap *out,
                           struct mhg_error *error)
{
    struct mhg_runtime *owner = userdata;

    return owner->config.ops.cloud_refresh(owner->config.userdata, out, error);
}

static int runtime_attempt(void *userdata, const struct mhg_lan_bootstrap *bootstrap,
                           size_t *device_count, struct mhg_error *error)
{
    struct mhg_runtime *owner = userdata;
    int result = owner->config.ops.lan_attempt(owner->config.userdata, bootstrap,
                                               device_count, error);

    if (result == 0)
        owner->device_count = *device_count;
    return result;
}

static bool runtime_connected(void *userdata)
{
    struct mhg_runtime *owner = userdata;

    return owner->config.ops.lan_connected(owner->config.userdata);
}

static uint64_t runtime_next_attempt(void *userdata, uint64_t now_ms)
{
    struct mhg_runtime *owner = userdata;

    if (!owner->config.ops.lan_next_attempt_ms)
        return 0u;
    return owner->config.ops.lan_next_attempt_ms(owner->config.userdata, now_ms);
}

int mhg_runtime_create(struct mhg_runtime **owner_out,
                       const struct mhg_runtime_config *config)
{
    struct mhg_runtime *owner;
    struct mhg_lan_driver_config driver_config = MHG_LAN_DRIVER_CONFIG_INIT;

    if (owner_out)
        *owner_out = NULL;
    if (!owner_out || !config || !config->ops.gate || !config->ops.lan_connected ||
        !config->ops.cloud_refresh || !config->ops.lan_attempt ||
        !config->ops.resources_sync || !config->delivery)
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner)
        return -1;
    owner->config = *config;
    owner->gate = MHG_RUNTIME_GATE_CREDENTIALS;
    owner->state = MHG_RUNTIME_CREDENTIALS_REQUIRED;
    driver_config.ops.now_ms = config->ops.now_ms ? runtime_clock : NULL;
    driver_config.ops.connected = runtime_connected;
    driver_config.ops.next_attempt_ms = runtime_next_attempt;
    driver_config.ops.refresh = runtime_refresh;
    driver_config.ops.attempt = runtime_attempt;
    driver_config.userdata = owner;
    driver_config.backoff_initial_ms = config->backoff_initial_ms;
    driver_config.backoff_max_ms = config->backoff_max_ms;
    driver_config.cloud_retry_ms = config->cloud_retry_ms;
    driver_config.stop = config->stop;
    if (mhg_lan_driver_create(&owner->driver, &driver_config) != 0) {
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_runtime_destroy(struct mhg_runtime *owner)
{
    if (!owner)
        return;
    mhg_lan_driver_destroy(owner->driver);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

static void runtime_probe_gate(struct mhg_runtime *owner, uint64_t now_ms)
{
    enum mhg_runtime_gate gate = MHG_RUNTIME_GATE_CREDENTIALS;
    struct mhg_error error = {0};

    if (owner->config.ops.gate(owner->config.userdata, &gate, &error))
        gate = MHG_RUNTIME_GATE_CREDENTIALS;
    owner->gate = gate;
    owner->next_gate_ms =
        now_ms + (owner->config.slow_ms ? owner->config.slow_ms : 1000u);
}

int mhg_runtime_service(struct mhg_runtime *owner, uint64_t now_ms)
{
    if (!owner)
        return -1;
    if (owner->stopped || (owner->config.stop && *owner->config.stop)) {
        if (!owner->stopped) {
            mhg_lan_driver_stop(owner->driver);
            owner->stopped = true;
        }
        owner->state = MHG_RUNTIME_STOPPED;
        return 0;
    }
    /* 1. Persisted records gate every network step. */
    if (now_ms >= owner->next_gate_ms)
        runtime_probe_gate(owner, now_ms);
    if (owner->gate != MHG_RUNTIME_GATE_OPEN) {
        owner->resources_ready = false;
        owner->resources_generation = 0u;
        owner->next_resources_ms = 0u;
        owner->state = owner->gate == MHG_RUNTIME_GATE_TARGET
                           ? MHG_RUNTIME_TARGET_REQUIRED
                           : MHG_RUNTIME_CREDENTIALS_REQUIRED;
        return 0;
    }
    /* 2. Keep the LAN session warm. A failed refresh or attempt is a state the
     *    driver owns (BACKOFF / CLOUD_REQUIRED), not a runtime error. */
    if (owner->config.ops.lan_service_idle)
        owner->config.ops.lan_service_idle(owner->config.userdata, now_ms);
    (void)mhg_lan_driver_service(owner->driver, now_ms);
    if (owner->config.ops.now_ms) now_ms = runtime_clock(owner);
    if (!owner->config.ops.lan_connected(owner->config.userdata)) {
        enum mhg_lan_driver_state driver_state = mhg_lan_driver_state(owner->driver);

        owner->resources_ready = false;
        owner->resources_generation = 0u;
        owner->next_resources_ms = 0u;
        if (driver_state == MHG_LAN_DRIVER_CLOUD_REQUIRED)
            owner->state = MHG_RUNTIME_CLOUD_REQUIRED;
        else if (driver_state == MHG_LAN_DRIVER_STOPPED)
            owner->state = MHG_RUNTIME_STOPPED;
        else if (driver_state == MHG_LAN_DRIVER_RECONNECTING)
            owner->state = MHG_RUNTIME_CONNECTING;
        else
            owner->state = MHG_RUNTIME_OFFLINE;
        return 0;
    }
    /* 3. Re-verify on connection changes and every minute. */
    if (owner->resources_ready && owner->config.ops.lan_snapshot) {
        uint64_t generation = 0u;
        enum mhg_lan_state lan_state = MHG_LAN_OFFLINE;
        enum mhg_lan_binding binding = MHG_LAN_BIND_NONE;

        owner->config.ops.lan_snapshot(owner->config.userdata, &generation, &lan_state,
                                       &binding);
        if (generation != owner->resources_generation) {
            owner->resources_ready = false;
            owner->next_resources_ms = 0u;
        }
    }
    if (now_ms >= owner->next_resources_ms) {
        struct mhg_error error = {0};
        bool was_ready = owner->resources_ready;

        if (!was_ready)
            owner->state = MHG_RUNTIME_RESOURCES;
        int synchronized =
            owner->config.ops.resources_sync(owner->config.userdata, &error);
        if (owner->config.ops.now_ms) now_ms = runtime_clock(owner);
        if (synchronized < 0) {
            /* A failed maintenance pass revokes the previous resource proof.
             * Retry on the slow lane; the session stays warm meanwhile. */
            owner->resources_ready = false;
            owner->resources_generation = 0u;
            owner->next_resources_ms = 0u;
            owner->last_error =
                error.code == ETIMEDOUT ? MHG_CLOUD_NETWORK : MHG_CLOUD_SERVICE;
            owner->next_resources_ms =
                now_ms + (owner->config.slow_ms ? owner->config.slow_ms : 1000u);
            return 0;
        }
        owner->resources_ready = true;
        owner->next_resources_ms = now_ms + MHG_RUNTIME_RESOURCE_CHECK_MS;
        if (owner->config.ops.lan_snapshot) {
            enum mhg_lan_state lan_state = MHG_LAN_OFFLINE;
            enum mhg_lan_binding binding = MHG_LAN_BIND_NONE;

            owner->config.ops.lan_snapshot(owner->config.userdata,
                                           &owner->resources_generation, &lan_state,
                                           &binding);
        }
        /* §7.3: first ready state, LAN recovery and resource reconcile all
         * re-assert the newest authoritative presence. A failure pause is not
         * released here: it owns a bounded retry, and releasing it on every
         * self-inflicted reconnect turned one failed write into a retry loop. */
        if (!was_ready)
            mhg_delivery_reassert(owner->config.delivery);
    }
    if (!owner->resources_ready)
        return 0;
    /* 4. Newest presence hand-off, then the nine-slot delivery. */
    if (owner->config.presence &&
        mhg_presence_source_pump(owner->config.presence, owner->config.delivery)) {
        owner->presence_snapshots += 1u;
        owner->presence_ms = now_ms;
    }
    if (mhg_delivery_service(owner->config.delivery, now_ms) != 0) {
        struct mhg_delivery_stats stats = MHG_DELIVERY_STATS_INIT;

        mhg_delivery_stats_get(owner->config.delivery, &stats);
        owner->last_error = stats.last_error;
        if (!owner->config.ops.lan_connected(owner->config.userdata)) {
            owner->resources_ready = false;
            owner->resources_generation = 0u;
            owner->next_resources_ms = 0u;
            owner->state = MHG_RUNTIME_OFFLINE;
        } else {
            owner->state = MHG_RUNTIME_DELIVERY_PAUSED;
        }
        return 0;
    }
    if (mhg_delivery_state(owner->config.delivery) == MHG_DELIVERY_PAUSED) {
        owner->state = MHG_RUNTIME_DELIVERY_PAUSED;
        return 0;
    }
    owner->state = MHG_RUNTIME_READY;
    owner->last_error = MHG_CLOUD_OK;
    return 0;
}

void mhg_runtime_stop(struct mhg_runtime *owner)
{
    if (!owner)
        return;
    mhg_lan_driver_stop(owner->driver);
    owner->stopped = true;
    owner->state = MHG_RUNTIME_STOPPED;
}

void mhg_runtime_request_recheck(struct mhg_runtime *owner)
{
    if (!owner)
        return;
    owner->next_gate_ms = 0u;
    owner->next_resources_ms = 0u;
    owner->resources_ready = false;
}

void mhg_runtime_status_get(const struct mhg_runtime *owner,
                            struct mhg_runtime_status *status)
{
    struct mhg_runtime *mutable;

    if (!status)
        return;
    memset(status, 0, sizeof(*status));
    if (!owner)
        return;
    mutable = (struct mhg_runtime *)owner;
    status->state = owner->state;
    status->resources_ready = owner->resources_ready;
    status->lan_generation = owner->resources_generation;
    status->device_count = owner->device_count;
    status->presence_snapshots = owner->presence_snapshots;
    status->presence_ms = owner->presence_ms;
    status->last_error = owner->last_error;
    status->driver = mhg_lan_driver_state(owner->driver);
    mhg_lan_driver_stats_get(owner->driver, &status->driver_stats);
    status->delivery = mhg_delivery_state(owner->config.delivery);
    mhg_delivery_stats_get(owner->config.delivery, &status->delivery_stats);
    if (owner->config.presence &&
        mhg_presence_source_peek(mutable->config.presence, &status->presence))
        status->presence_known = true;
    if (owner->config.ops.lan_snapshot)
        owner->config.ops.lan_snapshot(owner->config.userdata, &status->lan_generation,
                                       &status->lan, &status->binding);
}

const char *mhg_runtime_state_name(enum mhg_runtime_state state)
{
    switch (state) {
    case MHG_RUNTIME_CREDENTIALS_REQUIRED:
        return "credentials_required";
    case MHG_RUNTIME_TARGET_REQUIRED:
        return "target_required";
    case MHG_RUNTIME_OFFLINE:
        return "offline";
    case MHG_RUNTIME_CLOUD_REQUIRED:
        return "cloud_required";
    case MHG_RUNTIME_CONNECTING:
        return "connecting";
    case MHG_RUNTIME_RESOURCES:
        return "resources";
    case MHG_RUNTIME_READY:
        return "ready";
    case MHG_RUNTIME_DELIVERY_PAUSED:
        return "delivery_paused";
    case MHG_RUNTIME_STOPPED:
        return "stopped";
    }
    return NULL;
}

const char *mhg_runtime_gate_name(enum mhg_runtime_gate gate)
{
    switch (gate) {
    case MHG_RUNTIME_GATE_CREDENTIALS:
        return "credentials";
    case MHG_RUNTIME_GATE_TARGET:
        return "target";
    case MHG_RUNTIME_GATE_OPEN:
        return "open";
    }
    return NULL;
}
