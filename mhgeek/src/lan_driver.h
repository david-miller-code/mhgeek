#ifndef MHGEEK_LAN_DRIVER_H
#define MHGEEK_LAN_DRIVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

/* Schedules LAN reconnection on the owning scheduler (§6.7):
 *
 * - While the session is up nothing happens; a drop is noticed on the next
 *   service step and the refresh starts immediately, so the connection is
 *   rebuilt before the next user action or event.
 * - A LAN attempt that fails uses the §6.3 schedule (1/2/4/8/16/30s by default
 *   with bounded jitter, reset only after a success).
 * - A cloud refresh that fails stops in CLOUD_REQUIRED and only retries after
 *   its own delay: the frontend can then tell "LAN session healthy" apart from
 *   "LAN down and the cloud is needed" instead of looping silently.
 *
 * The cloud and the LAN attempt are injected, so this state machine is
 * exercised offline and the runtime decides what "refresh" and "attempt" mean
 * (resolver + LAN owner in production). */
enum mhg_lan_driver_state {
    MHG_LAN_DRIVER_IDLE = 0,
    MHG_LAN_DRIVER_CONNECTED,
    MHG_LAN_DRIVER_RECONNECTING,
    MHG_LAN_DRIVER_BACKOFF,
    MHG_LAN_DRIVER_CLOUD_REQUIRED,
    MHG_LAN_DRIVER_STOPPED,
};

/* One fresh bootstrap: the URL and passcode of the current cloud generation,
 * plus the persisted identity the attempt must match. All pointers are
 * borrowed for the duration of the attempt only. */
struct mhg_lan_bootstrap {
    const char *url;
    const char *passcode;
    const char *target_ip;
    const char *target_did;
    const char *target_model;
    uint64_t generation;
};

struct mhg_lan_driver_ops {
    /* Completion clock for blocking callbacks; NULL for instantaneous test ops. */
    uint64_t (*now_ms)(void *userdata);
    /* True while the live session is usable; false means "rebuild it". */
    bool (*connected)(void *userdata);
    /* Optional: the LAN-side schedule of the injected owner. When present the
     * driver never starts a cycle before that time, so the §6.3 backoff lives
     * in exactly one place and no cloud bootstrap is spent on a refused
     * attempt. Without it the driver uses its own schedule. */
    uint64_t (*next_attempt_ms)(void *userdata, uint64_t now_ms);
    /* Obtains a fresh URL+passcode for the persisted target. */
    int (*refresh)(void *userdata, struct mhg_lan_bootstrap *out,
                   struct mhg_error *error);
    /* Runs one LAN attempt and returns 0 only when the binding is verified. */
    int (*attempt)(void *userdata, const struct mhg_lan_bootstrap *bootstrap,
                   size_t *device_count, struct mhg_error *error);
};

struct mhg_lan_driver_config {
    struct mhg_lan_driver_ops ops;
    void *userdata;
    unsigned int backoff_initial_ms;
    unsigned int backoff_max_ms;
    /* How long CLOUD_REQUIRED waits before asking the cloud again. */
    unsigned int cloud_retry_ms;
    const volatile sig_atomic_t *stop;
};

#define MHG_LAN_DRIVER_CONFIG_INIT \
    {{NULL, NULL, NULL, NULL, NULL}, NULL, 1000u, 30000u, 30000u, NULL}

struct mhg_lan_driver_stats {
    uint64_t refreshes;
    uint64_t attempts;
    uint64_t cloud_failures;
    uint64_t lan_failures;
    uint64_t reconnects;
    uint64_t consecutive_failures;
    uint64_t backoff_ms;
};

#define MHG_LAN_DRIVER_STATS_INIT {0u, 0u, 0u, 0u, 0u, 0u, 0u}

struct mhg_lan_driver;

int mhg_lan_driver_create(struct mhg_lan_driver **driver_out,
                          const struct mhg_lan_driver_config *config);
void mhg_lan_driver_destroy(struct mhg_lan_driver *driver);

/* One scheduler step; refresh and attempt may block until their deadlines. A success means the injected attempt
 * reached the verified binding; every failure is reflected in the state and
 * stats rather than returned as an error. */
int mhg_lan_driver_service(struct mhg_lan_driver *driver, uint64_t now_ms);
void mhg_lan_driver_stop(struct mhg_lan_driver *driver);
enum mhg_lan_driver_state mhg_lan_driver_state(
    const struct mhg_lan_driver *driver);
uint64_t mhg_lan_driver_next_attempt_ms(const struct mhg_lan_driver *driver);
void mhg_lan_driver_stats_get(const struct mhg_lan_driver *driver,
                              struct mhg_lan_driver_stats *stats);
const char *mhg_lan_driver_state_name(enum mhg_lan_driver_state state);

#endif
