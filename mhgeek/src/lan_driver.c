#include "lan_driver.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct mhg_lan_driver {
    struct mhg_lan_driver_config config;
    enum mhg_lan_driver_state state;
    uint64_t next_attempt_ms;
    int stopped;
    /* The last cycle failed at the cloud refresh, so the wait before the next
     * cycle is a "the account path is needed" wait, not a LAN backoff. */
    int cloud_failed;
    struct mhg_lan_driver_stats stats;
};

static int config_is_valid(const struct mhg_lan_driver_config *config)
{
    return config && config->ops.refresh && config->ops.attempt &&
           config->backoff_initial_ms != 0u &&
           config->backoff_max_ms >= config->backoff_initial_ms &&
           config->cloud_retry_ms != 0u;
}

int mhg_lan_driver_create(struct mhg_lan_driver **driver_out,
                          const struct mhg_lan_driver_config *config)
{
    struct mhg_lan_driver *driver;

    if (driver_out) *driver_out = NULL;
    if (!driver_out || !config_is_valid(config)) return -1;
    driver = calloc(1u, sizeof(*driver));
    if (!driver) return -1;
    driver->config = *config;
    driver->state = MHG_LAN_DRIVER_IDLE;
    driver->stats = (struct mhg_lan_driver_stats)MHG_LAN_DRIVER_STATS_INIT;
    *driver_out = driver;
    return 0;
}

/* Bounded jitter below the cap, deterministic for a given failure count so a
 * test can assert the schedule. */
static uint64_t next_delay_ms(const struct mhg_lan_driver *driver)
{
    uint64_t delay = driver->config.backoff_initial_ms;
    uint64_t step;
    uint64_t span;
    uint64_t mixed;

    for (step = 1u; step < driver->stats.consecutive_failures; ++step) {
        if (delay >= driver->config.backoff_max_ms) break;
        delay *= 2u;
    }
    if (delay >= driver->config.backoff_max_ms)
        return driver->config.backoff_max_ms;
    span = delay / 4u;
    if (span == 0u) return delay;
    mixed = driver->stats.consecutive_failures * 2654435761u;
    mixed ^= mixed >> 13;
    return delay - span + (mixed % (2u * span + 1u));
}

static bool stopped_now(const struct mhg_lan_driver *driver)
{
    return driver->stopped || (driver->config.stop && *driver->config.stop);
}

static uint64_t completed_at(struct mhg_lan_driver *driver, uint64_t started)
{
    uint64_t now = driver->config.ops.now_ms ?
        driver->config.ops.now_ms(driver->config.userdata) : started;
    return now > started ? now : started;
}

static int run_cycle(struct mhg_lan_driver *driver, uint64_t now_ms)
{
    struct mhg_lan_bootstrap bootstrap = {0};
    struct mhg_error error = {0};
    size_t devices = 0u;

    driver->stats.refreshes += 1u;
    if (driver->config.ops.refresh(driver->config.userdata, &bootstrap,
                                   &error)) {
        /* The LAN is down and the cloud could not help: stay here and tell the
         * user instead of hot-looping the account path. */
        driver->stats.cloud_failures += 1u;
        driver->cloud_failed = 1;
        driver->state = MHG_LAN_DRIVER_CLOUD_REQUIRED;
        driver->next_attempt_ms = completed_at(driver, now_ms) + driver->config.cloud_retry_ms;
        return -1;
    }
    driver->cloud_failed = 0;
    driver->stats.attempts += 1u;
    if (driver->config.ops.attempt(driver->config.userdata, &bootstrap,
                                   &devices, &error)) {
        now_ms = completed_at(driver, now_ms);
        driver->stats.lan_failures += 1u;
        driver->stats.consecutive_failures += 1u;
        if (driver->config.ops.next_attempt_ms) {
            driver->next_attempt_ms = driver->config.ops.next_attempt_ms(
                driver->config.userdata, now_ms);
            driver->stats.backoff_ms = driver->next_attempt_ms > now_ms ?
                driver->next_attempt_ms - now_ms : 0u;
        } else {
            driver->stats.backoff_ms = next_delay_ms(driver);
            driver->next_attempt_ms = now_ms + driver->stats.backoff_ms;
        }
        driver->state = MHG_LAN_DRIVER_BACKOFF;
        return -1;
    }
    driver->stats.consecutive_failures = 0u;
    driver->stats.backoff_ms = 0u;
    driver->next_attempt_ms = 0u;
    if (driver->state != MHG_LAN_DRIVER_IDLE)
        driver->stats.reconnects += 1u;
    driver->state = MHG_LAN_DRIVER_CONNECTED;
    return 0;
}

int mhg_lan_driver_service(struct mhg_lan_driver *driver, uint64_t now_ms)
{
    if (!driver)
        return -1;
    if (stopped_now(driver)) {
        driver->state = MHG_LAN_DRIVER_STOPPED;
        return 0;
    }
    if (driver->config.ops.connected &&
        driver->config.ops.connected(driver->config.userdata)) {
        driver->state = MHG_LAN_DRIVER_CONNECTED;
        driver->stats.consecutive_failures = 0u;
        driver->stats.backoff_ms = 0u;
        return 0;
    }
    if (driver->state == MHG_LAN_DRIVER_CONNECTED ||
        driver->state == MHG_LAN_DRIVER_IDLE) {
        /* A drop starts the rebuild right away: the passcode and the handshake
         * are the only path back in, so warming them early is the whole point
         * of this driver (§6.7). */
        driver->state = MHG_LAN_DRIVER_RECONNECTING;
        driver->next_attempt_ms = now_ms;
    }
    {
        /* Two schedules must both allow the next cycle: the owner's §6.3
         * schedule (so a refused attempt never spends a bootstrap) and our own
         * retry deadline (a failed cloud refresh). Neither may shorten the
         * other, otherwise a cloud failure would hot-loop the account path. */
        uint64_t allowed = driver->next_attempt_ms;

        if (driver->config.ops.next_attempt_ms) {
            uint64_t owner_ms = driver->config.ops.next_attempt_ms(
                driver->config.userdata, now_ms);

            if (owner_ms > allowed) allowed = owner_ms;
        }
        if (allowed != 0u && now_ms < allowed) {
            driver->state = driver->cloud_failed ?
                MHG_LAN_DRIVER_CLOUD_REQUIRED : MHG_LAN_DRIVER_BACKOFF;
            driver->next_attempt_ms = allowed;
            driver->stats.backoff_ms = allowed - now_ms;
            return 0;
        }
    }
    driver->state = MHG_LAN_DRIVER_RECONNECTING;
    return run_cycle(driver, now_ms);
}

void mhg_lan_driver_stop(struct mhg_lan_driver *driver)
{
    if (!driver) return;
    driver->stopped = 1;
    driver->state = MHG_LAN_DRIVER_STOPPED;
    driver->next_attempt_ms = 0u;
    driver->stats.backoff_ms = 0u;
}

void mhg_lan_driver_destroy(struct mhg_lan_driver *driver)
{
    if (!driver) return;
    OPENSSL_clear_free(driver, sizeof(*driver));
}

enum mhg_lan_driver_state mhg_lan_driver_state(
    const struct mhg_lan_driver *driver)
{
    return driver ? driver->state : MHG_LAN_DRIVER_IDLE;
}

uint64_t mhg_lan_driver_next_attempt_ms(const struct mhg_lan_driver *driver)
{
    return driver ? driver->next_attempt_ms : 0u;
}

void mhg_lan_driver_stats_get(const struct mhg_lan_driver *driver,
                              struct mhg_lan_driver_stats *stats)
{
    if (!stats) return;
    *stats = driver ? driver->stats :
                      (struct mhg_lan_driver_stats)MHG_LAN_DRIVER_STATS_INIT;
}

const char *mhg_lan_driver_state_name(enum mhg_lan_driver_state state)
{
    switch (state) {
    case MHG_LAN_DRIVER_IDLE: return "idle";
    case MHG_LAN_DRIVER_CONNECTED: return "connected";
    case MHG_LAN_DRIVER_RECONNECTING: return "reconnecting";
    case MHG_LAN_DRIVER_BACKOFF: return "backoff";
    case MHG_LAN_DRIVER_CLOUD_REQUIRED: return "cloud_required";
    case MHG_LAN_DRIVER_STOPPED: return "stopped";
    }
    return NULL;
}
