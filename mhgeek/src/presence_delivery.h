#ifndef MHGEEK_PRESENCE_DELIVERY_H
#define MHGEEK_PRESENCE_DELIVERY_H

#include <stdbool.h>
#include <signal.h>
#include <stdint.h>

#include "common.h"
#include "cloud_wire_types.h"

enum mhg_presence_slot {
    MHG_PRESENCE_GLOBAL = 0,
    MHG_PRESENCE_ZONE_A = 1,
    MHG_PRESENCE_ZONE_B = 2,
    MHG_PRESENCE_ZONE_C = 3,
    MHG_PRESENCE_ZONE_D = 4,
    MHG_PRESENCE_ZONE_E = 5,
    MHG_PRESENCE_ZONE_F = 6,
    MHG_PRESENCE_ZONE_G = 7,
    MHG_PRESENCE_ZONE_H = 8,
    MHG_PRESENCE_SLOT_COUNT = 9,
};

#define MHG_PRESENCE_EVENT_LIMIT MHG_PRESENCE_SLOT_COUNT

struct mhg_presence_state {
    bool on[MHG_PRESENCE_SLOT_COUNT];
};

enum mhg_delivery_state {
    MHG_DELIVERY_IDLE = 0,
    MHG_DELIVERY_SENDING,
    MHG_DELIVERY_PAUSED,
};

struct mhg_delivery_ops {
    /* Completion clock for a blocking send; NULL for instantaneous test ops. */
    uint64_t (*now_ms)(void *userdata);
    /* Returns success only after neutral=2 and desired=1/0 each receive a
     * successful setVarValue JSON-RPC/business ACK. A partial or lost ACK is
     * never accepted, even if the hub may have applied a value. */
    int (*send)(void *userdata, enum mhg_presence_slot slot, bool present,
                struct mhg_error *error);
};

struct mhg_delivery_config {
    struct mhg_delivery_ops ops;
    void *userdata;
    const volatile sig_atomic_t *stop;
};

#define MHG_DELIVERY_CONFIG_INIT {{NULL, NULL}, NULL, NULL}

struct mhg_delivery_stats {
    uint64_t batches;
    uint64_t replays;
    uint64_t events_attempted;
    uint64_t events_accepted;
    uint64_t events_failed;
    uint64_t events_skipped;
    uint64_t pauses;
    uint64_t retries;
    uint64_t superseded;
    enum mhg_cloud_error last_error;
    char error_message[160];
};

#define MHG_DELIVERY_STATS_INIT \
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, MHG_CLOUD_OK, ""}

/* A failed batch waits before retrying the newest authoritative state. */
#define MHG_DELIVERY_PAUSE_RETRY_MS 30000u

struct mhg_delivery;

int mhg_delivery_create(struct mhg_delivery **owner_out,
                        const struct mhg_delivery_config *config);
void mhg_delivery_destroy(struct mhg_delivery *owner);
void mhg_delivery_apply_presence(struct mhg_delivery *owner,
                                 const struct mhg_presence_state *state);
void mhg_delivery_request_replay(struct mhg_delivery *owner);
void mhg_delivery_reassert(struct mhg_delivery *owner);
/* Drops old-generation applied knowledge; no old ACK can complete on a new
 * emitter. A failure pause retains its bounded retry deadline. */
void mhg_delivery_rebind(struct mhg_delivery *owner);
void mhg_delivery_resume(struct mhg_delivery *owner);
/* Called on the existing 30 ms runtime schedule; submits at most one slot. */
int mhg_delivery_service(struct mhg_delivery *owner, uint64_t now_ms);
enum mhg_delivery_state mhg_delivery_state(const struct mhg_delivery *owner);
void mhg_delivery_stats_get(const struct mhg_delivery *owner,
                            struct mhg_delivery_stats *stats);
bool mhg_delivery_pending(const struct mhg_delivery *owner);
const char *mhg_delivery_state_name(enum mhg_delivery_state state);

#endif
