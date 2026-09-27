#ifndef MHGEEK_PRESENCE_SOURCE_H
#define MHGEEK_PRESENCE_SOURCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ainice/event.h"
#include "common.h"
#include "presence_delivery.h"

/* Consumes the authoritative SUBSYS typed presence (§7.3) and hands it to the
 * delivery state machine without ever keeping a borrowed pointer:
 *
 * - the subscription callback runs on the subscriber thread, so it only copies
 *   the fields this plugin needs into a mutex-protected slot and bumps a
 *   sequence number;
 * - the runtime loop (30ms cadence) calls take(), which returns a newer
 *   snapshot exactly once, and then applies it to the delivery owner from the
 *   scheduler thread.
 *
 * hold durations and target lists are deliberately ignored: this plugin uses
 * the final presence flags only. */
struct mhg_presence_source_ops {
    /* One blocking subscription; the production value is
     * ainice_presence_subscribe_until(). */
    int (*subscribe)(ainice_presence_handler_t handler, void *userdata,
                     ainice_event_should_stop_t should_stop,
                     void *stop_userdata);
};

struct mhg_presence_source_config {
    struct mhg_presence_source_ops ops;
    /* Stops the blocking subscription; also consulted by stop(). */
    ainice_event_should_stop_t should_stop;
    void *stop_userdata;
};

#define MHG_PRESENCE_SOURCE_CONFIG_INIT {{NULL}, NULL, NULL}

struct mhg_presence_source;

int mhg_presence_source_create(struct mhg_presence_source **owner_out,
                               const struct mhg_presence_source_config *config);
void mhg_presence_source_destroy(struct mhg_presence_source *owner);

/* Runs the blocking subscription until the callback or the stop hook ends it.
 * Returns 0 on a normal end and -1 on a connect/protocol failure; the caller
 * decides whether to resubscribe (the SDK never reconnects on its own). */
int mhg_presence_source_run(struct mhg_presence_source *owner,
                            struct mhg_error *error);

/* Copies the newest snapshot into *state when one arrived since the last take;
 * returns 1 when it did, 0 when there is nothing new. */
int mhg_presence_source_take(struct mhg_presence_source *owner,
                             struct mhg_presence_state *state);

/* Copies the newest snapshot without consuming it, for status displays;
 * returns 1 when one has ever arrived, 0 otherwise. */
int mhg_presence_source_peek(struct mhg_presence_source *owner,
                             struct mhg_presence_state *state);

/* Applies a newer snapshot to the delivery owner, if there is one. */
int mhg_presence_source_pump(struct mhg_presence_source *owner,
                             struct mhg_delivery *delivery);

void mhg_presence_source_request_stop(struct mhg_presence_source *owner);
uint64_t mhg_presence_source_snapshots(const struct mhg_presence_source *owner);

/* The callback the subscription hands to the SDK; exposed for offline tests. */
int mhg_presence_source_callback(const ainice_presence_snapshot_t *snapshot,
                                 void *userdata);

#endif
