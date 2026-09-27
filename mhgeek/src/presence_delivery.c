#include "presence_delivery.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct delivery_event {
    enum mhg_presence_slot slot;
    bool present;
};

struct mhg_delivery {
    struct mhg_delivery_config config;
    struct mhg_presence_state desired;
    struct mhg_presence_state applied;
    bool applied_known[MHG_PRESENCE_SLOT_COUNT];
    bool has_desired;
    bool paused;
    bool replay_required;
    struct delivery_event plan[MHG_PRESENCE_EVENT_LIMIT];
    size_t plan_count;
    size_t plan_next;
    uint64_t paused_at_ms;
    enum mhg_delivery_state state;
    struct mhg_delivery_stats stats;
};

int mhg_delivery_create(struct mhg_delivery **owner_out,
                        const struct mhg_delivery_config *config)
{
    struct mhg_delivery *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || !config->ops.send) return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->config = *config;
    owner->state = MHG_DELIVERY_IDLE;
    owner->replay_required = true;
    owner->stats = (struct mhg_delivery_stats)MHG_DELIVERY_STATS_INIT;
    *owner_out = owner;
    return 0;
}

void mhg_delivery_destroy(struct mhg_delivery *owner)
{
    if (owner) OPENSSL_clear_free(owner, sizeof(*owner));
}

static bool state_equal(const struct mhg_presence_state *a,
                        const struct mhg_presence_state *b)
{
    return memcmp(a->on, b->on, sizeof(a->on)) == 0;
}

static void clear_plan(struct mhg_delivery *owner)
{
    owner->plan_count = 0u;
    owner->plan_next = 0u;
}

static bool needs_work(const struct mhg_delivery *owner,
                       enum mhg_presence_slot slot)
{
    return owner->has_desired &&
        (!owner->applied_known[slot] ||
         owner->applied.on[slot] != owner->desired.on[slot]);
}

static bool any_work(const struct mhg_delivery *owner)
{
    int slot;

    for (slot = 0; slot < MHG_PRESENCE_SLOT_COUNT; ++slot)
        if (needs_work(owner, (enum mhg_presence_slot)slot)) return true;
    return false;
}

static void push_event(struct mhg_delivery *owner, enum mhg_presence_slot slot,
                       bool present)
{
    if (owner->plan_count >= MHG_PRESENCE_EVENT_LIMIT) return;
    owner->plan[owner->plan_count++] = (struct delivery_event){slot, present};
}

/* Preserve the established order: ON global, ON zones, OFF zones, OFF global.
 * The replay order first clears OFF zones, then sends global and ON zones. */
static void build_plan(struct mhg_delivery *owner)
{
    int slot;

    clear_plan(owner);
    if (!owner->has_desired) return;
    if (owner->replay_required) {
        for (slot = MHG_PRESENCE_ZONE_A; slot <= MHG_PRESENCE_ZONE_H; ++slot)
            if (!owner->desired.on[slot])
                push_event(owner, (enum mhg_presence_slot)slot, false);
        push_event(owner, MHG_PRESENCE_GLOBAL,
                   owner->desired.on[MHG_PRESENCE_GLOBAL]);
        for (slot = MHG_PRESENCE_ZONE_A; slot <= MHG_PRESENCE_ZONE_H; ++slot)
            if (owner->desired.on[slot])
                push_event(owner, (enum mhg_presence_slot)slot, true);
        owner->stats.replays += 1u;
    } else {
        if (owner->desired.on[MHG_PRESENCE_GLOBAL] &&
            needs_work(owner, MHG_PRESENCE_GLOBAL))
            push_event(owner, MHG_PRESENCE_GLOBAL, true);
        for (slot = MHG_PRESENCE_ZONE_A; slot <= MHG_PRESENCE_ZONE_H; ++slot)
            if (owner->desired.on[slot] &&
                needs_work(owner, (enum mhg_presence_slot)slot))
                push_event(owner, (enum mhg_presence_slot)slot, true);
        for (slot = MHG_PRESENCE_ZONE_A; slot <= MHG_PRESENCE_ZONE_H; ++slot)
            if (!owner->desired.on[slot] &&
                needs_work(owner, (enum mhg_presence_slot)slot))
                push_event(owner, (enum mhg_presence_slot)slot, false);
        if (!owner->desired.on[MHG_PRESENCE_GLOBAL] &&
            needs_work(owner, MHG_PRESENCE_GLOBAL))
            push_event(owner, MHG_PRESENCE_GLOBAL, false);
    }
    owner->replay_required = false;
    if (owner->plan_count != 0u) owner->stats.batches += 1u;
}

static void prune_plan(struct mhg_delivery *owner)
{
    size_t kept = owner->plan_next;
    size_t index;

    for (index = owner->plan_next; index < owner->plan_count; ++index) {
        const struct delivery_event *event = &owner->plan[index];

        if (owner->has_desired &&
            owner->desired.on[event->slot] == event->present)
            owner->plan[kept++] = *event;
        else
            owner->stats.events_skipped += 1u;
    }
    owner->plan_count = kept;
}

static enum mhg_cloud_error classify(const struct mhg_error *error)
{
    if (error && (error->code == ETIMEDOUT || error->code == ECONNRESET ||
                  error->code == ENOTCONN || error->code == EPIPE))
        return MHG_CLOUD_NETWORK;
    return MHG_CLOUD_SERVICE;
}

static void pause_delivery(struct mhg_delivery *owner, uint64_t now_ms,
                           const struct mhg_error *error)
{
    const char *source = error ? error->message : "";
    size_t index;

    owner->paused = true;
    if (owner->config.ops.now_ms) {
        uint64_t completed = owner->config.ops.now_ms(owner->config.userdata);
        if (completed > now_ms) now_ms = completed;
    }
    owner->paused_at_ms = now_ms;
    owner->replay_required = true;
    owner->stats.pauses += 1u;
    owner->stats.last_error = classify(error);
    clear_plan(owner);
    snprintf(owner->stats.error_message, sizeof(owner->stats.error_message),
             "state write errno=%d: ", error ? error->code : 0);
    for (index = 0u; source[index] != '\0'; ++index) {
        size_t used = strlen(owner->stats.error_message);
        unsigned char byte = (unsigned char)source[index];

        if (used + 1u >= sizeof(owner->stats.error_message)) break;
        owner->stats.error_message[used] =
            (byte >= 0x20u && byte < 0x7fu) ? (char)byte : '?';
        owner->stats.error_message[used + 1u] = '\0';
    }
    owner->state = MHG_DELIVERY_PAUSED;
}

void mhg_delivery_apply_presence(struct mhg_delivery *owner,
                                 const struct mhg_presence_state *state)
{
    bool changed;

    if (!owner || !state) return;
    changed = !owner->has_desired || !state_equal(&owner->desired, state);
    owner->desired = *state;
    owner->has_desired = true;
    if (owner->paused) {
        if (changed) {
            owner->paused = false;
            owner->replay_required = true;
            owner->stats.superseded += 1u;
            clear_plan(owner);
        }
        return;
    }
    if (changed && owner->plan_next < owner->plan_count)
        owner->stats.superseded += 1u;
    if (owner->plan_next < owner->plan_count) prune_plan(owner);
}

void mhg_delivery_request_replay(struct mhg_delivery *owner)
{
    if (!owner) return;
    owner->paused = false;
    owner->replay_required = true;
    clear_plan(owner);
}

void mhg_delivery_resume(struct mhg_delivery *owner)
{
    mhg_delivery_request_replay(owner);
}

void mhg_delivery_reassert(struct mhg_delivery *owner)
{
    if (!owner || owner->paused) return;
    owner->replay_required = true;
    clear_plan(owner);
}

void mhg_delivery_rebind(struct mhg_delivery *owner)
{
    if (!owner) return;
    memset(owner->applied_known, 0, sizeof(owner->applied_known));
    owner->replay_required = true;
    clear_plan(owner);
}

int mhg_delivery_service(struct mhg_delivery *owner, uint64_t now_ms)
{
    if (!owner) return -1;
    if (owner->config.stop && *owner->config.stop) return 0;
    if (owner->paused) {
        if (now_ms < owner->paused_at_ms ||
            now_ms - owner->paused_at_ms < MHG_DELIVERY_PAUSE_RETRY_MS) {
            owner->state = MHG_DELIVERY_PAUSED;
            return 0;
        }
        owner->stats.retries += 1u;
        owner->paused = false;
        owner->replay_required = true;
        clear_plan(owner);
    }
    if (owner->plan_next >= owner->plan_count) clear_plan(owner);
    if (owner->plan_count == 0u &&
        (owner->replay_required || any_work(owner)))
        build_plan(owner);
    if (owner->plan_count != 0u) prune_plan(owner);
    while (owner->plan_next < owner->plan_count) {
        const struct delivery_event event = owner->plan[owner->plan_next++];
        struct mhg_error error = {0};

        if (!owner->has_desired ||
            owner->desired.on[event.slot] != event.present) {
            owner->stats.events_skipped += 1u;
            continue;
        }
        owner->stats.events_attempted += 1u;
        if (owner->config.ops.send(owner->config.userdata, event.slot,
                                   event.present, &error)) {
            owner->applied_known[event.slot] = false;
            owner->stats.events_failed += 1u;
            pause_delivery(owner, now_ms, &error);
            return -1;
        }
        owner->applied.on[event.slot] = event.present;
        owner->applied_known[event.slot] = true;
        owner->stats.events_accepted += 1u;
        break; /* At most one slot's two writes per 30 ms service call. */
    }
    if (owner->plan_next >= owner->plan_count) clear_plan(owner);
    if (!owner->replay_required && owner->plan_count == 0u &&
        !any_work(owner)) {
        owner->state = MHG_DELIVERY_IDLE;
        owner->stats.last_error = MHG_CLOUD_OK;
        owner->stats.error_message[0] = '\0';
    } else {
        owner->state = MHG_DELIVERY_SENDING;
    }
    return 0;
}

enum mhg_delivery_state mhg_delivery_state(const struct mhg_delivery *owner)
{
    return owner ? owner->state : MHG_DELIVERY_IDLE;
}

void mhg_delivery_stats_get(const struct mhg_delivery *owner,
                            struct mhg_delivery_stats *stats)
{
    if (stats) *stats = owner ? owner->stats :
                                (struct mhg_delivery_stats)MHG_DELIVERY_STATS_INIT;
}

bool mhg_delivery_pending(const struct mhg_delivery *owner)
{
    return owner && owner->has_desired &&
        (owner->paused || owner->replay_required ||
         owner->plan_next < owner->plan_count || any_work(owner));
}

const char *mhg_delivery_state_name(enum mhg_delivery_state state)
{
    switch (state) {
    case MHG_DELIVERY_IDLE: return "idle";
    case MHG_DELIVERY_SENDING: return "sending";
    case MHG_DELIVERY_PAUSED: return "paused";
    }
    return NULL;
}
