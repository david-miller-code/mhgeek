#include "lan_owner.h"
#include "core_bootstrap.h"

#include <openssl/crypto.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

/* Hub-side rejection for a call on a session the hub no longer authenticates:
 * reads are still answered, writes come back with this code. */
#define MHG_LAN_HUB_NOT_AUTHENTICATED (-10004)

bool mhg_lan_reply_auth_rejected(const cJSON *reply,
                                 bool set_variable_value)
{
    const cJSON *error;
    const cJSON *result;
    const cJSON *code;

    if (!cJSON_IsObject(reply)) return false;
    error = cJSON_GetObjectItemCaseSensitive(reply, "error");
    result = cJSON_GetObjectItemCaseSensitive(reply, "result");
    code = cJSON_IsObject(error) ?
        cJSON_GetObjectItemCaseSensitive(error, "code") : NULL;
    if (cJSON_IsNumber(code) &&
        code->valuedouble == (double)MHG_LAN_HUB_NOT_AUTHENTICATED)
        return true;
    code = set_variable_value && cJSON_IsObject(result) ?
        cJSON_GetObjectItemCaseSensitive(result, "code") : NULL;
    return cJSON_IsNumber(code) &&
           code->valuedouble == (double)MHG_LAN_HUB_NOT_AUTHENTICATED;
}

struct mhg_lan_pending {
    int active;
    bool set_variable_value;
    uint64_t generation;
    uint64_t id;
    uint64_t deadline_ms;
};

struct mhg_lan_owner {
    struct mhg_lan_config config;
    char attempt_url[512];
    struct mhg_transport *transport;
    struct mhg_session *session;
    enum mhg_lan_state state;
    enum mhg_lan_binding binding;
    uint64_t generation;
    uint64_t next_attempt_ms;
    int stopped;
    struct mhg_lan_pending pending;
    struct mhg_lan_stats stats;
};

static int config_is_valid(const struct mhg_lan_config *config)
{
    return config && config->max_message >= 22u &&
           config->connect_timeout_ms != 0u &&
           config->handshake_timeout_ms != 0u &&
           config->call_timeout_ms != 0u &&
           config->backoff_initial_ms != 0u &&
           config->backoff_max_ms >= config->backoff_initial_ms;
}

int mhg_lan_owner_create(struct mhg_lan_owner **owner_out,
                         const struct mhg_lan_config *config)
{
    struct mhg_lan_owner *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config_is_valid(config)) return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->config = *config;
    owner->state = MHG_LAN_OFFLINE;
    owner->stats = (struct mhg_lan_stats)MHG_LAN_STATS_INIT;
    *owner_out = owner;
    return 0;
}

/* Closes the live attempt. The generation is not reused: a later begin() takes
 * the next value, so any result still carrying the ended one is refused. */
static void close_attempt(struct mhg_lan_owner *owner)
{
    mhg_session_free(owner->session);
    owner->session = NULL;
    mhg_transport_close(owner->transport);
    owner->transport = NULL;
    owner->binding = MHG_LAN_BIND_NONE;
    /* A request still in flight loses its reply with the generation; callers
     * must treat its outcome as unknown rather than reusing the session. */
    owner->pending = (struct mhg_lan_pending){0};
}

/* xorshift64 keeps the bounded jitter deterministic for a given attempt, so a
 * test can assert the schedule without weakening it. */
static uint64_t mix(uint64_t value)
{
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
}

static uint64_t next_delay_ms(const struct mhg_lan_owner *owner)
{
    uint64_t delay = owner->config.backoff_initial_ms;
    uint64_t step;
    uint64_t span;
    uint64_t offset;

    for (step = 1u; step < owner->stats.consecutive_failures; ++step) {
        if (delay >= owner->config.backoff_max_ms) break;
        delay *= 2u;
    }
    /* The cap is deterministic: jitter only spreads the steps below it. */
    if (delay >= owner->config.backoff_max_ms)
        return owner->config.backoff_max_ms;
    span = delay / 4u;
    if (span == 0u) return delay;
    offset = mix(owner->generation * 1087u +
                 owner->stats.consecutive_failures) % (2u * span + 1u);
    delay = delay - span + offset;
    return delay;
}

uint64_t mhg_lan_owner_begin(struct mhg_lan_owner *owner, uint64_t now_ms)
{
    if (!owner || owner->stopped) return 0u;
    if (owner->state == MHG_LAN_CONNECTING || owner->state == MHG_LAN_JPAKE ||
        owner->state == MHG_LAN_ONLINE)
        return 0u;
    if (owner->next_attempt_ms != 0u && now_ms < owner->next_attempt_ms)
        return 0u;
    owner->generation += 1u;
    owner->state = MHG_LAN_CONNECTING;
    owner->binding = MHG_LAN_BIND_NONE;
    owner->next_attempt_ms = 0u;
    owner->stats.attempts += 1u;
    if (owner->stats.attempts > 1u) owner->stats.reconnects += 1u;
    return owner->generation;
}

int mhg_lan_owner_connect(struct mhg_lan_owner *owner, uint64_t generation,
                          const char *base_url, const char *passcode,
                          uint64_t now_ms, struct mhg_error *error)
{
    const char *phase = "input";
    uint64_t deadline;

    if (!owner || !base_url || !passcode)
        return mhg_errorf(error, EINVAL, "invalid LAN connection arguments");
    if (generation != owner->generation ||
        owner->state != MHG_LAN_CONNECTING) {
        owner->stats.stale_rejections += 1u;
        return mhg_errorf(error, ESTALE, "stale LAN generation");
    }
    if (owner->config.stop && *owner->config.stop) {
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_CANCELLED, now_ms);
        return mhg_errorf(error, ECANCELED, "LAN attempt stopped");
    }
    if (mhg_deadline_after(owner->config.connect_timeout_ms, &deadline, error))
        return -1;
    owner->transport = mhg_transport_open(base_url, owner->config.max_message,
                                          deadline, owner->config.stop, error);
    if (!owner->transport) {
        owner->stats.connect_failures += 1u;
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_NETWORK, now_ms);
        return -1;
    }
    owner->state = MHG_LAN_JPAKE;
    snprintf(owner->attempt_url, sizeof(owner->attempt_url), "%s", base_url);
    if (mhg_deadline_after(owner->config.handshake_timeout_ms, &deadline,
                           error) ||
        !(owner->session = mhg_session_open(owner->transport, passcode,
                                            owner->config.max_message, deadline,
                                            &phase, error))) {
        if (error && error->code == EACCES) {
            owner->stats.auth_failures += 1u;
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_AUTH, now_ms);
        } else {
            owner->stats.handshake_failures += 1u;
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL,
                              now_ms);
        }
        return -1;
    }
    owner->state = MHG_LAN_ONLINE;
    owner->stats.consecutive_failures = 0u;
    owner->stats.backoff_ms = 0u;
    owner->next_attempt_ms = 0u;
    return 0;
}

int mhg_lan_owner_call(struct mhg_lan_owner *owner, uint64_t generation,
                       const char *method, const cJSON *params, cJSON **reply,
                       uint64_t now_ms, struct mhg_error *error)
{
    uint64_t deadline;

    if (!owner || !method || !reply || *reply)
        return mhg_errorf(error, EINVAL, "invalid LAN call arguments");
    if (generation != owner->generation ||
        owner->state != MHG_LAN_ONLINE) {
        owner->stats.stale_rejections += 1u;
        return mhg_errorf(error, ESTALE, "stale LAN generation");
    }
    if (owner->config.stop && *owner->config.stop) {
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_CANCELLED, now_ms);
        return mhg_errorf(error, ECANCELED, "LAN call stopped");
    }
    if (mhg_deadline_after(owner->config.call_timeout_ms, &deadline, error))
        return -1;
    owner->stats.calls += 1u;
    if (mhg_session_call(owner->session, method, params, deadline, reply,
                         error)) {
        /* A failed exchange leaves delivery uncertain; the generation ends so
         * no later result of it can be mistaken for the live session. */
        if (error && (error->code == ETIMEDOUT || error->code == ECONNRESET ||
                      error->code == ENOTCONN || error->code == EIO))
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_NETWORK, now_ms);
        else
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL,
                              now_ms);
        return -1;
    }
    /* A read can still succeed when the hub rejects writes. The rejection may
     * be inside result.code, so it must be consumed before any caller treats
     * this response as a successful write or resource readback. */
    if (mhg_lan_reply_auth_rejected(
            *reply, strcmp(method, "/api/setVarValue") == 0)) {
        cJSON_Delete(*reply);
        *reply = NULL;
        owner->stats.auth_failures += 1u;
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_AUTH, now_ms);
        return mhg_errorf(error, EACCES,
                          "hub rejected %s: session is not authenticated",
                          method);
    }
    return 0;
}

int mhg_lan_owner_check_membership(struct mhg_lan_owner *owner,
                                   uint64_t generation, const cJSON *dev_list,
                                   const char *target_did,
                                   const char *target_model,
                                   uint64_t now_ms,
                                   struct mhg_error *error)
{
    enum mhg_lan_membership verdict;

    if (!owner || !target_did || !target_model)
        return mhg_errorf(error, EINVAL, "invalid membership arguments");
    if (generation != owner->generation || owner->state != MHG_LAN_ONLINE) {
        owner->stats.stale_rejections += 1u;
        return mhg_errorf(error, ESTALE, "stale LAN generation");
    }
    verdict = mhg_lan_membership_evaluate(dev_list, target_did, target_model);
    if (verdict != MHG_LAN_MEMBERSHIP_PRESENT) {
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
        switch (verdict) {
        case MHG_LAN_MEMBERSHIP_MISMATCH:
            return mhg_errorf(error, EPROTO,
                              "target DID has a different model");
        case MHG_LAN_MEMBERSHIP_MALFORMED:
            return mhg_errorf(error, EPROTO, "device entry is malformed");
        case MHG_LAN_MEMBERSHIP_ABSENT:
        default:
            return mhg_errorf(error, EPROTO,
                              "target DID is absent from the list");
        }
    }
    /* Membership is necessary but never sufficient (§6.5): the authoritative
     * endpoint identity mechanism is not frozen, so VERIFIED stays unreachable
     * and the resource phase stays closed. */
    owner->binding = MHG_LAN_BIND_MEMBERSHIP;
    return 0;
}

int mhg_lan_owner_submit(struct mhg_lan_owner *owner, uint64_t generation,
                         const char *method, const cJSON *params,
                         uint64_t now_ms, struct mhg_error *error)
{
    uint64_t deadline;
    uint64_t id = 0u;

    if (!owner || !method)
        return mhg_errorf(error, EINVAL, "invalid LAN submit arguments");
    if (generation != owner->generation ||
        owner->state != MHG_LAN_ONLINE) {
        owner->stats.stale_rejections += 1u;
        return mhg_errorf(error, ESTALE, "stale LAN generation");
    }
    if (owner->pending.active) {
        owner->stats.submit_conflicts += 1u;
        return mhg_errorf(error, EALREADY, "a LAN request is already in flight");
    }
    if (owner->config.stop && *owner->config.stop) {
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_CANCELLED, now_ms);
        return mhg_errorf(error, ECANCELED, "LAN submit stopped");
    }
    if (mhg_deadline_after(owner->config.call_timeout_ms, &deadline, error))
        return -1;
    if (mhg_session_send(owner->session, method, params, &id, deadline, error)) {
        if (error && (error->code == ETIMEDOUT || error->code == ECONNRESET ||
                      error->code == ENOTCONN || error->code == EIO))
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_NETWORK, now_ms);
        else
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
        return -1;
    }
    owner->pending.active = 1;
    owner->pending.set_variable_value =
        strcmp(method, "/api/setVarValue") == 0;
    owner->pending.generation = generation;
    owner->pending.id = id;
    owner->pending.deadline_ms = deadline;
    owner->stats.submits += 1u;
    return 0;
}

int mhg_lan_owner_service(struct mhg_lan_owner *owner, uint64_t now_ms,
                          cJSON **reply, int *ready, struct mhg_error *error)
{
    int got = 0;

    if (!owner || !reply || !ready || *reply)
        return mhg_errorf(error, EINVAL, "invalid LAN service arguments");
    *ready = 0;
    if (owner->state != MHG_LAN_ONLINE)
        return mhg_errorf(error, ENOTCONN, "LAN session is not online");
    if (owner->pending.active) {
        if (owner->pending.generation != owner->generation) {
            owner->pending = (struct mhg_lan_pending){0};
            owner->stats.abandoned += 1u;
            return mhg_errorf(error, ESTALE, "stale LAN generation");
        }
        if (mhg_session_poll(owner->session, owner->pending.id, reply, &got,
                             owner->pending.deadline_ms, error)) {
            if (error && error->code == ETIMEDOUT) {
                owner->stats.timeouts += 1u;
                mhg_lan_owner_end(owner, owner->generation, MHG_LAN_END_NETWORK,
                                  now_ms);
            } else if (error && (error->code == ECONNRESET ||
                                 error->code == ENOTCONN ||
                                 error->code == EIO)) {
                mhg_lan_owner_end(owner, owner->generation, MHG_LAN_END_NETWORK,
                                  now_ms);
            } else {
                mhg_lan_owner_end(owner, owner->generation,
                                  MHG_LAN_END_PROTOCOL, now_ms);
            }
            return -1;
        }
        if (!got) return 0;
        if (mhg_lan_reply_auth_rejected(
                *reply, owner->pending.set_variable_value)) {
            cJSON_Delete(*reply);
            *reply = NULL;
            owner->stats.auth_failures += 1u;
            mhg_lan_owner_end(owner, owner->generation, MHG_LAN_END_AUTH,
                              now_ms);
            return mhg_errorf(error, EACCES,
                              "hub rejected call: session is not authenticated");
        }
        owner->pending = (struct mhg_lan_pending){0};
        owner->stats.replies += 1u;
        *ready = 1;
        return 0;
    }
    /* No request in flight: keep the connection serviced so server pings and
     * notifications are consumed while the session is idle. */
    {
        uint64_t deadline;

        if (mhg_deadline_after(owner->config.call_timeout_ms, &deadline, error))
            return -1;
        if (mhg_session_service_idle(owner->session, deadline, error)) {
            mhg_lan_owner_end(owner, owner->generation,
                              MHG_LAN_END_PROTOCOL, now_ms);
            return -1;
        }
    }
    return 0;
}

static void sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
    (void)nanosleep(&delay, NULL);
}

int mhg_lan_owner_attempt(struct mhg_lan_owner *owner, const char *url,
                          const char *passcode, const char *target_ip,
                          const char *target_did, const char *target_model,
                          uint64_t now_ms, size_t *device_count,
                          struct mhg_error *error)
{
    uint64_t generation;
    uint64_t deadline;
    cJSON *reply = NULL;
    int result = -1;

    if (device_count) *device_count = 0u;
    if (!owner || !url || !passcode || !target_ip || !target_did ||
        !target_model)
        return mhg_errorf(error, EINVAL, "invalid LAN attempt arguments");
    generation = mhg_lan_owner_begin(owner, now_ms);
    if (!generation)
        return mhg_errorf(error, EAGAIN, "LAN attempt is not allowed yet");
    if (mhg_lan_owner_connect(owner, generation, url, passcode, now_ms, error))
        return -1;
    if (mhg_lan_owner_submit(owner, generation, "/api/getDevList", NULL,
                             now_ms, error))
        return -1;
    if (mhg_deadline_after(owner->config.call_timeout_ms + 1000u, &deadline,
                           error))
        goto done;
    for (;;) {
        int ready = 0;

        if (mhg_lan_owner_service(owner, now_ms, &reply, &ready, error))
            goto done;
        if (ready) break;
        if (mhg_remaining_ms(deadline, 1, owner->config.stop, error) < 0) {
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_NETWORK, now_ms);
            goto done;
        }
        sleep_ms(10u);
    }
    if (cJSON_GetObjectItemCaseSensitive(reply, "error")) {
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
        mhg_errorf(error, EREMOTEIO, "gateway returned a JSON-RPC error");
        goto done;
    }
    {
        const cJSON *result_item =
            cJSON_GetObjectItemCaseSensitive(reply, "result");
        const cJSON *dev_list =
            cJSON_GetObjectItemCaseSensitive(result_item, "devList");

        if (!cJSON_IsObject(dev_list)) {
            mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
            mhg_errorf(error, EPROTO, "getDevList result has unexpected shape");
            goto done;
        }
        if (device_count) {
            const cJSON *item;
            size_t count = 0u;

            for (item = dev_list->child; item; item = item->next) ++count;
            *device_count = count;
        }
        if (mhg_lan_owner_check_membership(owner, generation, dev_list,
                                           target_did, target_model, now_ms,
                                           error))
            goto done;
    }
    if (mhg_lan_owner_verify_target(owner, generation, target_ip, now_ms,
                                    error))
        goto done;
    result = 0;

done:
    cJSON_Delete(reply);
    return result;
}

int mhg_lan_owner_verify_target(struct mhg_lan_owner *owner, uint64_t generation,
                                const char *expected_ip, uint64_t now_ms,
                                struct mhg_error *error)
{
    if (!owner || !expected_ip)
        return mhg_errorf(error, EINVAL, "invalid target verification arguments");
    if (generation != owner->generation || owner->state != MHG_LAN_ONLINE) {
        owner->stats.stale_rejections += 1u;
        return mhg_errorf(error, ESTALE, "stale LAN generation");
    }
    if (!mhg_url_host_matches(owner->attempt_url, expected_ip)) {
        /* The live session was not established through this address, so the
         * persisted identity cannot be attached to it. */
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
        return mhg_errorf(error, EPROTO,
                          "live session does not address the recorded target");
    }
    if (owner->binding != MHG_LAN_BIND_MEMBERSHIP) {
        /* Membership was never established against this attempt's list. */
        mhg_lan_owner_end(owner, generation, MHG_LAN_END_PROTOCOL, now_ms);
        return mhg_errorf(error, EPROTO,
                          "target identity was not matched on this session");
    }
    owner->binding = MHG_LAN_BIND_VERIFIED;
    return 0;
}

int mhg_lan_owner_pending(const struct mhg_lan_owner *owner)
{
    return owner && owner->pending.active;
}

enum mhg_lan_membership mhg_lan_membership_evaluate(
    const cJSON *dev_list, const char *target_did, const char *target_model)
{
    const cJSON *item;
    int found = 0;

    if (!target_did || !target_model) return MHG_LAN_MEMBERSHIP_MALFORMED;
    if (!cJSON_IsObject(dev_list)) return MHG_LAN_MEMBERSHIP_MALFORMED;
    /* The hub keys every entry by its DID and carries model/urn inside; a DID
     * field is not part of the real reply, but an entry that carries one must
     * agree with its key. */
    for (item = dev_list->child; item; item = item->next) {
        const cJSON *did = cJSON_GetObjectItemCaseSensitive(item, "did");
        const cJSON *model;

        if (!cJSON_IsObject(item) || !item->string || !item->string[0])
            return MHG_LAN_MEMBERSHIP_MALFORMED;
        if (did && (!cJSON_IsString(did) || !did->valuestring[0] ||
                    strcmp(item->string, did->valuestring) != 0))
            return MHG_LAN_MEMBERSHIP_MALFORMED;
        if (strcmp(item->string, target_did) != 0) continue;
        found = 1;
        model = cJSON_GetObjectItemCaseSensitive(item, "model");
        if (!cJSON_IsString(model) || !model->valuestring[0] ||
            strcmp(model->valuestring, target_model) != 0)
            return MHG_LAN_MEMBERSHIP_MISMATCH;
    }
    return found ? MHG_LAN_MEMBERSHIP_PRESENT : MHG_LAN_MEMBERSHIP_ABSENT;
}

void mhg_lan_owner_end(struct mhg_lan_owner *owner, uint64_t generation,
                       enum mhg_lan_end_reason reason, uint64_t now_ms)
{
    if (!owner || generation != owner->generation) return;
    close_attempt(owner);
    switch (reason) {
    case MHG_LAN_END_CANCELLED:
        owner->state = MHG_LAN_OFFLINE;
        owner->next_attempt_ms = 0u;
        owner->stats.backoff_ms = 0u;
        return;
    case MHG_LAN_END_AUTH:
        owner->state = MHG_LAN_AUTH_REQUIRED;
        break;
    case MHG_LAN_END_PROTOCOL:
        owner->state = MHG_LAN_PROTOCOL_ERROR;
        owner->stats.protocol_failures += 1u;
        break;
    case MHG_LAN_END_NETWORK:
    default:
        owner->state = MHG_LAN_BACKOFF;
        break;
    }
    owner->stats.consecutive_failures += 1u;
    owner->stats.backoff_ms = next_delay_ms(owner);
    if (owner->config.now_ms) {
        uint64_t completed = owner->config.now_ms(owner->config.clock_userdata);
        if (completed > now_ms) now_ms = completed;
    }
    owner->next_attempt_ms = now_ms + owner->stats.backoff_ms;
}

void mhg_lan_owner_stop(struct mhg_lan_owner *owner, uint64_t now_ms)
{
    if (!owner) return;
    owner->stopped = 1;
    close_attempt(owner);
    owner->state = MHG_LAN_OFFLINE;
    owner->next_attempt_ms = 0u;
    owner->stats.backoff_ms = 0u;
    (void)now_ms;
}

void mhg_lan_owner_destroy(struct mhg_lan_owner *owner)
{
    if (!owner) return;
    close_attempt(owner);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

int mhg_lan_owner_stopped(const struct mhg_lan_owner *owner)
{
    return owner && owner->stopped;
}

enum mhg_lan_state mhg_lan_owner_state(const struct mhg_lan_owner *owner)
{
    return owner ? owner->state : MHG_LAN_OFFLINE;
}

enum mhg_lan_binding mhg_lan_owner_binding(const struct mhg_lan_owner *owner)
{
    return owner ? owner->binding : MHG_LAN_BIND_NONE;
}

uint64_t mhg_lan_owner_generation(const struct mhg_lan_owner *owner)
{
    return owner ? owner->generation : 0u;
}

uint64_t mhg_lan_owner_backoff_ms(const struct mhg_lan_owner *owner)
{
    return owner ? owner->stats.backoff_ms : 0u;
}

uint64_t mhg_lan_owner_next_attempt_ms(const struct mhg_lan_owner *owner)
{
    return owner ? owner->next_attempt_ms : 0u;
}

int mhg_lan_owner_resources_open(const struct mhg_lan_owner *owner)
{
    return owner && owner->state == MHG_LAN_ONLINE &&
           owner->binding == MHG_LAN_BIND_VERIFIED;
}

void mhg_lan_owner_stats_get(const struct mhg_lan_owner *owner,
                             struct mhg_lan_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_lan_stats)MHG_LAN_STATS_INIT;
}

const char *mhg_lan_state_name(enum mhg_lan_state state)
{
    switch (state) {
    case MHG_LAN_OFFLINE: return "offline";
    case MHG_LAN_CONNECTING: return "connecting";
    case MHG_LAN_JPAKE: return "jpake";
    case MHG_LAN_ONLINE: return "online";
    case MHG_LAN_BACKOFF: return "backoff";
    case MHG_LAN_AUTH_REQUIRED: return "auth_required";
    case MHG_LAN_PROTOCOL_ERROR: return "protocol_error";
    }
    return NULL;
}

const char *mhg_lan_binding_name(enum mhg_lan_binding binding)
{
    switch (binding) {
    case MHG_LAN_BIND_NONE: return "none";
    case MHG_LAN_BIND_MEMBERSHIP: return "membership";
    case MHG_LAN_BIND_VERIFIED: return "verified";
    }
    return NULL;
}
