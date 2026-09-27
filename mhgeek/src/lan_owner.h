#ifndef MHGEEK_LAN_OWNER_H
#define MHGEEK_LAN_OWNER_H

#include "common.h"
#include "session.h"

#include <cjson/cJSON.h>
#include <stdbool.h>

/* One long-lived owner per target hub (§6.7): a successful attempt keeps its
 * WebSocket session, and every later RPC reuses it instead of calling the
 * cloud again. Every attempt allocates its own `lan_generation` before any
 * I/O, and every asynchronous result must name that generation to be accepted
 * (§6.2). Failed or ended attempts drop their generation together with all of
 * its pending work (§6.3). */
enum mhg_lan_state {
    MHG_LAN_OFFLINE = 0,
    MHG_LAN_CONNECTING,
    MHG_LAN_JPAKE,
    MHG_LAN_ONLINE,
    MHG_LAN_BACKOFF,
    MHG_LAN_AUTH_REQUIRED,
    MHG_LAN_PROTOCOL_ERROR,
};

/* §6.5: device-list membership is not proof that the endpoint is the target.
 * Until the authoritative self-identity mechanism is frozen, a consistent
 * directory entry only reaches MEMBERSHIP and never opens the resource phase. */
enum mhg_lan_binding {
    MHG_LAN_BIND_NONE = 0,
    MHG_LAN_BIND_MEMBERSHIP,
    MHG_LAN_BIND_VERIFIED,
};

/* One device list can only be judged against the exact target identity. The
 * verdict is split from the owner so it can be exercised without a session. */
enum mhg_lan_membership {
    MHG_LAN_MEMBERSHIP_ABSENT = 0,
    MHG_LAN_MEMBERSHIP_MISMATCH,
    MHG_LAN_MEMBERSHIP_MALFORMED,
    MHG_LAN_MEMBERSHIP_PRESENT,
};

enum mhg_lan_end_reason {
    MHG_LAN_END_CANCELLED = 0,
    MHG_LAN_END_NETWORK,
    MHG_LAN_END_AUTH,
    MHG_LAN_END_PROTOCOL,
};

struct mhg_lan_owner;

struct mhg_lan_config {
    /* Maximum complete protocol message, including the type byte. */
    size_t max_message;
    unsigned int connect_timeout_ms;
    unsigned int handshake_timeout_ms;
    unsigned int call_timeout_ms;
    /* §6.3: 1/2/4/8/16/30s by default, bounded jitter, reset only on success. */
    unsigned int backoff_initial_ms;
    unsigned int backoff_max_ms;
    const volatile sig_atomic_t *stop;
    /* Completion clock for blocking calls; NULL uses the supplied test time. */
    uint64_t (*now_ms)(void *userdata);
    void *clock_userdata;
};

#define MHG_LAN_CONFIG_DEFAULT \
    {4194304u, 5000u, 10000u, 10000u, 1000u, 30000u, NULL, NULL, NULL}

struct mhg_lan_stats {
    uint64_t attempts;
    uint64_t connect_failures;
    uint64_t handshake_failures;
    uint64_t auth_failures;
    uint64_t protocol_failures;
    uint64_t calls;
    uint64_t stale_rejections;
    uint64_t consecutive_failures;
    uint64_t reconnects;
    uint64_t backoff_ms;
    uint64_t submits;
    uint64_t replies;
    uint64_t submit_conflicts;
    uint64_t timeouts;
    uint64_t abandoned;
};

#define MHG_LAN_STATS_INIT \
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}

int mhg_lan_owner_create(struct mhg_lan_owner **owner_out,
                         const struct mhg_lan_config *config);
void mhg_lan_owner_destroy(struct mhg_lan_owner *owner);

/* Allocates the next `lan_generation` and enters CONNECTING, before any
 * socket work. Refused while ONLINE, while stopped, or on invalid input.
 * Returns the new generation, or 0 on refusal. */
uint64_t mhg_lan_owner_begin(struct mhg_lan_owner *owner, uint64_t now_ms);

/* One blocking attempt step: opens the transport and authenticates with the
 * current passcode. Only the generation returned by begin() is accepted; any
 * other value is refused as stale before any I/O. Ends the attempt on failure
 * and schedules the next backoff. */
int mhg_lan_owner_connect(struct mhg_lan_owner *owner, uint64_t generation,
                          const char *base_url, const char *passcode,
                          uint64_t now_ms, struct mhg_error *error);

/* Issues one RPC on the warm session. The caller's generation must match the
 * live attempt, otherwise the call is refused without I/O. */
int mhg_lan_owner_call(struct mhg_lan_owner *owner, uint64_t generation,
                       const char *method, const cJSON *params, cJSON **reply,
                       uint64_t now_ms, struct mhg_error *error);

/* The hub can report an expired session as JSON-RPC error.code; the observed
 * setVarValue refusal is result.code while reads still work. Other result
 * codes remain business results. Shared by blocking and asynchronous calls. */
bool mhg_lan_reply_auth_rejected(const cJSON *reply,
                                 bool set_variable_value);

/* Asynchronous path used by the scheduler (§6.7): submit() queues one request
 * on the warm session without waiting, and service() is a non-blocking step
 * that delivers the matching reply exactly once. Only one request may be in
 * flight per connection; a second submit is refused without I/O. A request
 * that is abandoned or times out leaves its result unknown, so the generation
 * ends instead of the session being reused. */
int mhg_lan_owner_submit(struct mhg_lan_owner *owner, uint64_t generation,
                         const char *method, const cJSON *params,
                         uint64_t now_ms, struct mhg_error *error);
int mhg_lan_owner_service(struct mhg_lan_owner *owner, uint64_t now_ms,
                          cJSON **reply, int *ready, struct mhg_error *error);
int mhg_lan_owner_pending(const struct mhg_lan_owner *owner);

/* Evaluates §6.5 against one device list: the exact target DID must appear with
 * the exact model. Even then the binding stays MEMBERSHIP, because membership
 * is not endpoint identity. */
int mhg_lan_owner_check_membership(struct mhg_lan_owner *owner,
                                   uint64_t generation, const cJSON *dev_list,
                                   const char *target_did,
                                   const char *target_model,
                                   uint64_t now_ms,
                                   struct mhg_error *error);
enum mhg_lan_membership mhg_lan_membership_evaluate(
    const cJSON *dev_list, const char *target_did, const char *target_model);

/* One complete attempt: allocate the generation, authenticate with the URL and
 * passcode of this bootstrap, read the device list, match the persisted target
 * identity and confirm the binding. Returns 0 only when the same generation
 * reached VERIFIED with the resource phase open. */
int mhg_lan_owner_attempt(struct mhg_lan_owner *owner, const char *url,
                          const char *passcode, const char *target_ip,
                          const char *target_did, const char *target_model,
                          uint64_t now_ms, size_t *device_count,
                          struct mhg_error *error);

/* Confirms §6.5 for the live generation: the attempt must have authenticated
 * through the persisted target's bootstrap (url host == expected_ip) and the
 * device list must already have matched that target DID/model. Only then does
 * the same generation reach VERIFIED and open the resource phase. The caller
 * passes the recorded identity, so a drifted record can never be re-bound
 * silently: a mismatch is refused and ends the attempt. */
int mhg_lan_owner_verify_target(struct mhg_lan_owner *owner, uint64_t generation,
                                const char *expected_ip, uint64_t now_ms,
                                struct mhg_error *error);

/* Ends the current generation: the session and every pending result of that
 * generation become invalid, and the next attempt is scheduled by §6.3. */
void mhg_lan_owner_end(struct mhg_lan_owner *owner, uint64_t generation,
                       enum mhg_lan_end_reason reason, uint64_t now_ms);

void mhg_lan_owner_stop(struct mhg_lan_owner *owner, uint64_t now_ms);
int mhg_lan_owner_stopped(const struct mhg_lan_owner *owner);
enum mhg_lan_state mhg_lan_owner_state(const struct mhg_lan_owner *owner);
enum mhg_lan_binding mhg_lan_owner_binding(const struct mhg_lan_owner *owner);
uint64_t mhg_lan_owner_generation(const struct mhg_lan_owner *owner);
/* Milliseconds to wait after the last ended attempt, bounded by the configured
 * maximum; 0 when an attempt may start immediately. */
uint64_t mhg_lan_owner_backoff_ms(const struct mhg_lan_owner *owner);
uint64_t mhg_lan_owner_next_attempt_ms(const struct mhg_lan_owner *owner);
/* The resource and event phases open only for a VERIFIED binding of the live
 * generation; membership alone keeps them closed. */
int mhg_lan_owner_resources_open(const struct mhg_lan_owner *owner);
void mhg_lan_owner_stats_get(const struct mhg_lan_owner *owner,
                             struct mhg_lan_stats *stats);
const char *mhg_lan_state_name(enum mhg_lan_state state);
const char *mhg_lan_binding_name(enum mhg_lan_binding binding);

#endif
