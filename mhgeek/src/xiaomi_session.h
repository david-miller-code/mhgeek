#ifndef MHGEEK_XIAOMI_SESSION_H
#define MHGEEK_XIAOMI_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "xiaomi_service.h"

/* One owner per SID: it owns that SID's CURL handle, cookie jar and published
 * session, and it never builds a request from the other SID's material. The
 * service account host is shared by both SIDs; the typed SID query selects the
 * endpoint, and the redirect chain only accepts the SID's own STS host. */
struct mhg_xiaomi_session_config {
    /* NULL selects the production account endpoint. An override must still be
     * the exact HTTPS account host. */
    const char *service_base_url;
    const char *ca_info;
    unsigned long connect_timeout_ms;
    unsigned long total_timeout_ms;
    size_t response_limit;
    bool allow_system_proxy;
    /* NULL-terminated libcurl CONNECT_TO entries, test-only: empty in
     * production so a trusted hostname can never be pointed at another peer.
     * A test supplies the account host and the SID's own STS host. */
    const char *connect_to[4];
};

#define MHG_XIAOMI_SESSION_CONFIG_INIT \
    {NULL, NULL, 10000ul, 30000ul, 262144u, true, {NULL, NULL, NULL, NULL}}

enum mhg_xiaomi_session_state {
    /* Nothing is published: no attempt has succeeded yet, or the SID was
     * invalidated by a rejected request. */
    MHG_XIAOMI_SESSION_EMPTY = 0,
    MHG_XIAOMI_SESSION_ACTIVE = 1,
    /* A rebuild after a rejection was rejected as well. Automatic bootstrap
     * must stop until this SID verifies successfully. */
    MHG_XIAOMI_SESSION_CREDENTIALS_SUSPECT = 2,
};

struct mhg_xiaomi_session_stats {
    uint64_t token_login_requests;
    uint64_t redirect_requests;
    uint64_t establishes;
    uint64_t session_generation;
    uint64_t consecutive_rejections;
    long last_http_status;
    enum mhg_cloud_error last_error;
    enum mhg_service_provider_class provider_class;
    int provider_code;
};

#define MHG_XIAOMI_SESSION_STATS_INIT \
    {0u, 0u, 0u, 0u, 0u, 0, MHG_CLOUD_OK, MHG_SERVICE_PROVIDER_NONE, 0}

struct mhg_xiaomi_session;

int mhg_xiaomi_session_create(struct mhg_xiaomi_session **owner_out,
                              enum mhg_xiaomi_sid sid,
                              const struct mhg_xiaomi_session_config *config);
void mhg_xiaomi_session_destroy(struct mhg_xiaomi_session *owner);
enum mhg_xiaomi_sid mhg_xiaomi_session_sid(
    const struct mhg_xiaomi_session *owner);
/* Stable name of a session state, or NULL for an unknown value. */
const char *mhg_xiaomi_session_state_name(enum mhg_xiaomi_session_state state);

/* One token-login and redirect-chain attempt for this SID, using the stored
 * base credential pair. A rejected pair counts towards the suspect state; any
 * other failure leaves an already published session untouched. */
enum mhg_cloud_error mhg_xiaomi_session_establish(
    struct mhg_xiaomi_session *owner, const char *user_id,
    const char *pass_token);

/* The published session, or NULL while the SID is not active. */
const struct mhg_service_session *mhg_xiaomi_session_current(
    const struct mhg_xiaomi_session *owner);
enum mhg_xiaomi_session_state mhg_xiaomi_session_state(
    const struct mhg_xiaomi_session *owner);
/* Drops this SID's session after a rejected request without touching the
 * rejection history or the other SID. */
void mhg_xiaomi_session_invalidate(struct mhg_xiaomi_session *owner);
void mhg_xiaomi_session_stats_get(const struct mhg_xiaomi_session *owner,
                                  struct mhg_xiaomi_session_stats *stats);

/* Both SIDs, each with its own owner, jar, generation and state. */
struct mhg_xiaomi_sessions;

int mhg_xiaomi_sessions_create(struct mhg_xiaomi_sessions **sessions_out,
                               const struct mhg_xiaomi_session_config *config);
void mhg_xiaomi_sessions_destroy(struct mhg_xiaomi_sessions *sessions);
/* The per-SID owner, so a caller can drive one SID without naming a slot. */
struct mhg_xiaomi_session *mhg_xiaomi_sessions_owner(
    struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid);

/* Establishes both SIDs from one stored basis, each independently. Returns the
 * first failure while keeping every SID that did succeed. */
enum mhg_cloud_error mhg_xiaomi_sessions_establish_both(
    struct mhg_xiaomi_sessions *sessions, const char *user_id,
    const char *pass_token);
/* Rebuilds exactly one SID after that SID rejected a request. */
enum mhg_cloud_error mhg_xiaomi_sessions_rebuild(
    struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid,
    const char *user_id, const char *pass_token);
void mhg_xiaomi_sessions_invalidate(struct mhg_xiaomi_sessions *sessions,
                                    enum mhg_xiaomi_sid sid);
const struct mhg_service_session *mhg_xiaomi_sessions_current(
    const struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid);
enum mhg_xiaomi_session_state mhg_xiaomi_sessions_state(
    const struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid);
/* True only while both SIDs hold a verified session and neither base
 * credential pair is suspect; automatic bootstrap stays paused otherwise. */
bool mhg_xiaomi_sessions_bootstrap_ready(
    const struct mhg_xiaomi_sessions *sessions);

#endif
