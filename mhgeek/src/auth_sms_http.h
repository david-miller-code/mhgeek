#ifndef MHGEEK_AUTH_SMS_HTTP_H
#define MHGEEK_AUTH_SMS_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "auth_sms.h"

struct mhg_auth_sms_http_config {
    /* NULL selects the production Xiaomi endpoint. Overrides must still use
     * HTTPS and are intended for a loopback test prefix on the same host. */
    const char *passport_base_url;
    const char *service_base_url;
    const char *ca_info;
    unsigned long connect_timeout_ms;
    unsigned long total_timeout_ms;
    size_t response_limit;
    bool allow_system_proxy;
#ifdef MHG_AUTH_SMS_HTTP_TESTING
    /* libcurl CONNECT_TO syntax. Test-only so production cannot redirect the
     * trusted account hostname to another peer. */
    const char *connect_to;
    const char *service_connect_to;
#endif
};

#define MHG_AUTH_SMS_HTTP_CONFIG_INIT \
    {NULL, NULL, NULL, 10000ul, 30000ul, 262144u, true \
     MHG_AUTH_SMS_HTTP_CONFIG_TEST_INIT}
#ifdef MHG_AUTH_SMS_HTTP_TESTING
#define MHG_AUTH_SMS_HTTP_CONFIG_TEST_INIT , NULL, NULL
#else
#define MHG_AUTH_SMS_HTTP_CONFIG_TEST_INIT
#endif

struct mhg_auth_sms_http_result {
    enum mhg_cloud_error cloud_error;
    struct mhg_passport_response passport;
    struct mhg_auth_sms_provider_diagnostic provider;
    struct mhg_secret_buf passport_device_id;
    struct mhg_secret_buf rotated_device_id;
    struct mhg_secret_buf rotated_user_id;
    struct mhg_secret_buf rotated_pass_token;
};

#define MHG_AUTH_SMS_HTTP_RESULT_INIT \
    {MHG_CLOUD_INTERNAL, MHG_PASSPORT_RESPONSE_INIT, \
     MHG_AUTH_SMS_PROVIDER_DIAGNOSTIC_INIT, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

enum mhg_ticket_candidate_source {
    MHG_TICKET_CANDIDATE_NONE = 0,
    MHG_TICKET_CANDIDATE_JSON = 1,
    MHG_TICKET_CANDIDATE_REDIRECT_COOKIE = 2,
};

enum mhg_auth_sms_http_stage {
    MHG_AUTH_SMS_HTTP_STAGE_NONE = 0,
    MHG_AUTH_SMS_HTTP_STAGE_POLICY = 1,
    MHG_AUTH_SMS_HTTP_STAGE_PREFERENCE = 2,
    MHG_AUTH_SMS_HTTP_STAGE_SEND_TICKET = 3,
    MHG_AUTH_SMS_HTTP_STAGE_PHONE_INFO = 4,
    MHG_AUTH_SMS_HTTP_STAGE_TICKET_AUTH = 5,
    MHG_AUTH_SMS_HTTP_STAGE_TICKET_REDIRECT = 6,
    MHG_AUTH_SMS_HTTP_STAGE_TOKEN_LOGIN = 7,
    MHG_AUTH_SMS_HTTP_STAGE_SERVICE_REDIRECT = 8,
};

struct mhg_auth_sms_http_stats {
    uint64_t total_requests;
    uint64_t passport_requests[6];
    uint64_t ticket_redirect_requests;
    uint64_t token_login_requests;
    uint64_t redirect_requests;
    enum mhg_auth_sms_http_stage last_stage;
    long last_http_status;
    bool ticket_token_present;
    bool json_pair_complete;
    bool redirect_cookie_pair_complete;
    bool pair_values_equal;
    enum mhg_ticket_candidate_source selected_source;
    bool passport_device_id_present;
};

struct mhg_auth_sms_http;

struct mhg_auth_sms_http_control {
    atomic_bool cancel_requested;
};

#define MHG_AUTH_SMS_HTTP_CONTROL_INIT {ATOMIC_VAR_INIT(false)}

void mhg_auth_sms_http_control_reset(
    struct mhg_auth_sms_http_control *control);
void mhg_auth_sms_http_control_cancel(
    struct mhg_auth_sms_http_control *control);

int mhg_auth_sms_http_create(struct mhg_auth_sms_http **owner_out,
                             const struct mhg_auth_sms_http_config *config);
void mhg_auth_sms_http_destroy(struct mhg_auth_sms_http *owner);

/* Executes one immutable typed work item. One owner serializes all calls and
 * exclusively owns its CURL handle, cookies, and response buffers. result
 * must begin at RESULT_INIT and be cleared before its storage is released.
 * Config string storage must remain valid for the owner's lifetime. */
enum mhg_cloud_error mhg_auth_sms_http_execute(
    struct mhg_auth_sms_http *owner, const struct mhg_auth_sms_work *work,
    const struct mhg_auth_sms_http_control *control,
    struct mhg_auth_sms_http_result *result);
void mhg_auth_sms_http_get_stats(struct mhg_auth_sms_http *owner,
                                 struct mhg_auth_sms_http_stats *stats);
const char *mhg_auth_sms_http_stage_name(
    enum mhg_auth_sms_http_stage stage);
const char *mhg_ticket_candidate_source_name(
    enum mhg_ticket_candidate_source source);
void mhg_auth_sms_http_result_clear(struct mhg_auth_sms_http_result *result);

/* Feeds an execution result back through the existing state machine without
 * weakening its generation/owner/operation checks. */
enum mhg_auth_sms_result mhg_auth_sms_http_complete(
    struct mhg_auth_sms *auth, const struct mhg_auth_sms_work *completed,
    const struct mhg_auth_sms_http_result *result, uint64_t now_ms,
    struct mhg_auth_sms_work *next);

#endif
