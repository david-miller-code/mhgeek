#ifndef MHGEEK_AUTH_SMS_ADAPTER_H
#define MHGEEK_AUTH_SMS_ADAPTER_H

#include "auth_sms.h"

/* This typed service boundary is intentionally independent of libainice and
 * JSON. A later Bridge owner can parse one request, enqueue the returned work,
 * and expose the status snapshot without running network I/O synchronously. */
enum mhg_auth_sms_action {
    MHG_AUTH_SMS_ACTION_STATUS = 0,
    MHG_AUTH_SMS_ACTION_START = 1,
    MHG_AUTH_SMS_ACTION_RESEND = 2,
    MHG_AUTH_SMS_ACTION_VERIFY = 3,
    MHG_AUTH_SMS_ACTION_CANCEL = 4,
    MHG_AUTH_SMS_ACTION_CLEAR = 5,
    MHG_AUTH_SMS_ACTION_EXPIRE = 6,
    MHG_AUTH_SMS_ACTION_RETRY_PERSIST = 7,
    MHG_AUTH_SMS_ACTION_RETRY = 8,
};

struct mhg_auth_sms_request {
    enum mhg_auth_sms_action action;
    uint64_t operation_id;
    uint64_t challenge_generation;
    uint64_t now_ms;
    const char *calling_code;
    const char *national_number;
    const char *code;
};

struct mhg_auth_sms_reply {
    enum mhg_auth_sms_result result;
    struct mhg_auth_sms_status status;
    struct mhg_auth_sms_work work;
};

#define MHG_AUTH_SMS_REPLY_INIT \
    {MHG_AUTH_SMS_REJECTED_INPUT, {0}, MHG_AUTH_SMS_WORK_INIT}

/* reply/work outputs must use their INIT macro before first use. */
void mhg_auth_sms_reply_clear(struct mhg_auth_sms_reply *reply);
int mhg_auth_sms_dispatch(struct mhg_auth_sms *auth,
                          const struct mhg_auth_sms_request *request,
                          struct mhg_auth_sms_reply *reply);

#endif
