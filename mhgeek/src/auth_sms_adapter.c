#include "auth_sms_adapter.h"

#include <errno.h>
#include <string.h>

void mhg_auth_sms_reply_clear(struct mhg_auth_sms_reply *reply)
{
    if (!reply) return;
    mhg_auth_sms_work_clear(&reply->work);
    memset(reply, 0, sizeof(*reply));
    reply->result = MHG_AUTH_SMS_REJECTED_INPUT;
}

int mhg_auth_sms_dispatch(struct mhg_auth_sms *auth,
                          const struct mhg_auth_sms_request *request,
                          struct mhg_auth_sms_reply *reply)
{
    enum mhg_auth_sms_result result;

    if (!reply) {
        errno = EINVAL;
        return -1;
    }
    mhg_auth_sms_reply_clear(reply);
    if (!auth || !request) {
        errno = EINVAL;
        return -1;
    }
    switch (request->action) {
    case MHG_AUTH_SMS_ACTION_STATUS:
        result = MHG_AUTH_SMS_ACCEPTED;
        break;
    case MHG_AUTH_SMS_ACTION_START:
        result = mhg_auth_sms_start(auth, request->calling_code,
                                    request->national_number,
                                    request->operation_id, &reply->work);
        break;
    case MHG_AUTH_SMS_ACTION_RESEND:
        result = mhg_auth_sms_resend(auth, request->operation_id,
                                     request->now_ms, &reply->work);
        break;
    case MHG_AUTH_SMS_ACTION_VERIFY:
        result = mhg_auth_sms_verify(auth, request->code,
                                     request->operation_id, &reply->work);
        break;
    case MHG_AUTH_SMS_ACTION_CANCEL:
        result = mhg_auth_sms_cancel(auth, request->operation_id);
        break;
    case MHG_AUTH_SMS_ACTION_CLEAR:
        result = mhg_auth_sms_clear(auth, request->operation_id);
        break;
    case MHG_AUTH_SMS_ACTION_EXPIRE:
        result = mhg_auth_sms_expire(auth,
                                     request->challenge_generation);
        break;
    case MHG_AUTH_SMS_ACTION_RETRY_PERSIST:
        result = mhg_auth_sms_retry_persist(
            auth, request->challenge_generation, request->operation_id);
        break;
    case MHG_AUTH_SMS_ACTION_RETRY:
        result = mhg_auth_sms_retry(auth, request->operation_id,
                                    &reply->work);
        break;
    default:
        result = MHG_AUTH_SMS_REJECTED_INPUT;
        break;
    }
    reply->result = result;
    mhg_auth_sms_get_status(auth, request->now_ms, &reply->status);
    return 0;
}
