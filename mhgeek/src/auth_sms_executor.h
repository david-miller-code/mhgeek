#ifndef MHGEEK_AUTH_SMS_EXECUTOR_H
#define MHGEEK_AUTH_SMS_EXECUTOR_H

#include "auth_sms_adapter.h"
#include "auth_sms_http.h"

struct mhg_auth_sms_executor;

/* Creation restores the independent MHGeek account before constructing the
 * HTTP owner. Restore is passive and never emits an SMS or network request. */
int mhg_auth_sms_executor_create(
    struct mhg_auth_sms_executor **executor_out,
    const struct mhg_auth_sms_store *store,
    const struct mhg_auth_sms_http_config *http_config);
/* Safe against its one active run: requests cancellation and waits for that
 * deadline-bounded run to return. The owner must exclude new API calls once
 * destruction begins. */
void mhg_auth_sms_executor_destroy(struct mhg_auth_sms_executor *executor);

/* Dispatches the typed service API. START is rejected while a restored valid
 * account exists; callers must explicitly clear before authorizing another
 * account. */
int mhg_auth_sms_executor_dispatch(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_request *request,
    struct mhg_auth_sms_reply *reply);

/* Executes one already-issued work item synchronously on the serial owner and
 * submits its result to auth_sms. next must begin at WORK_INIT. */
enum mhg_auth_sms_result mhg_auth_sms_executor_run(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_work *work, uint64_t now_ms,
    struct mhg_auth_sms_work *next,
    enum mhg_cloud_error *cloud_error_out);

/* Commits cancellation in the state machine first, then signals the exact
 * active worker only when the operation was accepted. The caller supplies a
 * fresh monotonic operation id for cancellation. */
enum mhg_auth_sms_result mhg_auth_sms_executor_cancel(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_work *work, uint64_t cancel_operation_id);

void mhg_auth_sms_executor_status(struct mhg_auth_sms_executor *executor,
                                  uint64_t now_ms,
                                  struct mhg_auth_sms_status *status);
int mhg_auth_sms_executor_copy_account(
    struct mhg_auth_sms_executor *executor,
    struct mhg_account_record *output);
void mhg_auth_sms_executor_http_stats(
    struct mhg_auth_sms_executor *executor,
    struct mhg_auth_sms_http_stats *stats);
bool mhg_auth_sms_executor_http_is_active(
    struct mhg_auth_sms_executor *executor);

#endif
