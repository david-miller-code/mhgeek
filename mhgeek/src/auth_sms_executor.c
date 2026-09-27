#define _POSIX_C_SOURCE 200809L
#include "auth_sms_executor.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct mhg_auth_sms_executor {
    struct mhg_auth_sms *auth;
    struct mhg_auth_sms_http *http;
    pthread_mutex_t auth_lock;
    pthread_mutex_t lifecycle_lock;
    pthread_cond_t lifecycle_cond;
    struct mhg_auth_sms_http_control http_control;
    bool active_run;
    bool destroying;
    uint64_t active_challenge;
    uint64_t active_owner;
    uint64_t active_operation;
};

int mhg_auth_sms_executor_create(
    struct mhg_auth_sms_executor **executor_out,
    const struct mhg_auth_sms_store *store,
    const struct mhg_auth_sms_http_config *http_config)
{
    struct mhg_auth_sms_executor *executor;
    if (!executor_out) { errno = EINVAL; return -1; }
    *executor_out = NULL;
    executor = calloc(1u, sizeof(*executor));
    if (!executor) return -1;
    atomic_init(&executor->http_control.cancel_requested, false);
    if (pthread_mutex_init(&executor->auth_lock, NULL) != 0) {
        free(executor);
        errno = EIO;
        return -1;
    }
    if (pthread_mutex_init(&executor->lifecycle_lock, NULL) != 0) {
        pthread_mutex_destroy(&executor->auth_lock);
        free(executor);
        errno = EIO;
        return -1;
    }
    if (pthread_cond_init(&executor->lifecycle_cond, NULL) != 0) {
        pthread_mutex_destroy(&executor->lifecycle_lock);
        pthread_mutex_destroy(&executor->auth_lock);
        free(executor);
        errno = EIO;
        return -1;
    }
    if (mhg_auth_sms_create(&executor->auth, store) != 0 ||
        mhg_auth_sms_restore(executor->auth) != 0 ||
        mhg_auth_sms_http_create(&executor->http, http_config) != 0) {
        mhg_auth_sms_http_destroy(executor->http);
        mhg_auth_sms_destroy(executor->auth);
        pthread_cond_destroy(&executor->lifecycle_cond);
        pthread_mutex_destroy(&executor->lifecycle_lock);
        pthread_mutex_destroy(&executor->auth_lock);
        free(executor);
        return -1;
    }
    *executor_out = executor;
    return 0;
}

void mhg_auth_sms_executor_destroy(struct mhg_auth_sms_executor *executor)
{
    if (!executor) return;
    pthread_mutex_lock(&executor->lifecycle_lock);
    executor->destroying = true;
    if (executor->active_run)
        mhg_auth_sms_http_control_cancel(&executor->http_control);
    while (executor->active_run)
        pthread_cond_wait(&executor->lifecycle_cond,
                          &executor->lifecycle_lock);
    pthread_mutex_unlock(&executor->lifecycle_lock);
    mhg_auth_sms_http_destroy(executor->http);
    mhg_auth_sms_destroy(executor->auth);
    pthread_cond_destroy(&executor->lifecycle_cond);
    pthread_mutex_destroy(&executor->lifecycle_lock);
    pthread_mutex_destroy(&executor->auth_lock);
    free(executor);
}

int mhg_auth_sms_executor_dispatch(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_request *request,
    struct mhg_auth_sms_reply *reply)
{
    if (!executor || !request || !reply) { errno = EINVAL; return -1; }
    if (request->action == MHG_AUTH_SMS_ACTION_CANCEL) {
        int dispatched;
        pthread_mutex_lock(&executor->lifecycle_lock);
        pthread_mutex_lock(&executor->auth_lock);
        dispatched = mhg_auth_sms_dispatch(executor->auth, request, reply);
        if (dispatched == 0 && reply->result == MHG_AUTH_SMS_ACCEPTED &&
            executor->active_run)
            mhg_auth_sms_http_control_cancel(&executor->http_control);
        pthread_mutex_unlock(&executor->auth_lock);
        pthread_mutex_unlock(&executor->lifecycle_lock);
        return dispatched;
    }
    if (request->action == MHG_AUTH_SMS_ACTION_STATUS) {
        int dispatched;
        pthread_mutex_lock(&executor->auth_lock);
        dispatched = mhg_auth_sms_dispatch(executor->auth, request, reply);
        pthread_mutex_unlock(&executor->auth_lock);
        return dispatched;
    }
    pthread_mutex_lock(&executor->lifecycle_lock);
    if (executor->destroying || executor->active_run) {
        pthread_mutex_lock(&executor->auth_lock);
        mhg_auth_sms_reply_clear(reply);
        reply->result = MHG_AUTH_SMS_REJECTED_CONFLICT;
        mhg_auth_sms_get_status(executor->auth, request->now_ms,
                                &reply->status);
        pthread_mutex_unlock(&executor->auth_lock);
        pthread_mutex_unlock(&executor->lifecycle_lock);
        return 0;
    }
    pthread_mutex_lock(&executor->auth_lock);
    {
        int result = mhg_auth_sms_dispatch(executor->auth, request, reply);
        pthread_mutex_unlock(&executor->auth_lock);
        pthread_mutex_unlock(&executor->lifecycle_lock);
        return result;
    }
}

enum mhg_auth_sms_result mhg_auth_sms_executor_run(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_work *work, uint64_t now_ms,
    struct mhg_auth_sms_work *next,
    enum mhg_cloud_error *cloud_error_out)
{
    struct mhg_auth_sms_http_result result = MHG_AUTH_SMS_HTTP_RESULT_INIT;
    enum mhg_auth_sms_result completed;
    enum mhg_cloud_error cloud_error;
    if (cloud_error_out) *cloud_error_out = MHG_CLOUD_INPUT;
    if (!next) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(next);
    if (!executor || !work) return MHG_AUTH_SMS_REJECTED_INPUT;
    pthread_mutex_lock(&executor->lifecycle_lock);
    if (executor->destroying || executor->active_run) {
        pthread_mutex_unlock(&executor->lifecycle_lock);
        if (cloud_error_out) *cloud_error_out = MHG_CLOUD_NOT_DISPATCHED;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    pthread_mutex_lock(&executor->auth_lock);
    if (!mhg_auth_sms_work_is_current(executor->auth, work)) {
        pthread_mutex_unlock(&executor->auth_lock);
        pthread_mutex_unlock(&executor->lifecycle_lock);
        if (cloud_error_out) *cloud_error_out = MHG_CLOUD_NOT_DISPATCHED;
        return MHG_AUTH_SMS_REJECTED_STALE;
    }
    mhg_auth_sms_http_control_reset(&executor->http_control);
    executor->active_run = true;
    executor->active_challenge = work->challenge_generation;
    executor->active_owner = work->owner_generation;
    executor->active_operation = work->operation_id;
    pthread_mutex_unlock(&executor->auth_lock);
    pthread_mutex_unlock(&executor->lifecycle_lock);
    struct timespec started = {0}, finished = {0};
    bool clock_ok = clock_gettime(CLOCK_MONOTONIC, &started) == 0;
    cloud_error = mhg_auth_sms_http_execute(
        executor->http, work, &executor->http_control, &result);
    if (clock_ok && clock_gettime(CLOCK_MONOTONIC, &finished) == 0) {
        uint64_t elapsed_ms = (uint64_t)(finished.tv_sec - started.tv_sec) * 1000u;
        if (finished.tv_nsec >= started.tv_nsec)
            elapsed_ms += (uint64_t)(finished.tv_nsec - started.tv_nsec) / 1000000u;
        else
            elapsed_ms -= (uint64_t)(started.tv_nsec - finished.tv_nsec) / 1000000u;
        if (elapsed_ms <= UINT64_MAX - now_ms) now_ms += elapsed_ms;
    }
    if (cloud_error_out) *cloud_error_out = cloud_error;
    pthread_mutex_lock(&executor->auth_lock);
    completed = mhg_auth_sms_http_complete(executor->auth, work, &result,
                                           now_ms, next);
    pthread_mutex_unlock(&executor->auth_lock);
    mhg_auth_sms_http_result_clear(&result);
    pthread_mutex_lock(&executor->lifecycle_lock);
    executor->active_run = false;
    executor->active_challenge = 0u;
    executor->active_owner = 0u;
    executor->active_operation = 0u;
    pthread_cond_broadcast(&executor->lifecycle_cond);
    pthread_mutex_unlock(&executor->lifecycle_lock);
    return completed;
}

enum mhg_auth_sms_result mhg_auth_sms_executor_cancel(
    struct mhg_auth_sms_executor *executor,
    const struct mhg_auth_sms_work *work, uint64_t cancel_operation_id)
{
    if (!executor || !work) return MHG_AUTH_SMS_REJECTED_INPUT;
    pthread_mutex_lock(&executor->lifecycle_lock);
    pthread_mutex_lock(&executor->auth_lock);
    {
        enum mhg_auth_sms_result result;
        if (!mhg_auth_sms_work_is_current(executor->auth, work) ||
            (executor->active_run &&
             (executor->active_challenge != work->challenge_generation ||
              executor->active_owner != work->owner_generation ||
              executor->active_operation != work->operation_id)))
            result = MHG_AUTH_SMS_REJECTED_STALE;
        else
            result = mhg_auth_sms_cancel(executor->auth,
                                         cancel_operation_id);
        if (result == MHG_AUTH_SMS_ACCEPTED && executor->active_run)
            mhg_auth_sms_http_control_cancel(&executor->http_control);
        pthread_mutex_unlock(&executor->auth_lock);
        pthread_mutex_unlock(&executor->lifecycle_lock);
        return result;
    }
}

void mhg_auth_sms_executor_status(struct mhg_auth_sms_executor *executor,
                                  uint64_t now_ms,
                                  struct mhg_auth_sms_status *status)
{
    if (!executor || !status) return;
    pthread_mutex_lock(&executor->auth_lock);
    mhg_auth_sms_get_status(executor->auth, now_ms, status);
    pthread_mutex_unlock(&executor->auth_lock);
}

int mhg_auth_sms_executor_copy_account(
    struct mhg_auth_sms_executor *executor,
    struct mhg_account_record *output)
{
    int result;
    if (!executor || !output) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&executor->auth_lock);
    result = mhg_auth_sms_copy_account(executor->auth, output);
    pthread_mutex_unlock(&executor->auth_lock);
    return result;
}

void mhg_auth_sms_executor_http_stats(
    struct mhg_auth_sms_executor *executor,
    struct mhg_auth_sms_http_stats *stats)
{
    if (!executor || !stats) return;
    mhg_auth_sms_http_get_stats(executor->http, stats);
}

bool mhg_auth_sms_executor_http_is_active(
    struct mhg_auth_sms_executor *executor)
{
    bool active;
    if (!executor) return false;
    pthread_mutex_lock(&executor->lifecycle_lock);
    active = executor->active_run;
    pthread_mutex_unlock(&executor->lifecycle_lock);
    return active;
}
