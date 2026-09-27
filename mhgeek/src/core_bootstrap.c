#include "core_bootstrap.h"

#include "common.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct mhg_bootstrap {
    struct mhg_cloud_http *http;
    pthread_mutex_t lock;
    /* Core request ids are never reused: every run uses two fresh ids. */
    uint64_t next_request_id;
    /* Previous passcode, kept only to count repeats (nonsecret diagnostic). */
    struct mhg_secret_buf previous_passcode;
    struct mhg_bootstrap_stats stats;
};

int mhg_bootstrap_create(struct mhg_bootstrap **owner_out,
                         const struct mhg_bootstrap_config *config)
{
    struct mhg_bootstrap *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config) return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->next_request_id = 1u;
    owner->previous_passcode = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    owner->stats.last_error = MHG_CLOUD_OK;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return -1;
    }
    if (mhg_cloud_http_create(&owner->http, MHG_XIAOMI_SID_MIJIA,
                              &config->http) != 0) {
        pthread_mutex_destroy(&owner->lock);
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_bootstrap_destroy(struct mhg_bootstrap *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    mhg_cloud_http_destroy(owner->http);
    mhg_secret_buf_clear(&owner->previous_passcode);
    pthread_mutex_unlock(&owner->lock);
    pthread_mutex_destroy(&owner->lock);
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

static enum mhg_cloud_error run_rpc(struct mhg_bootstrap *owner,
                                    const struct mhg_service_session *session,
                                    enum mhg_core_method method,
                                    const struct mhg_bootstrap_target *target,
                                    struct mhg_cloud_http_result *result_data, uint64_t deadline)
{
    struct mhg_cloud_http_work work = MHG_CLOUD_HTTP_WORK_INIT;
    struct mhg_cloud_http_stats http_stats = MHG_CLOUD_HTTP_STATS_INIT;
    enum mhg_cloud_error result;

    result = mhg_cloud_http_work_core(&work, session, method,
                                      owner->next_request_id++,
                                      target->access_key, target->did,
                                      target->model);
    if (result == MHG_CLOUD_OK) {
        result = mhg_cloud_http_execute_deadline(owner->http, &work, result_data, deadline);
        mhg_cloud_http_stats_get(owner->http, &http_stats);
        owner->stats.http_requests = http_stats.total_requests;
        owner->stats.last_http_status =
            http_stats.last_http_status < 0 ? 0u :
            (uint64_t)http_stats.last_http_status;
        /* The rejected code is the only response field kept; it is fixed and
         * nonsecret, and it is what distinguishes a refused accessKey from a
         * device the cloud cannot reach. */
        if (result == MHG_CLOUD_SERVICE)
            owner->stats.last_provider_code = result_data->envelope.provider_code;
    }
    mhg_cloud_http_work_clear(&work);
    return result;
}

enum mhg_cloud_error mhg_bootstrap_probe_url(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target,
    struct mhg_secret_buf *url, uint64_t deadline)
{
    struct mhg_cloud_http_result result_data = MHG_CLOUD_HTTP_RESULT_INIT;
    struct mhg_core_autowebconfig autowebconfig = MHG_CORE_AUTOWEBCONFIG_INIT;
    enum mhg_cloud_error result;

    if (url) mhg_secret_buf_clear(url);
    if (!owner || !url) return MHG_CLOUD_INPUT;
    if (!session || session->sid != MHG_XIAOMI_SID_MIJIA)
        return session ? MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    if (!target || !target->did || !target->did[0] || !target->model ||
        !target->model[0] || !target->access_key || !target->access_key[0] ||
        !target->expected_host || !target->expected_host[0])
        return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    owner->stats.runs++;
    owner->stats.last_error = MHG_CLOUD_OK;
    owner->stats.last_provider_code = 0;

    result = run_rpc(owner, session, MHG_CORE_AUTOWEBCONFIG, target,
                     &result_data, deadline);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_core_parse_autowebconfig(
        session,
        MHG_BYTES_VIEW(result_data.envelope.result_json.data,
                       result_data.envelope.result_json.len),
        &autowebconfig);
    mhg_cloud_http_result_clear(&result_data);
    if (result != MHG_CLOUD_OK) goto out;
    if (!mhg_url_host_matches(
            (const char *)autowebconfig.url.data, target->expected_host)) {
        /* A Web URL that does not address the configured host means the cloud
         * answered for another device; no passcode is requested for it. */
        result = MHG_CLOUD_TARGET_MISMATCH;
        goto out;
    }

    *url = autowebconfig.url;
    autowebconfig.url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
out:
    owner->stats.last_error = result;
    mhg_core_autowebconfig_clear(&autowebconfig);
    mhg_cloud_http_result_clear(&result_data);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

enum mhg_cloud_error mhg_bootstrap_finish(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target, struct mhg_secret_buf *url,
    struct mhg_bootstrap_evidence *evidence)
{
    struct mhg_cloud_http_result result_data = MHG_CLOUD_HTTP_RESULT_INIT;
    struct mhg_core_passcode passcode = MHG_CORE_PASSCODE_INIT;
    enum mhg_cloud_error result;

    if (evidence) mhg_bootstrap_evidence_clear(evidence);
    if (!owner || !evidence || !url || !url->data || !target ||
        !target->did || !target->model || !target->access_key ||
        !mhg_url_host_matches((const char *)url->data, target->expected_host))
        return MHG_CLOUD_INPUT;
    if (!session || session->sid != MHG_XIAOMI_SID_MIJIA)
        return session ? MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    owner->stats.last_provider_code = 0;
    result = run_rpc(owner, session, MHG_CORE_CENTRAL_LINK_PASSCODE, target,
                     &result_data, 0u);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_core_parse_passcode(
        session,
        MHG_BYTES_VIEW(result_data.envelope.result_json.data,
                       result_data.envelope.result_json.len),
        &passcode);
    if (result != MHG_CLOUD_OK) goto out;

    owner->stats.bootstrap_generation++;
    if (owner->previous_passcode.data && passcode.value.data &&
        owner->previous_passcode.len == passcode.value.len &&
        memcmp(owner->previous_passcode.data, passcode.value.data,
               passcode.value.len) == 0)
        owner->stats.passcode_repeats += 1u;
    {
        struct mhg_secret_buf copy = MHG_SECRET_BUF_INIT;

        if (passcode.value.data &&
            mhg_secret_buf_set(&copy, (const char *)passcode.value.data,
                               passcode.value.len) == 0) {
            mhg_secret_buf_clear(&owner->previous_passcode);
            owner->previous_passcode = copy;
            copy = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
        }
        mhg_secret_buf_clear(&copy);
    }
    evidence->bootstrap_generation = owner->stats.bootstrap_generation;
    evidence->url = *url;
    evidence->passcode = passcode.value;
    *url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    passcode.value = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    result = MHG_CLOUD_OK;

out:
    owner->stats.last_error = result;
    mhg_core_passcode_clear(&passcode);
    mhg_cloud_http_result_clear(&result_data);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

enum mhg_cloud_error mhg_bootstrap_run(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target,
    struct mhg_bootstrap_evidence *evidence)
{
    struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
    enum mhg_cloud_error result;

    if (evidence) mhg_bootstrap_evidence_clear(evidence);
    if (!evidence) return MHG_CLOUD_INPUT;
    result = mhg_bootstrap_probe_url(owner, session, target, &url, 0u);
    if (result == MHG_CLOUD_OK)
        result = mhg_bootstrap_finish(owner, session, target, &url, evidence);
    mhg_secret_buf_clear(&url);
    return result;
}

void mhg_bootstrap_evidence_clear(struct mhg_bootstrap_evidence *evidence)
{
    if (!evidence) return;
    mhg_secret_buf_clear(&evidence->url);
    mhg_secret_buf_clear(&evidence->passcode);
    mhg_secure_clear(evidence, sizeof(*evidence));
}

void mhg_bootstrap_stats_get(const struct mhg_bootstrap *owner,
                             struct mhg_bootstrap_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_bootstrap_stats)
        MHG_BOOTSTRAP_STATS_INIT;
}
