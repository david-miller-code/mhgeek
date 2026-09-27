#define _POSIX_C_SOURCE 200809L

#include "cloud_http.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "https_client.h"
#include "xiaomi_account_url.h"

struct mhg_cloud_http {
    struct mhg_https_client *client;
    enum mhg_xiaomi_sid sid;
    struct mhg_cloud_http_config config;
    char passport_device_id[17];
    struct mhg_cloud_http_stats stats;
};

static int append_text(struct mhg_secret_buf *buffer,
                       const void *data, size_t length)
{
    unsigned char *grown;
    size_t total;
    if (!buffer || (!data && length != 0u) ||
        length > SIZE_MAX - buffer->len - 1u)
        return -1;
    total = buffer->len + length;
    grown = OPENSSL_realloc(buffer->data, total + 1u);
    if (!grown) return -1;
    buffer->data = grown;
    if (length) memcpy(buffer->data + buffer->len, data, length);
    buffer->len = total;
    buffer->data[total] = '\0';
    return 0;
}

static int append_cstr(struct mhg_secret_buf *buffer, const char *text)
{
    return append_text(buffer, text, strlen(text));
}

/* Mirrors the tracked client: sixteen alphanumerics drawn from the reference
 * base-62 alphabet, fixed for the owner's lifetime. */
static int generate_passport_device_id(char output[17])
{
    static const char alphabet[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* MHG_PUBLIC_PROTOCOL_MATERIAL */
    unsigned char bytes[16];
    size_t index;

    if (!output) return -1;
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) return -1;
    for (index = 0u; index < sizeof(bytes); ++index)
        output[index] = alphabet[bytes[index] % 62u];
    output[16] = '\0';
    mhg_secure_clear(bytes, sizeof(bytes));
    return 0;
}

static const char *base_url_for(const struct mhg_cloud_http *owner,
                                enum mhg_cloud_http_kind kind)
{
    if (kind == MHG_CLOUD_HTTP_CATALOG)
        return owner->config.catalog_base_url ?
               owner->config.catalog_base_url : mhg_catalog_base_url();
    return owner->config.core_base_url ?
           owner->config.core_base_url : mhg_core_base_url();
}

static enum mhg_cloud_error session_copy(
    struct mhg_service_session *destination,
    const struct mhg_service_session *source)
{
    mhg_service_session_clear(destination);
    if (!source || !mhg_xiaomi_sid_name(source->sid) ||
        !source->user_id.data || !source->cuser_id.data ||
        !source->service_token.data || !source->ssecurity.data)
        return MHG_CLOUD_INPUT;
    destination->sid = source->sid;
    if (mhg_secret_buf_set(&destination->user_id, source->user_id.data,
                           source->user_id.len) != 0 ||
        mhg_secret_buf_set(&destination->cuser_id, source->cuser_id.data,
                           source->cuser_id.len) != 0 ||
        mhg_secret_buf_set(&destination->service_token,
                           source->service_token.data,
                           source->service_token.len) != 0 ||
        mhg_secret_buf_set(&destination->ssecurity, source->ssecurity.data,
                           source->ssecurity.len) != 0)
        goto failed;
    if (source->pass_token.data &&
        mhg_secret_buf_set(&destination->pass_token, source->pass_token.data,
                           source->pass_token.len) != 0)
        goto failed;
    return MHG_CLOUD_OK;

failed:
    mhg_service_session_clear(destination);
    return MHG_CLOUD_INTERNAL;
}

int mhg_cloud_http_create(struct mhg_cloud_http **owner_out,
                          enum mhg_xiaomi_sid sid,
                          const struct mhg_cloud_http_config *config)
{
    struct mhg_cloud_http *owner;
    struct mhg_https_client_config http = MHG_HTTPS_CLIENT_CONFIG_INIT;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || !mhg_xiaomi_sid_name(sid)) return -1;
    if (config->response_limit == 0u ||
        !mhg_https_url_is_trusted_for_exact_host(
            config->catalog_base_url ? config->catalog_base_url :
                                       mhg_catalog_base_url(),
            "api.io.mi.com") ||
        !mhg_https_url_is_trusted_for_exact_host(
            config->core_base_url ? config->core_base_url :
                                    mhg_core_base_url(),
            "core.api.mijia.tech"))
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->sid = sid;
    owner->config = *config;
    owner->stats.last_error = MHG_CLOUD_OK;
    if (generate_passport_device_id(owner->passport_device_id) != 0) {
        free(owner);
        return -1;
    }
    http.ca_info = config->ca_info;
    http.connect_timeout_ms = config->connect_timeout_ms;
    http.total_timeout_ms = config->total_timeout_ms;
    http.response_limit = config->response_limit;
    http.allow_system_proxy = config->allow_system_proxy;
#ifdef MHG_CLOUD_HTTP_TESTING
    http.connect_to[0] = config->catalog_connect_to;
    http.connect_to[1] = config->core_connect_to;
#endif
    if (mhg_https_client_create(&owner->client, &http) != 0) {
        mhg_secure_clear(owner->passport_device_id,
                         sizeof(owner->passport_device_id));
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_cloud_http_destroy(struct mhg_cloud_http *owner)
{
    if (!owner) return;
    mhg_https_client_destroy(owner->client);
    mhg_secure_clear(owner->passport_device_id,
                     sizeof(owner->passport_device_id));
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

const char *mhg_cloud_http_kind_name(enum mhg_cloud_http_kind kind)
{
    if (kind == MHG_CLOUD_HTTP_CATALOG) return "catalog";
    if (kind == MHG_CLOUD_HTTP_CORE) return "core";
    return NULL;
}

static enum mhg_cloud_error sid_for_kind(enum mhg_cloud_http_kind kind,
                                         enum mhg_xiaomi_sid *sid_out)
{
    if (kind == MHG_CLOUD_HTTP_CATALOG) {
        if (sid_out) *sid_out = MHG_XIAOMI_SID_XIAOMIIO;
        return MHG_CLOUD_OK;
    }
    if (kind == MHG_CLOUD_HTTP_CORE) {
        if (sid_out) *sid_out = MHG_XIAOMI_SID_MIJIA;
        return MHG_CLOUD_OK;
    }
    return MHG_CLOUD_INPUT;
}

enum mhg_cloud_error mhg_cloud_http_work_catalog(
    struct mhg_cloud_http_work *work, const struct mhg_service_session *session,
    const char *params_json)
{
    enum mhg_cloud_error result;

    if (work) mhg_cloud_http_work_clear(work);
    if (!work || !params_json) return MHG_CLOUD_INPUT;
    work->kind = MHG_CLOUD_HTTP_CATALOG;
    result = session_copy(&work->session, session);
    if (result != MHG_CLOUD_OK) goto failed;
    if (work->session.sid != MHG_XIAOMI_SID_XIAOMIIO) {
        result = MHG_CLOUD_SID_MISMATCH;
        goto failed;
    }
    if (mhg_secret_buf_set(&work->data_json, params_json,
                           strlen(params_json)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto failed;
    }
    return MHG_CLOUD_OK;

failed:
    mhg_cloud_http_work_clear(work);
    return result;
}

enum mhg_cloud_error mhg_cloud_http_work_core(
    struct mhg_cloud_http_work *work, const struct mhg_service_session *session,
    enum mhg_core_method method, uint64_t id, const char *access_key,
    const char *did, const char *model)
{
    enum mhg_cloud_error result;

    if (work) mhg_cloud_http_work_clear(work);
    if (!work || !did || !did[0] || !model || !model[0])
        return MHG_CLOUD_INPUT;
    work->kind = MHG_CLOUD_HTTP_CORE;
    result = session_copy(&work->session, session);
    if (result != MHG_CLOUD_OK) goto failed;
    if (work->session.sid != MHG_XIAOMI_SID_MIJIA) {
        result = MHG_CLOUD_SID_MISMATCH;
        goto failed;
    }
    if (mhg_secret_buf_set(&work->did, did, strlen(did)) != 0 ||
        mhg_secret_buf_set(&work->model, model, strlen(model)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto failed;
    }
    result = mhg_core_build_data(method, id, access_key, &work->data_json);
    if (result != MHG_CLOUD_OK) goto failed;
    return MHG_CLOUD_OK;

failed:
    mhg_cloud_http_work_clear(work);
    return result;
}

void mhg_cloud_http_work_clear(struct mhg_cloud_http_work *work)
{
    if (!work) return;
    mhg_service_session_clear(&work->session);
    mhg_secret_buf_clear(&work->data_json);
    mhg_secret_buf_clear(&work->did);
    mhg_secret_buf_clear(&work->model);
    mhg_secure_clear(work, sizeof(*work));
}

static enum mhg_cloud_error build_core_headers(
    const struct mhg_cloud_http_work *work, struct curl_slist **headers_out)
{
    const struct mhg_core_header *profile;
    struct curl_slist *headers = NULL;
    size_t count = 0u;
    size_t index;

    profile = mhg_core_compatible_headers(&count);
    if (!profile || count == 0u) return MHG_CLOUD_INTERNAL;
    for (index = 0u; index < count; ++index) {
        const char *value = profile[index].value;
        struct curl_slist *grown;

        if (profile[index].source == MHG_CORE_HEADER_MODEL)
            value = (const char *)work->model.data;
        if (!profile[index].name || !value) {
            mhg_https_client_free_headers(headers);
            return MHG_CLOUD_INTERNAL;
        }
        grown = mhg_https_client_append_header(headers, profile[index].name,
                                               value);
        if (!grown) {
            mhg_https_client_free_headers(headers);
            return MHG_CLOUD_INTERNAL;
        }
        headers = grown;
    }
    *headers_out = headers;
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_cloud_http_execute(
    struct mhg_cloud_http *owner, const struct mhg_cloud_http_work *work,
    struct mhg_cloud_http_result *result)
{
    return mhg_cloud_http_execute_deadline(owner, work, result, 0u);
}

enum mhg_cloud_error mhg_cloud_http_execute_deadline(
    struct mhg_cloud_http *owner, const struct mhg_cloud_http_work *work,
    struct mhg_cloud_http_result *result, uint64_t deadline)
{
    struct mhg_secret_buf path = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf body = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cookie = MHG_SECRET_BUF_INIT;
    struct mhg_cloud_form form = MHG_CLOUD_FORM_INIT;
    struct mhg_https_response response = MHG_HTTPS_RESPONSE_INIT;
    struct mhg_https_request request = MHG_HTTPS_REQUEST_INIT;
    struct curl_slist *headers = NULL;
    unsigned char random_prefix[8];
    unsigned char nonce[12];
    unsigned char signed_nonce[32];
    enum mhg_xiaomi_sid required_sid = MHG_XIAOMI_SID_XIAOMIIO;
    long status = 0;
    enum mhg_cloud_error result_code;

    if (result) mhg_cloud_http_result_clear(result);
    if (!owner || !work || !result) return MHG_CLOUD_INPUT;
    result_code = sid_for_kind(work->kind, &required_sid);
    if (result_code != MHG_CLOUD_OK) return result_code;
    if (owner->sid != required_sid || work->session.sid != required_sid)
        return MHG_CLOUD_SID_MISMATCH;
    if (!work->data_json.data || !work->session.ssecurity.data ||
        work->session.ssecurity.len == 0u)
        return MHG_CLOUD_INPUT;
    if (work->kind == MHG_CLOUD_HTTP_CORE) {
        if (!work->did.data || !work->did.len || !work->model.data)
            return MHG_CLOUD_INPUT;
        result_code = mhg_core_validate_data(
            (const char *)work->data_json.data);
        if (result_code != MHG_CLOUD_OK) return result_code;
        result_code = mhg_core_canonical_path(&work->session,
                                              (const char *)work->did.data,
                                              &path);
    } else {
        result_code = mhg_secret_buf_set(&path, mhg_catalog_path(),
                                         strlen(mhg_catalog_path()));
    }
    if (result_code != MHG_CLOUD_OK) goto out;
    if (RAND_bytes(random_prefix, (int)sizeof(random_prefix)) != 1) {
        result_code = MHG_CLOUD_INTERNAL;
        goto out;
    }
    mhg_cloud_nonce(random_prefix, (uint32_t)((uint64_t)time(NULL) / 60u),
                    nonce);
    result_code = mhg_cloud_signed_nonce(work->session.ssecurity.data,
                                         work->session.ssecurity.len, nonce,
                                         signed_nonce);
    if (result_code != MHG_CLOUD_OK) goto out;
    result_code = mhg_cloud_build_form((const char *)path.data,
                                       (const char *)work->data_json.data,
                                       work->session.ssecurity.data,
                                       work->session.ssecurity.len, nonce,
                                       &form);
    if (result_code != MHG_CLOUD_OK) goto out;
    result_code = mhg_cloud_form_encode(&form, &body);
    if (result_code != MHG_CLOUD_OK) goto out;
    result_code = mhg_service_cookie_profile(&work->session,
                                             owner->passport_device_id,
                                             &cookie);
    if (result_code != MHG_CLOUD_OK) goto out;
    if (append_cstr(&url, base_url_for(owner, work->kind)) != 0 ||
        append_text(&url, path.data, path.len) != 0) {
        result_code = MHG_CLOUD_INTERNAL;
        goto out;
    }
    if (work->kind == MHG_CLOUD_HTTP_CORE) {
        result_code = build_core_headers(work, &headers);
        if (result_code != MHG_CLOUD_OK) goto out;
    }
    struct curl_slist *grown = mhg_https_client_append_header(
        headers, "Content-Type", "application/x-www-form-urlencoded");
    if (!grown) {
        result_code = MHG_CLOUD_INTERNAL;
        goto out;
    }
    headers = grown;
    request.url = (const char *)url.data;
    request.method = "POST";
    request.headers = headers;
    request.body = &body;
    request.cookie = (const char *)cookie.data;
    request.deadline = mhg_https_now_ms() + owner->config.total_timeout_ms;
    if (deadline && deadline < request.deadline) request.deadline = deadline;
    owner->stats.total_requests++;
    result_code = mhg_https_client_perform(owner->client, &request, &response,
                                           &status);
    owner->stats.last_http_status = status;
    if (result_code != MHG_CLOUD_OK) goto out;
    result_code = mhg_cloud_classify_http((int)status);
    if (result_code != MHG_CLOUD_OK) goto out;
    result_code = mhg_cloud_decrypt_envelope(
        MHG_BYTES_VIEW(response.data, response.len), signed_nonce,
        &result->envelope);
    if (result_code != MHG_CLOUD_OK) goto out;
    result->http_status = status;

out:
    owner->stats.last_error = result_code;
    mhg_https_response_clear(&response);
    mhg_https_client_free_headers(headers);
    mhg_cloud_form_clear(&form);
    mhg_secret_buf_clear(&body);
    mhg_secret_buf_clear(&cookie);
    mhg_secret_buf_clear(&url);
    mhg_secret_buf_clear(&path);
    mhg_secure_clear(random_prefix, sizeof(random_prefix));
    mhg_secure_clear(nonce, sizeof(nonce));
    mhg_secure_clear(signed_nonce, sizeof(signed_nonce));
    if (result_code == MHG_CLOUD_SERVICE) {
        /* Keep the fixed nonsecret rejected code; the envelope writer already
         * left the result empty. */
        mhg_secret_buf_clear(&result->envelope.result_json);
    } else if (result_code != MHG_CLOUD_OK) {
        mhg_cloud_http_result_clear(result);
    }
    return result_code;
}

void mhg_cloud_http_result_clear(struct mhg_cloud_http_result *result)
{
    if (!result) return;
    mhg_cloud_envelope_clear(&result->envelope);
    result->http_status = 0;
}

void mhg_cloud_http_stats_get(const struct mhg_cloud_http *owner,
                              struct mhg_cloud_http_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_cloud_http_stats)
        MHG_CLOUD_HTTP_STATS_INIT;
}
