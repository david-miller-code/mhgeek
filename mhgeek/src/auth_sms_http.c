#define _POSIX_C_SOURCE 200809L

#include "auth_sms_http.h"

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "xiaomi_service.h"
#include "xiaomi_account_url.h"
#include "passport_device_id.h"

struct response_buffer {
    unsigned char *data;
    size_t len;
    size_t capacity;
    size_t limit;
    bool overflow;
    bool internal_failure;
    bool header_malformed;
    bool saw_extension_pragma;
    bool saw_location;
    struct mhg_secret_buf extension_pragma;
    struct mhg_secret_buf location;
};

struct mhg_auth_sms_http {
    CURL *curl;
    struct mhg_auth_sms_http_config config;
    pthread_mutex_t execute_lock;
    const struct mhg_auth_sms_http_control *active_control;
    char device_id[MHG_PASSPORT_DEVICE_ID_SIZE];
    uint64_t device_id_challenge_generation;
    uint64_t passport_cookie_challenge_generation;
    struct mhg_auth_sms_http_stats stats;
};

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_global_result = CURLE_FAILED_INIT;

static void init_curl(void)
{
    curl_global_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static uint64_t monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0u;
    return (uint64_t)value.tv_sec * 1000u +
           (uint64_t)value.tv_nsec / 1000000u;
}

static void response_clear(struct response_buffer *response)
{
    if (!response) return;
    if (response->data) {
        mhg_secure_clear(response->data, response->capacity);
        free(response->data);
    }
    mhg_secret_buf_clear(&response->extension_pragma);
    mhg_secret_buf_clear(&response->location);
    memset(response, 0, sizeof(*response));
}

static size_t response_write(char *input, size_t size, size_t count,
                             void *userdata)
{
    struct response_buffer *response = userdata;
    size_t bytes;
    size_t needed;
    size_t capacity;
    unsigned char *grown;

    if (!response || (size != 0u && count > SIZE_MAX / size)) return 0u;
    bytes = size * count;
    if (bytes > response->limit - response->len) {
        response->overflow = true;
        return 0u;
    }
    needed = response->len + bytes + 1u;
    if (needed > response->capacity) {
        capacity = response->capacity ? response->capacity : 1024u;
        while (capacity < needed) {
            if (capacity > (response->limit + 1u) / 2u) {
                capacity = response->limit + 1u;
                break;
            }
            capacity *= 2u;
        }
        grown = realloc(response->data, capacity);
        if (!grown) {
            response->internal_failure = true;
            return 0u;
        }
        response->data = grown;
        response->capacity = capacity;
    }
    if (bytes) memcpy(response->data + response->len, input, bytes);
    response->len += bytes;
    response->data[response->len] = '\0';
    return bytes;
}

static size_t response_header(char *input, size_t size, size_t count,
                              void *userdata)
{
    static const char extension_name[] = "extension-pragma:";
    static const char location_name[] = "location:";
    struct response_buffer *response = userdata;
    struct mhg_secret_buf *destination;
    size_t name_length;
    size_t bytes;
    size_t begin;
    size_t end;

    if (!response || (size != 0u && count > SIZE_MAX / size)) return 0u;
    bytes = size * count;
    if (bytes >= 5u && strncasecmp(input, "HTTP/", 5u) == 0) {
        mhg_secret_buf_clear(&response->extension_pragma);
        mhg_secret_buf_clear(&response->location);
        response->header_malformed = false;
        response->saw_extension_pragma = false;
        response->saw_location = false;
        return bytes;
    }
    if (bytes >= sizeof(extension_name) - 1u &&
        strncasecmp(input, extension_name,
                    sizeof(extension_name) - 1u) == 0) {
        name_length = sizeof(extension_name) - 1u;
        destination = &response->extension_pragma;
        if (response->saw_extension_pragma) {
            response->header_malformed = true;
            return bytes;
        }
        response->saw_extension_pragma = true;
    } else if (bytes >= sizeof(location_name) - 1u &&
               strncasecmp(input, location_name,
                           sizeof(location_name) - 1u) == 0) {
        name_length = sizeof(location_name) - 1u;
        destination = &response->location;
        if (response->saw_location) {
            response->header_malformed = true;
            return bytes;
        }
        response->saw_location = true;
    } else {
        return bytes;
    }
    begin = name_length;
    while (begin < bytes && (input[begin] == ' ' || input[begin] == '\t'))
        ++begin;
    end = bytes;
    while (end > begin && (input[end - 1u] == '\r' ||
                           input[end - 1u] == '\n' ||
                           input[end - 1u] == ' ' || input[end - 1u] == '\t'))
        --end;
    if (end - begin > response->limit) {
        response->overflow = true;
        return 0u;
    }
    if (end == begin) {
        response->header_malformed = true;
        return bytes;
    }
    if (mhg_secret_buf_set(destination, input + begin,
                           end - begin) != 0) {
        response->internal_failure = true;
        return 0u;
    }
    return bytes;
}

static int transfer_progress(void *userdata, curl_off_t down_total,
                             curl_off_t down_now, curl_off_t up_total,
                             curl_off_t up_now)
{
    struct mhg_auth_sms_http *owner = userdata;
    bool canceled = false;
    (void)down_total;
    (void)down_now;
    (void)up_total;
    (void)up_now;
    if (owner->active_control)
        canceled = atomic_load_explicit(
            &owner->active_control->cancel_requested, memory_order_relaxed);
    return canceled ? 1 : 0;
}

static enum mhg_cloud_error map_curl(CURLcode code,
                                     const struct response_buffer *response)
{
    if (response->overflow || response->header_malformed)
        return MHG_CLOUD_MALFORMED;
    if (response->internal_failure) return MHG_CLOUD_INTERNAL;
    switch (code) {
    case CURLE_OK: return MHG_CLOUD_OK;
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CIPHER:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_SSL_ISSUER_ERROR:
        return MHG_CLOUD_CRYPTO;
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_COULDNT_CONNECT:
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_ABORTED_BY_CALLBACK:
        return MHG_CLOUD_NETWORK;
    case CURLE_WEIRD_SERVER_REPLY: return MHG_CLOUD_MALFORMED;
    case CURLE_OUT_OF_MEMORY: return MHG_CLOUD_INTERNAL;
    default: return MHG_CLOUD_NETWORK;
    }
}

static int https_base_is_valid(const char *value)
{
    return value && !strchr(value, '?') &&
           mhg_xiaomi_account_redirect_is_trusted(value);
}

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

static int append_pair(CURL *curl, struct mhg_secret_buf *output,
                       bool *first, const char *name,
                       const unsigned char *value, size_t value_len)
{
    char *escaped;
    if (value_len > INT_MAX) return -1;
    escaped = curl_easy_escape(curl, (const char *)value, (int)value_len);
    if (!escaped) return -1;
    if ((!*first && append_cstr(output, "&") != 0) ||
        append_cstr(output, name) != 0 || append_cstr(output, "=") != 0 ||
        append_cstr(output, escaped) != 0) {
        curl_free(escaped);
        return -1;
    }
    curl_free(escaped);
    *first = false;
    return 0;
}

static int base64_secret(const struct mhg_secret_buf *input,
                         struct mhg_secret_buf *output)
{
    size_t capacity;
    int length;
    unsigned char *encoded;
    if (!input || !input->data || input->len > INT_MAX) return -1;
    capacity = 4u * ((input->len + 2u) / 3u);
    encoded = malloc(capacity + 1u);
    if (!encoded) return -1;
    length = EVP_EncodeBlock(encoded, input->data, (int)input->len);
    if (length < 0 ||
        mhg_secret_buf_set(output, encoded, (size_t)length) != 0) {
        mhg_secure_clear(encoded, capacity + 1u);
        free(encoded);
        return -1;
    }
    mhg_secure_clear(encoded, capacity + 1u);
    free(encoded);
    return 0;
}

static int generated_hex(char *output, size_t byte_count)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[16];
    size_t index;
    if (!output || byte_count > sizeof(bytes) || RAND_bytes(bytes,
                                              (int)byte_count) != 1)
        return -1;
    for (index = 0u; index < byte_count; ++index) {
        output[index * 2u] = hex[bytes[index] >> 4u];
        output[index * 2u + 1u] = hex[bytes[index] & 15u];
    }
    output[byte_count * 2u] = '\0';
    mhg_secure_clear(bytes, sizeof(bytes));
    return 0;
}

static int work_is_valid(const struct mhg_auth_sms_work *work)
{
    return work && work->kind != MHG_AUTH_SMS_WORK_NONE &&
           work->challenge_generation != 0u &&
           work->owner_generation != 0u && work->operation_id != 0u;
}

static unsigned long remaining_ms(const struct mhg_auth_sms_http *owner,
                                  uint64_t deadline)
{
    uint64_t now = monotonic_ms();
    uint64_t left;
    if (!now || now >= deadline) return 1ul;
    left = deadline - now;
    if (left > owner->config.total_timeout_ms)
        left = owner->config.total_timeout_ms;
    return left > ULONG_MAX ? ULONG_MAX : (unsigned long)left;
}

static enum mhg_cloud_error perform(struct mhg_auth_sms_http *owner,
                                    enum mhg_auth_sms_http_stage stage,
                                    const char *url,
                                    const char *method,
                                    const struct curl_slist *headers,
                                    const struct mhg_secret_buf *body,
                                    const char *cookie,
                                    bool accept_redirect,
                                    uint64_t deadline,
                                    struct response_buffer *response,
                                    long *http_status)
{
    CURLcode code;
    unsigned long timeout;
    struct curl_slist *connect_to = NULL;

    memset(response, 0, sizeof(*response));
    owner->stats.last_stage = stage;
    owner->stats.last_http_status = 0;
    response->extension_pragma = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    response->location = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    response->limit = owner->config.response_limit;
    timeout = remaining_ms(owner, deadline);
    curl_easy_reset(owner->curl);
    if (curl_easy_setopt(owner->curl, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_WRITEFUNCTION,
                         response_write) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_WRITEDATA, response) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_HEADERFUNCTION,
                         response_header) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_HEADERDATA, response) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_REDIR_PROTOCOLS_STR,
                         "https") != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_SUPPRESS_CONNECT_HEADERS,
                         1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_CONNECTTIMEOUT_MS,
                         owner->config.connect_timeout_ms) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_TIMEOUT_MS, timeout) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_XFERINFOFUNCTION,
                         transfer_progress) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_XFERINFODATA, owner) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_NOPROGRESS, 0L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_COOKIEFILE, "") != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (cookie && curl_easy_setopt(owner->curl, CURLOPT_COOKIE,
                                   cookie) != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (owner->config.ca_info &&
        curl_easy_setopt(owner->curl, CURLOPT_CAINFO,
                         owner->config.ca_info) != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (!owner->config.allow_system_proxy &&
        (curl_easy_setopt(owner->curl, CURLOPT_PROXY, "") != CURLE_OK ||
         curl_easy_setopt(owner->curl, CURLOPT_NOPROXY, "*") != CURLE_OK))
        return MHG_CLOUD_NOT_DISPATCHED;
#ifdef MHG_AUTH_SMS_HTTP_TESTING
    if (owner->config.connect_to) {
        connect_to = curl_slist_append(NULL, owner->config.connect_to);
        if (!connect_to) {
            curl_slist_free_all(connect_to);
            return MHG_CLOUD_NOT_DISPATCHED;
        }
    }
    if (owner->config.service_connect_to) {
        struct curl_slist *grown = curl_slist_append(
            connect_to, owner->config.service_connect_to);
        if (!grown) {
            curl_slist_free_all(connect_to);
            return MHG_CLOUD_NOT_DISPATCHED;
        }
        connect_to = grown;
    }
    if (connect_to && curl_easy_setopt(owner->curl, CURLOPT_CONNECT_TO,
                                       connect_to) != CURLE_OK) {
        curl_slist_free_all(connect_to);
        return MHG_CLOUD_NOT_DISPATCHED;
    }
#endif
    if (strcmp(method, "POST") == 0) {
        if (curl_easy_setopt(owner->curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(owner->curl, CURLOPT_POSTFIELDS,
                             body && body->data ?
                                 (const char *)body->data : "") != CURLE_OK ||
            curl_easy_setopt(owner->curl, CURLOPT_POSTFIELDSIZE_LARGE,
                             (curl_off_t)(body ? body->len : 0u)) != CURLE_OK) {
            curl_slist_free_all(connect_to);
            return MHG_CLOUD_NOT_DISPATCHED;
        }
    }
    code = curl_easy_perform(owner->curl);
    {
        CURLcode info = curl_easy_getinfo(owner->curl,
                                          CURLINFO_RESPONSE_CODE,
                                          http_status);
        if (code == CURLE_OK && info != CURLE_OK)
            code = CURLE_HTTP_RETURNED_ERROR;
        if (info == CURLE_OK) owner->stats.last_http_status = *http_status;
    }
    curl_slist_free_all(connect_to);
    if (code != CURLE_OK) return map_curl(code, response);
    if (response->overflow || response->header_malformed)
        return MHG_CLOUD_MALFORMED;
    if (response->internal_failure) return MHG_CLOUD_INTERNAL;
    if (*http_status == 401 || *http_status == 403)
        return MHG_CLOUD_AUTH_REJECTED;
    if (*http_status >= 200 && *http_status < 300) return MHG_CLOUD_OK;
    if (accept_redirect && *http_status >= 300 && *http_status < 400)
        return MHG_CLOUD_OK;
    return MHG_CLOUD_HTTP;
}

static enum mhg_auth_sms_http_stage passport_http_stage(
    enum mhg_passport_step step)
{
    switch (step) {
    case MHG_PASSPORT_POLICY: return MHG_AUTH_SMS_HTTP_STAGE_POLICY;
    case MHG_PASSPORT_PREFERENCE:
        return MHG_AUTH_SMS_HTTP_STAGE_PREFERENCE;
    case MHG_PASSPORT_SEND_TICKET:
        return MHG_AUTH_SMS_HTTP_STAGE_SEND_TICKET;
    case MHG_PASSPORT_PHONE_INFO:
        return MHG_AUTH_SMS_HTTP_STAGE_PHONE_INFO;
    case MHG_PASSPORT_TICKET_AUTH:
        return MHG_AUTH_SMS_HTTP_STAGE_TICKET_AUTH;
    default: return MHG_AUTH_SMS_HTTP_STAGE_NONE;
    }
}

static int append_header(struct curl_slist **headers,
                         const char *name, const char *value)
{
    struct mhg_secret_buf line = MHG_SECRET_BUF_INIT;
    struct curl_slist *grown;
    if (append_cstr(&line, name) != 0 || append_cstr(&line, ": ") != 0 ||
        append_cstr(&line, value) != 0) {
        mhg_secret_buf_clear(&line);
        return -1;
    }
    grown = curl_slist_append(*headers, (const char *)line.data);
    mhg_secret_buf_clear(&line);
    if (!grown) return -1;
    *headers = grown;
    return 0;
}

static void secure_slist_free(struct curl_slist *list)
{
    struct curl_slist *item;
    for (item = list; item; item = item->next)
        if (item->data) mhg_secure_clear(item->data, strlen(item->data));
    curl_slist_free_all(list);
}

static enum mhg_cloud_error seed_passport_cookie_jar(
    struct mhg_auth_sms_http *owner, uint64_t challenge_generation)
{
    const struct mhg_passport_request_contract *contract =
        mhg_passport_contract(MHG_PASSPORT_POLICY);
    size_t index;

    if (!owner || !contract || !challenge_generation)
        return MHG_CLOUD_INPUT;
    if (owner->passport_cookie_challenge_generation == challenge_generation)
        return MHG_CLOUD_OK;
    if (owner->device_id_challenge_generation != challenge_generation) {
        mhg_secure_clear(owner->device_id, sizeof(owner->device_id));
        if (mhg_passport_device_id_generate(owner->device_id) != 0)
            return MHG_CLOUD_INTERNAL;
        owner->device_id_challenge_generation = challenge_generation;
    }
    if (!mhg_passport_device_id_is_valid(
            (const unsigned char *)owner->device_id,
            strlen(owner->device_id)) ||
        curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL") != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    for (index = 0u; index < contract->cookie_count; ++index) {
        const struct mhg_passport_field *field = &contract->cookies[index];
        const char *value;
        struct mhg_secret_buf line = MHG_SECRET_BUF_INIT;
        enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;

        if (field->source == MHG_PASSPORT_GENERATED)
            value = owner->device_id;
        else if (field->source == MHG_PASSPORT_CONSTANT)
            value = field->constant_value;
        else
            return MHG_CLOUD_INPUT;
        if (append_cstr(&line, "account.xiaomi.com\tFALSE\t/\tTRUE\t0\t") == 0 &&
            append_cstr(&line, field->name) == 0 &&
            append_cstr(&line, "\t") == 0 &&
            append_cstr(&line, value) == 0 &&
            curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST,
                             (const char *)line.data) == CURLE_OK)
            result = MHG_CLOUD_OK;
        mhg_secret_buf_clear(&line);
        if (result != MHG_CLOUD_OK) return result;
    }
    owner->passport_cookie_challenge_generation = challenge_generation;
    owner->stats.ticket_token_present = false;
    owner->stats.json_pair_complete = false;
    owner->stats.redirect_cookie_pair_complete = false;
    owner->stats.pair_values_equal = false;
    owner->stats.selected_source = MHG_TICKET_CANDIDATE_NONE;
    owner->stats.passport_device_id_present = true;
    return MHG_CLOUD_OK;
}

struct selected_cookie {
    const char *name;
    struct mhg_secret_buf value;
    size_t path_length;
    bool found;
};

enum cookie_origin {
    COOKIE_ORIGIN_ACCOUNT = 1,
    COOKIE_ORIGIN_MIJIA_STS = 2,
    COOKIE_ORIGIN_XIAOMIIO_STS = 3,
};

#define MHG_MAX_REDIRECT_HOPS 4u

static int span_equals(const char *text, size_t length, const char *expected)
{
    return strlen(expected) == length && memcmp(text, expected, length) == 0;
}

static int cookie_domain_matches(enum cookie_origin origin,
                                 const char *domain, size_t length)
{
    static const char http_only[] = "#HttpOnly_";
    static const char host[] = "account.xiaomi.com";
    static const char parent[] = "xiaomi.com";
    static const char sts[] = "sts.api.mijia.tech";
    static const char sts_parent[] = "api.mijia.tech";
    static const char mijia_parent[] = "mijia.tech";
    static const char xiaomiio_sts[] = "sts.api.io.mi.com";
    static const char xiaomiio_sts_parent[] = "api.io.mi.com";
    static const char xiaomiio_io_parent[] = "io.mi.com";
    static const char xiaomiio_parent[] = "mi.com";
    if (length >= sizeof(http_only) - 1u &&
        memcmp(domain, http_only, sizeof(http_only) - 1u) == 0) {
        domain += sizeof(http_only) - 1u;
        length -= sizeof(http_only) - 1u;
    }
    if (length && domain[0] == '.') {
        ++domain;
        --length;
    }
    if (origin == COOKIE_ORIGIN_ACCOUNT)
        return (length == sizeof(host) - 1u &&
                strncasecmp(domain, host, length) == 0) ||
               (length == sizeof(parent) - 1u &&
                strncasecmp(domain, parent, length) == 0);
    if (origin == COOKIE_ORIGIN_MIJIA_STS)
        return (length == sizeof(sts) - 1u &&
                strncasecmp(domain, sts, length) == 0) ||
               (length == sizeof(sts_parent) - 1u &&
                strncasecmp(domain, sts_parent, length) == 0) ||
               (length == sizeof(mijia_parent) - 1u &&
                strncasecmp(domain, mijia_parent, length) == 0);
    if (origin == COOKIE_ORIGIN_XIAOMIIO_STS)
        return (length == sizeof(xiaomiio_sts) - 1u &&
                strncasecmp(domain, xiaomiio_sts, length) == 0) ||
               (length == sizeof(xiaomiio_sts_parent) - 1u &&
                strncasecmp(domain, xiaomiio_sts_parent, length) == 0) ||
               (length == sizeof(xiaomiio_io_parent) - 1u &&
                strncasecmp(domain, xiaomiio_io_parent, length) == 0) ||
               (length == sizeof(xiaomiio_parent) - 1u &&
                strncasecmp(domain, xiaomiio_parent, length) == 0);
    return 0;
}

static int redirect_url_is_trusted(enum cookie_origin origin,
                                   const char *url)
{
    if (origin == COOKIE_ORIGIN_ACCOUNT)
        return mhg_xiaomi_account_redirect_is_trusted(url);
    if (origin == COOKIE_ORIGIN_MIJIA_STS)
        return mhg_service_redirect_is_trusted(
            MHG_XIAOMI_SID_MIJIA, url);
    if (origin == COOKIE_ORIGIN_XIAOMIIO_STS)
        return mhg_service_redirect_is_trusted(
            MHG_XIAOMI_SID_XIAOMIIO, url);
    return 0;
}

static int trusted_url_path(enum cookie_origin origin, const char *url,
                            const char **path_out, size_t *length_out)
{
    const char *authority;
    const char *path;
    const char *end;
    if (!redirect_url_is_trusted(origin, url))
        return -1;
    authority = url + sizeof("https://") - 1u;
    path = strchr(authority, '/');
    if (!path || (strchr(authority, '?') && strchr(authority, '?') < path)) {
        *path_out = "/";
        *length_out = 1u;
        return 0;
    }
    end = strchr(path, '?');
    *path_out = path;
    *length_out = end ? (size_t)(end - path) : strlen(path);
    return 0;
}

static int cookie_path_matches(const char *cookie_path, size_t cookie_length,
                               const char *request_path,
                               size_t request_length)
{
    if (cookie_length == 0u || cookie_path[0] != '/' ||
        cookie_length > request_length ||
        memcmp(cookie_path, request_path, cookie_length) != 0)
        return 0;
    return cookie_length == request_length ||
           cookie_path[cookie_length - 1u] == '/' ||
           request_path[cookie_length] == '/';
}

static void selected_cookies_clear(struct selected_cookie *selected,
                                   size_t count)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        mhg_secret_buf_clear(&selected[index].value);
        selected[index].path_length = 0u;
        selected[index].found = false;
    }
}

static enum mhg_cloud_error collect_selected_cookies(
    struct mhg_auth_sms_http *owner, enum cookie_origin origin,
    const char *url,
    struct selected_cookie *selected, size_t selected_count)
{
    struct curl_slist *cookies = NULL;
    struct curl_slist *item;
    const char *request_path;
    size_t request_path_length;
    enum mhg_cloud_error result = MHG_CLOUD_OK;
    size_t index;

    if (!owner || !selected || selected_count == 0u ||
        trusted_url_path(origin, url, &request_path,
                         &request_path_length) != 0)
        return MHG_CLOUD_INPUT;
    selected_cookies_clear(selected, selected_count);
    if (curl_easy_getinfo(owner->curl, CURLINFO_COOKIELIST, &cookies) != CURLE_OK)
        return MHG_CLOUD_INTERNAL;
    for (item = cookies; item; item = item->next) {
        const char *fields[7];
        size_t lengths[7];
        const char *cursor = item->data;
        unsigned int field;
        if (!cursor) continue;
        for (field = 0u; field < 6u; ++field) {
            const char *tab;
            fields[field] = cursor;
            tab = strchr(cursor, '\t');
            if (!tab) break;
            lengths[field] = (size_t)(tab - cursor);
            cursor = tab + 1u;
        }
        if (field != 6u) continue;
        fields[6] = cursor;
        lengths[6] = strlen(cursor);
        if (!cookie_domain_matches(origin, fields[0], lengths[0]) ||
            !cookie_path_matches(fields[2], lengths[2], request_path,
                                 request_path_length))
            continue;
        for (index = 0u; index < selected_count; ++index) {
            if (!span_equals(fields[5], lengths[5], selected[index].name))
                continue;
            /* Empty Set-Cookie values do not override a typed non-empty
             * candidate. Required cookies are rejected by the typed parser
             * if no non-empty value remains. */
            if (lengths[6] == 0u) break;
            if (selected[index].found &&
                selected[index].path_length == lengths[2]) {
                if (selected[index].value.len != lengths[6] ||
                    memcmp(selected[index].value.data, fields[6],
                           lengths[6]) != 0)
                    result = MHG_CLOUD_MALFORMED;
                break;
            }
            if (!selected[index].found ||
                lengths[2] > selected[index].path_length) {
                if (mhg_secret_buf_set(&selected[index].value,
                                       fields[6], lengths[6]) != 0)
                    result = MHG_CLOUD_INTERNAL;
                else {
                    selected[index].found = true;
                    selected[index].path_length = lengths[2];
                }
            }
            break;
        }
        if (result != MHG_CLOUD_OK) break;
    }
    secure_slist_free(cookies);
    if (result != MHG_CLOUD_OK)
        selected_cookies_clear(selected, selected_count);
    return result;
}

static enum mhg_cloud_error validate_passport_cookie_jar(
    struct mhg_auth_sms_http *owner, bool require_ticket)
{
    struct selected_cookie selected[] = {
        {"deviceId", MHG_SECRET_BUF_INIT, 0u, false},
        {"ticketToken", MHG_SECRET_BUF_INIT, 0u, false},
    };
    enum mhg_cloud_error result = collect_selected_cookies(
        owner, COOKIE_ORIGIN_ACCOUNT, owner->config.passport_base_url,
        selected, sizeof(selected) / sizeof(selected[0]));

    owner->stats.passport_device_id_present =
        result == MHG_CLOUD_OK && selected[0].found &&
        mhg_passport_device_id_is_valid(selected[0].value.data,
                                         selected[0].value.len) &&
        selected[0].value.len == strlen(owner->device_id) &&
        memcmp(selected[0].value.data, owner->device_id,
               selected[0].value.len) == 0;
    owner->stats.ticket_token_present =
        result == MHG_CLOUD_OK && selected[1].found;
    if (result == MHG_CLOUD_OK &&
        (!owner->stats.passport_device_id_present ||
         (require_ticket && !owner->stats.ticket_token_present)))
        result = MHG_CLOUD_MALFORMED;
    selected_cookies_clear(selected,
                           sizeof(selected) / sizeof(selected[0]));
    return result;
}

static enum mhg_cloud_error resolve_trusted_redirect(
    enum cookie_origin origin, const char *base, const char *location,
    struct mhg_secret_buf *resolved)
{
    CURLU *url = NULL;
    char *value = NULL;
    CURLUcode code;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (resolved) mhg_secret_buf_clear(resolved);
    if (!base || !location || !location[0] || !resolved ||
        !redirect_url_is_trusted(origin, base))
        return MHG_CLOUD_INPUT;
    url = curl_url();
    if (!url) return MHG_CLOUD_INTERNAL;
    code = curl_url_set(url, CURLUPART_URL, base, 0u);
    if (code == CURLUE_OK)
        code = curl_url_set(url, CURLUPART_URL, location, 0u);
    if (code == CURLUE_OK)
        code = curl_url_get(url, CURLUPART_URL, &value, 0u);
    if (code != CURLUE_OK || !redirect_url_is_trusted(origin, value))
        goto out;
    if (mhg_secret_buf_set(resolved, value, strlen(value)) != 0)
        result = MHG_CLOUD_INTERNAL;
    else
        result = MHG_CLOUD_OK;
out:
    if (value) {
        mhg_secure_clear(value, strlen(value));
        curl_free(value);
    }
    curl_url_cleanup(url);
    return result;
}

static int secret_buf_equals(const struct mhg_secret_buf *left,
                             const struct mhg_secret_buf *right)
{
    return left && right && left->data && right->data &&
           left->len == right->len &&
           memcmp(left->data, right->data, left->len) == 0;
}

static int decimal_identity_equals(const struct mhg_secret_buf *normalized,
                                   const struct mhg_secret_buf *candidate)
{
    size_t offset = 0u;
    size_t index;

    if (!normalized || !normalized->data || !normalized->len ||
        !candidate || !candidate->data || !candidate->len)
        return 0;
    for (index = 0u; index < candidate->len; ++index)
        if (candidate->data[index] < (unsigned char)'0' ||
            candidate->data[index] > (unsigned char)'9')
            return 0;
    while (candidate->len - offset > 1u &&
           candidate->data[offset] == (unsigned char)'0')
        ++offset;
    return normalized->len == candidate->len - offset &&
           memcmp(normalized->data, candidate->data + offset,
                  normalized->len) == 0;
}

static enum mhg_cloud_error execute_ticket_redirect_chain(
    struct mhg_auth_sms_http *owner,
    const struct mhg_passport_request_contract *contract,
    uint64_t deadline, struct mhg_passport_response *parsed,
    struct mhg_secret_buf *passport_device_id)
{
    struct selected_cookie selected[] = {
        {NULL, MHG_SECRET_BUF_INIT, 0u, false},
        {NULL, MHG_SECRET_BUF_INIT, 0u, false},
        {NULL, MHG_SECRET_BUF_INIT, 0u, false},
    };
    struct response_buffer response = {0};
    struct mhg_secret_buf current_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf next_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf visited[MHG_MAX_REDIRECT_HOPS + 1u] = {
        MHG_SECRET_BUF_INIT,
    };
    const char *redirect_user = NULL;
    const char *redirect_token = NULL;
    const struct mhg_passport_request_contract *get_contract;
    struct curl_slist *get_headers = NULL;
    unsigned int redirects = 0u;
    size_t index;
    long status = 0;
    enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;

    if (passport_device_id) mhg_secret_buf_clear(passport_device_id);
    if (!owner || !contract || !parsed || !parsed->location.data ||
        !passport_device_id ||
        contract->observed_response_cookie_count !=
            sizeof(selected) / sizeof(selected[0]))
        return MHG_CLOUD_INPUT;
    for (index = 0u; index < sizeof(selected) / sizeof(selected[0]); ++index)
        selected[index].name = contract->observed_response_cookies[index];
    get_contract = mhg_passport_contract(MHG_PASSPORT_POLICY);
    if (!get_contract) return MHG_CLOUD_INTERNAL;
    for (index = 0u; index < get_contract->header_count; ++index)
        if (append_header(&get_headers, get_contract->headers[index].name,
                          get_contract->headers[index].constant_value) != 0)
            goto out;
    owner->stats.json_pair_complete =
        parsed->user_id.data && parsed->user_id.len != 0u &&
        parsed->pass_token.data && parsed->pass_token.len != 0u;
    if (mhg_secret_buf_set(&current_url, parsed->location.data,
                           parsed->location.len) != 0 ||
        mhg_secret_buf_set(&visited[0], parsed->location.data,
                           parsed->location.len) != 0)
        goto out;

    for (;;) {
        owner->stats.total_requests++;
        owner->stats.ticket_redirect_requests++;
        result = perform(owner, MHG_AUTH_SMS_HTTP_STAGE_TICKET_REDIRECT,
                         (const char *)current_url.data, "GET", get_headers,
                         NULL, NULL, true, deadline, &response, &status);
        if (result != MHG_CLOUD_OK) goto out;
        if (status >= 200 && status < 300) break;
        if (status < 300 || status >= 400 || !response.location.data ||
            redirects >= MHG_MAX_REDIRECT_HOPS) {
            result = MHG_CLOUD_MALFORMED;
            goto out;
        }
        result = resolve_trusted_redirect(
            COOKIE_ORIGIN_ACCOUNT, (const char *)current_url.data,
            (const char *)response.location.data, &next_url);
        if (result != MHG_CLOUD_OK) goto out;
        for (index = 0u; index <= redirects; ++index) {
            if (secret_buf_equals(&visited[index], &next_url)) {
                result = MHG_CLOUD_MALFORMED;
                goto out;
            }
        }
        if (mhg_secret_buf_set(&visited[redirects + 1u], next_url.data,
                               next_url.len) != 0) {
            result = MHG_CLOUD_INTERNAL;
            goto out;
        }
        mhg_secret_buf_clear(&current_url);
        current_url = next_url;
        next_url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
        ++redirects;
        response_clear(&response);
    }

    /* Match the tracked CookieJar lookup at the trusted Passport base,
     * rather than selecting path-scoped cookies for the last redirect URL. */
    result = collect_selected_cookies(
        owner, COOKIE_ORIGIN_ACCOUNT, owner->config.passport_base_url,
        selected, sizeof(selected) / sizeof(selected[0]));
    if (result == MHG_CLOUD_OK) {
        owner->stats.passport_device_id_present =
            selected[0].found && mhg_passport_device_id_is_valid(
                selected[0].value.data, selected[0].value.len) &&
            selected[0].value.len == strlen(owner->device_id) &&
            memcmp(selected[0].value.data, owner->device_id,
                   selected[0].value.len) == 0;
        owner->stats.redirect_cookie_pair_complete =
            selected[1].found && selected[2].found;
        if (!owner->stats.passport_device_id_present) {
            result = MHG_CLOUD_MALFORMED;
            goto out;
        }
        if (owner->stats.redirect_cookie_pair_complete) {
            redirect_user = (const char *)selected[1].value.data;
            redirect_token = (const char *)selected[2].value.data;
        }
        owner->stats.pair_values_equal =
            owner->stats.json_pair_complete &&
            owner->stats.redirect_cookie_pair_complete &&
            decimal_identity_equals(&parsed->user_id,
                                    &selected[1].value) &&
            parsed->pass_token.len == selected[2].value.len &&
            CRYPTO_memcmp(parsed->pass_token.data, selected[2].value.data,
                          parsed->pass_token.len) == 0;
        result = mhg_passport_apply_ticket_redirect(
            parsed, redirect_user, redirect_token);
        if (result == MHG_CLOUD_OK) {
            owner->stats.selected_source =
                owner->stats.redirect_cookie_pair_complete ?
                    MHG_TICKET_CANDIDATE_REDIRECT_COOKIE :
                    MHG_TICKET_CANDIDATE_JSON;
            if (mhg_secret_buf_set(passport_device_id,
                                   selected[0].value.data,
                                   selected[0].value.len) != 0)
                result = MHG_CLOUD_INTERNAL;
        }
    }

out:
    response_clear(&response);
    mhg_secret_buf_clear(&current_url);
    mhg_secret_buf_clear(&next_url);
    for (index = 0u; index < sizeof(visited) / sizeof(visited[0]); ++index)
        mhg_secret_buf_clear(&visited[index]);
    selected_cookies_clear(selected,
                           sizeof(selected) / sizeof(selected[0]));
    secure_slist_free(get_headers);
    if (result != MHG_CLOUD_OK) mhg_secret_buf_clear(passport_device_id);
    return result;
}

static int build_challenge_referer(CURL *curl,
                                   const struct mhg_auth_sms_work *work,
                                   struct mhg_secret_buf *referer)
{
    bool first = true;
    if (append_cstr(referer,
                    "https://account.xiaomi.com/fe/service/login/challenge/ticket?") != 0 ||
        append_pair(curl, referer, &first, "_locale",
                    (const unsigned char *)"zh_CN", 5u) != 0 ||
        append_pair(curl, referer, &first, "_callingCode",
                    (const unsigned char *)work->calling_code,
                    strlen(work->calling_code)) != 0 ||
        append_pair(curl, referer, &first, "_user",
                    work->passport_user.data,
                    work->passport_user.len) != 0 ||
        append_pair(curl, referer, &first, "_agreementChecked",
                    (const unsigned char *)"true", 4u) != 0)
        return -1;
    return 0;
}

static int field_value(const struct mhg_passport_field *field,
                       const struct mhg_auth_sms_work *work,
                       const char *fingerprint,
                       const struct mhg_secret_buf *eui,
                       const unsigned char **value, size_t *length)
{
    if (field->source == MHG_PASSPORT_CONSTANT) {
        *value = (const unsigned char *)field->constant_value;
        *length = strlen(field->constant_value);
    } else if (field->source == MHG_PASSPORT_EUI_ENCRYPTED) {
        *value = eui->data;
        *length = eui->len;
    } else if (field->source == MHG_PASSPORT_SECRET) {
        *value = work->ticket.data;
        *length = work->ticket.len;
    } else if (field->source == MHG_PASSPORT_GENERATED) {
        *value = (const unsigned char *)fingerprint;
        *length = strlen(fingerprint);
    } else if (field->source == MHG_PASSPORT_SESSION) {
        if (strcmp(field->name, "policyName") == 0) {
            *value = (const unsigned char *)work->policy_name;
            *length = strlen(work->policy_name);
        } else {
            *value = work->passport_user.data;
            *length = work->passport_user.len;
        }
    } else {
        return -1;
    }
    return *value || *length == 0u ? 0 : -1;
}

static enum mhg_cloud_error execute_passport(
    struct mhg_auth_sms_http *owner, const struct mhg_auth_sms_work *work,
    uint64_t deadline, struct mhg_passport_response *parsed,
    struct mhg_secret_buf *passport_device_id)
{
    const struct mhg_passport_request_contract *contract;
    struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf body = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf referer = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cipher = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cipher_b64 = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf eui_header = MHG_SECRET_BUF_INIT;
    struct curl_slist *headers = NULL;
    struct response_buffer response = {0};
    EVP_PKEY *public_key = NULL;
    unsigned char aes_key[16] = {0};
    char fingerprint[33] = {0};
    bool first = true;
    const unsigned char *value;
    size_t value_len;
    size_t index;
    long status = 0;
    enum mhg_cloud_error result = MHG_CLOUD_NOT_DISPATCHED;

    contract = mhg_passport_contract(work->passport_step);
    if (!contract || !work->passport_user.data || !work->calling_code[0])
        return MHG_CLOUD_INPUT;
    if (work->passport_step == MHG_PASSPORT_POLICY) {
        result = seed_passport_cookie_jar(
            owner, work->challenge_generation);
        if (result != MHG_CLOUD_OK) goto out;
    }
    if (contract->uses_eui) {
        const char *encrypted_name = NULL;
        for (index = 0u; index < contract->form_count; ++index)
            if (contract->form[index].source == MHG_PASSPORT_EUI_ENCRYPTED) {
                encrypted_name = contract->form[index].name;
                break;
            }
        if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 ||
            mhg_passport_eui_aes_encrypt(aes_key,
                                         work->passport_user.data,
                                         work->passport_user.len,
                                         &cipher) != MHG_CLOUD_OK ||
            base64_secret(&cipher, &cipher_b64) != 0)
            goto out;
        public_key = mhg_passport_eui_protocol_public_key();
        if (!encrypted_name || !public_key || mhg_passport_eui_header(
                public_key, aes_key, encrypted_name,
                &eui_header) != MHG_CLOUD_OK)
            goto out;
    }
    if (generated_hex(fingerprint, 16u) != 0) goto out;
    if (append_cstr(&url, owner->config.passport_base_url) != 0 ||
        append_cstr(&url, contract->path) != 0)
        goto out;
    for (index = 0u; index < contract->query_count; ++index) {
        if (index == 0u && append_cstr(&url, "?") != 0) goto out;
        if (field_value(&contract->query[index], work, fingerprint,
                        &cipher_b64, &value, &value_len) != 0 ||
            append_pair(owner->curl, &url, &first,
                        contract->query[index].name, value, value_len) != 0)
            goto out;
    }
    first = true;
    for (index = 0u; index < contract->form_count; ++index) {
        if (field_value(&contract->form[index], work, fingerprint,
                        &cipher_b64, &value, &value_len) != 0 ||
            append_pair(owner->curl, &body, &first,
                        contract->form[index].name, value, value_len) != 0)
            goto out;
    }
    for (index = 0u; index < contract->header_count; ++index) {
        if (strcmp(contract->headers[index].name, "Referer") == 0 &&
            contract->uses_challenge_referer)
            continue;
        if (append_header(&headers, contract->headers[index].name,
                          contract->headers[index].constant_value) != 0)
            goto out;
    }
    if (contract->uses_challenge_referer) {
        if (build_challenge_referer(owner->curl, work, &referer) != 0 ||
            append_header(&headers, "Referer",
                          (const char *)referer.data) != 0)
            goto out;
    }
    if (contract->uses_eui &&
        append_header(&headers, contract->eui_header_name,
                      (const char *)eui_header.data) != 0)
        goto out;
    result = validate_passport_cookie_jar(
        owner, work->passport_step == MHG_PASSPORT_TICKET_AUTH);
    if (result != MHG_CLOUD_OK) goto out;
    owner->stats.total_requests++;
    owner->stats.passport_requests[work->passport_step]++;
    result = perform(owner, passport_http_stage(work->passport_step),
                     (const char *)url.data, contract->method, headers, &body,
                     NULL, false, deadline, &response,
                     &status);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_passport_parse_response(
        work->passport_step, MHG_BYTES_VIEW(response.data, response.len), parsed);
    if (result == MHG_CLOUD_OK &&
        work->passport_step == MHG_PASSPORT_TICKET_AUTH)
        result = execute_ticket_redirect_chain(
            owner, contract, deadline, parsed, passport_device_id);

out:
    EVP_PKEY_free(public_key);
    mhg_secure_clear(aes_key, sizeof(aes_key));
    mhg_secure_clear(fingerprint, sizeof(fingerprint));
    secure_slist_free(headers);
    response_clear(&response);
    mhg_secret_buf_clear(&url);
    mhg_secret_buf_clear(&body);
    mhg_secret_buf_clear(&referer);
    mhg_secret_buf_clear(&cipher);
    mhg_secret_buf_clear(&cipher_b64);
    mhg_secret_buf_clear(&eui_header);
    return result;
}

static enum mhg_cloud_error merge_selected_cookies(
    struct selected_cookie *destination, const struct selected_cookie *source,
    size_t count)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        if (!source[index].found) continue;
        if (mhg_secret_buf_set(&destination[index].value,
                               source[index].value.data,
                               source[index].value.len) != 0)
            return MHG_CLOUD_INTERNAL;
        destination[index].found = true;
        destination[index].path_length = source[index].path_length;
    }
    return MHG_CLOUD_OK;
}

static enum mhg_cloud_error finish_service_session(
    const struct mhg_service_login *login,
    const struct mhg_auth_sms_work *work,
    const struct selected_cookie *selected,
    const struct mhg_secret_buf *extension_pragma,
    struct mhg_service_session *session)
{
    struct mhg_cookie_pair pairs[] = {
        {"userId", NULL}, {"cUserId", NULL}, {"serviceToken", NULL},
        {"passToken", NULL},
    };
    size_t index;
    for (index = 0u; index < sizeof(pairs) / sizeof(pairs[0]); ++index)
        if (selected[index].found)
            pairs[index].value = (const char *)selected[index].value.data;
    return mhg_service_finish_redirect(
        login, (const char *)work->user_id.data, pairs,
        sizeof(pairs) / sizeof(pairs[0]),
        MHG_BYTES_VIEW(extension_pragma->data, extension_pragma->len), session);
}

static enum mhg_cloud_error execute_rotation(
    struct mhg_auth_sms_http *owner, const struct mhg_auth_sms_work *work,
    uint64_t deadline, struct mhg_secret_buf *rotated_device_id,
    struct mhg_secret_buf *rotated_user_id,
    struct mhg_secret_buf *rotated_pass_token,
    struct mhg_auth_sms_provider_diagnostic *provider)
{
    const enum mhg_xiaomi_sid rotation_sid = MHG_XIAOMI_SID_XIAOMIIO;
    const enum cookie_origin rotation_origin = COOKIE_ORIGIN_XIAOMIIO_STS;
    const struct mhg_service_login_request_contract *contract;
    struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cookie = MHG_SECRET_BUF_INIT;
    struct response_buffer response = {0};
    struct response_buffer redirect = {0};
    struct mhg_secret_buf current_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf next_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf extension_pragma = MHG_SECRET_BUF_INIT;
    struct curl_slist *headers = NULL;
    struct selected_cookie selected[] = {
        {"userId", MHG_SECRET_BUF_INIT, 0u, false},
        {"cUserId", MHG_SECRET_BUF_INIT, 0u, false},
        {"serviceToken", MHG_SECRET_BUF_INIT, 0u, false},
        {"passToken", MHG_SECRET_BUF_INIT, 0u, false},
    };
    struct mhg_service_login login = MHG_SERVICE_LOGIN_INIT;
    struct mhg_service_provider_diagnostic service_provider =
        MHG_SERVICE_PROVIDER_DIAGNOSTIC_INIT;
    struct mhg_service_session session = MHG_SERVICE_SESSION_INIT;
    bool first = true;
    long status = 0;
    unsigned int redirects = 0u;
    enum mhg_cloud_error result = MHG_CLOUD_NOT_DISPATCHED;

    if (provider)
        *provider = (struct mhg_auth_sms_provider_diagnostic)
            MHG_AUTH_SMS_PROVIDER_DIAGNOSTIC_INIT;
    if (!work->device_id.data ||
        !mhg_passport_device_id_is_valid(work->device_id.data,
                                         work->device_id.len) ||
        !work->user_id.data || !work->pass_token.data || !provider)
        return MHG_CLOUD_INPUT;
    if (curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL") != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    contract = mhg_service_login_request_contract();
    if (append_cstr(&url, owner->config.service_base_url) != 0 ||
        append_cstr(&url, contract->path) != 0 ||
        append_cstr(&url, "?") != 0 ||
        append_pair(owner->curl, &url, &first, contract->json_query_name,
                    (const unsigned char *)contract->json_query_value,
                    strlen(contract->json_query_value)) != 0 ||
        append_pair(owner->curl, &url, &first, contract->sid_query_name,
                    (const unsigned char *)mhg_xiaomi_sid_name(rotation_sid),
                    strlen(mhg_xiaomi_sid_name(rotation_sid))) != 0)
        goto out;
    result = mhg_service_login_cookie_header(
        (const char *)work->user_id.data,
        (const char *)work->pass_token.data, &cookie);
    if (result != MHG_CLOUD_OK) goto out;
    if (append_header(&headers, "User-Agent",
                      mhg_passport_client_user_agent()) != 0)
        goto out;
    owner->stats.total_requests++;
    owner->stats.token_login_requests++;
    result = perform(owner, MHG_AUTH_SMS_HTTP_STAGE_TOKEN_LOGIN,
                     (const char *)url.data, contract->method, headers, NULL,
                     (const char *)cookie.data, false, deadline, &response,
                     &status);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_service_parse_token_login(
        rotation_sid, MHG_BYTES_VIEW(response.data, response.len),
        &login, &service_provider);
    if (service_provider.provider_class != MHG_SERVICE_PROVIDER_NONE) {
        provider->scope = MHG_AUTH_SMS_PROVIDER_SCOPE_TOKEN_LOGIN;
        provider->provider_code = service_provider.provider_code;
        provider->provider_class = service_provider.provider_class ==
                MHG_SERVICE_PROVIDER_CREDENTIAL_REJECTED ?
            MHG_AUTH_SMS_PROVIDER_CREDENTIAL_REJECTED :
            MHG_AUTH_SMS_PROVIDER_OTHER;
    }
    if (result != MHG_CLOUD_OK) goto out;
    if (curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL") != CURLE_OK) {
        result = MHG_CLOUD_NOT_DISPATCHED;
        goto out;
    }
    if (mhg_secret_buf_set(&current_url, login.location.data,
                           login.location.len) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    for (;;) {
        struct selected_cookie hop[] = {
            {"userId", MHG_SECRET_BUF_INIT, 0u, false},
            {"cUserId", MHG_SECRET_BUF_INIT, 0u, false},
            {"serviceToken", MHG_SECRET_BUF_INIT, 0u, false},
            {"passToken", MHG_SECRET_BUF_INIT, 0u, false},
        };
        owner->stats.total_requests++;
        owner->stats.redirect_requests++;
        result = perform(owner, MHG_AUTH_SMS_HTTP_STAGE_SERVICE_REDIRECT,
                         (const char *)current_url.data, "GET", headers, NULL,
                         NULL, true, deadline, &redirect, &status);
        if (result == MHG_CLOUD_OK)
            result = collect_selected_cookies(
                owner, rotation_origin,
                (const char *)current_url.data, hop,
                sizeof(hop) / sizeof(hop[0]));
        if (result == MHG_CLOUD_OK)
            result = merge_selected_cookies(
                selected, hop, sizeof(hop) / sizeof(hop[0]));
        selected_cookies_clear(hop, sizeof(hop) / sizeof(hop[0]));
        if (result != MHG_CLOUD_OK) goto out;
        if (redirect.extension_pragma.len != 0u &&
            mhg_secret_buf_set(&extension_pragma,
                               redirect.extension_pragma.data,
                               redirect.extension_pragma.len) != 0) {
            result = MHG_CLOUD_INTERNAL;
            goto out;
        }
        if (curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL") !=
            CURLE_OK) {
            result = MHG_CLOUD_NOT_DISPATCHED;
            goto out;
        }
        if (status >= 200 && status < 300) break;
        if (status < 300 || status >= 400 ||
            redirects >= MHG_MAX_REDIRECT_HOPS ||
            !redirect.location.data) {
            result = MHG_CLOUD_MALFORMED;
            goto out;
        }
        result = resolve_trusted_redirect(
            rotation_origin, (const char *)current_url.data,
            (const char *)redirect.location.data, &next_url);
        if (result != MHG_CLOUD_OK) goto out;
        mhg_secret_buf_clear(&current_url);
        current_url = next_url;
        next_url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
        ++redirects;
        response_clear(&redirect);
    }
    result = finish_service_session(&login, work, selected,
                                    &extension_pragma, &session);
    if (result != MHG_CLOUD_OK) goto out;
    if (mhg_secret_buf_set(rotated_device_id, work->device_id.data,
                           work->device_id.len) != 0 ||
        mhg_secret_buf_set(rotated_user_id, session.user_id.data,
                           session.user_id.len) != 0 ||
        mhg_secret_buf_set(rotated_pass_token, session.pass_token.data,
                           session.pass_token.len) != 0)
        result = MHG_CLOUD_INTERNAL;
    else
        result = MHG_CLOUD_OK;

out:
    (void)curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL");
    secure_slist_free(headers);
    response_clear(&response);
    response_clear(&redirect);
    selected_cookies_clear(selected,
                           sizeof(selected) / sizeof(selected[0]));
    mhg_service_login_clear(&login);
    mhg_service_session_clear(&session);
    mhg_secret_buf_clear(&url);
    mhg_secret_buf_clear(&cookie);
    mhg_secret_buf_clear(&current_url);
    mhg_secret_buf_clear(&next_url);
    mhg_secret_buf_clear(&extension_pragma);
    if (result != MHG_CLOUD_OK) {
        mhg_secret_buf_clear(rotated_device_id);
        mhg_secret_buf_clear(rotated_user_id);
        mhg_secret_buf_clear(rotated_pass_token);
    }
    return result;
}

int mhg_auth_sms_http_create(struct mhg_auth_sms_http **owner_out,
                             const struct mhg_auth_sms_http_config *config)
{
    struct mhg_auth_sms_http *owner;
    struct mhg_auth_sms_http_config actual = MHG_AUTH_SMS_HTTP_CONFIG_INIT;
    if (!owner_out) { errno = EINVAL; return -1; }
    *owner_out = NULL;
    if (config) actual = *config;
    if (!actual.passport_base_url)
        actual.passport_base_url = mhg_passport_base_url();
    if (!actual.service_base_url)
        actual.service_base_url = mhg_service_login_base_url();
    if (!https_base_is_valid(actual.passport_base_url) ||
        !https_base_is_valid(actual.service_base_url) ||
        actual.connect_timeout_ms == 0ul || actual.total_timeout_ms == 0ul ||
        actual.response_limit == 0u || actual.response_limit > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    pthread_once(&curl_once, init_curl);
    if (curl_global_result != CURLE_OK) { errno = EIO; return -1; }
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->config = actual;
    if (pthread_mutex_init(&owner->execute_lock, NULL) != 0) {
        free(owner);
        errno = EIO;
        return -1;
    }
    owner->curl = curl_easy_init();
    if (!owner->curl) {
        pthread_mutex_destroy(&owner->execute_lock);
        free(owner);
        errno = ENOMEM;
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_auth_sms_http_destroy(struct mhg_auth_sms_http *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->execute_lock);
    (void)curl_easy_setopt(owner->curl, CURLOPT_COOKIELIST, "ALL");
    curl_easy_cleanup(owner->curl);
    mhg_secure_clear(owner->device_id, sizeof(owner->device_id));
    pthread_mutex_unlock(&owner->execute_lock);
    pthread_mutex_destroy(&owner->execute_lock);
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

void mhg_auth_sms_http_result_clear(struct mhg_auth_sms_http_result *result)
{
    if (!result) return;
    mhg_passport_response_clear(&result->passport);
    mhg_secret_buf_clear(&result->passport_device_id);
    mhg_secret_buf_clear(&result->rotated_device_id);
    mhg_secret_buf_clear(&result->rotated_user_id);
    mhg_secret_buf_clear(&result->rotated_pass_token);
    mhg_secure_clear(result, sizeof(*result));
}

void mhg_auth_sms_http_control_reset(
    struct mhg_auth_sms_http_control *control)
{
    if (control)
        atomic_store_explicit(&control->cancel_requested, false,
                              memory_order_relaxed);
}

void mhg_auth_sms_http_control_cancel(
    struct mhg_auth_sms_http_control *control)
{
    if (control)
        atomic_store_explicit(&control->cancel_requested, true,
                              memory_order_relaxed);
}

enum mhg_cloud_error mhg_auth_sms_http_execute(
    struct mhg_auth_sms_http *owner, const struct mhg_auth_sms_work *work,
    const struct mhg_auth_sms_http_control *control,
    struct mhg_auth_sms_http_result *result)
{
    uint64_t now;
    uint64_t deadline;
    enum mhg_cloud_error outcome;
    if (!result) return MHG_CLOUD_INPUT;
    mhg_auth_sms_http_result_clear(result);
    if (!owner || !work_is_valid(work)) return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->execute_lock);
    owner->stats.last_stage = MHG_AUTH_SMS_HTTP_STAGE_NONE;
    owner->stats.last_http_status = 0;
    owner->active_control = control;
    now = monotonic_ms();
    deadline = !now || UINT64_MAX - now < owner->config.total_timeout_ms ?
        UINT64_MAX : now + owner->config.total_timeout_ms;
    if (work->kind == MHG_AUTH_SMS_WORK_PASSPORT)
        outcome = execute_passport(owner, work, deadline, &result->passport,
                                   &result->passport_device_id);
    else if (work->kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE)
        outcome = execute_rotation(owner, work, deadline,
                                   &result->rotated_device_id,
                                   &result->rotated_user_id,
                                   &result->rotated_pass_token,
                                   &result->provider);
    else
        outcome = MHG_CLOUD_INPUT;
    result->cloud_error = outcome;
    owner->active_control = NULL;
    pthread_mutex_unlock(&owner->execute_lock);
    return outcome;
}

void mhg_auth_sms_http_get_stats(struct mhg_auth_sms_http *owner,
                                 struct mhg_auth_sms_http_stats *stats)
{
    if (!owner || !stats) return;
    pthread_mutex_lock(&owner->execute_lock);
    *stats = owner->stats;
    pthread_mutex_unlock(&owner->execute_lock);
}

const char *mhg_auth_sms_http_stage_name(
    enum mhg_auth_sms_http_stage stage)
{
    switch (stage) {
    case MHG_AUTH_SMS_HTTP_STAGE_NONE: return "none";
    case MHG_AUTH_SMS_HTTP_STAGE_POLICY: return "policy";
    case MHG_AUTH_SMS_HTTP_STAGE_PREFERENCE: return "preference";
    case MHG_AUTH_SMS_HTTP_STAGE_SEND_TICKET: return "send_ticket";
    case MHG_AUTH_SMS_HTTP_STAGE_PHONE_INFO: return "phone_info";
    case MHG_AUTH_SMS_HTTP_STAGE_TICKET_AUTH: return "ticket_auth";
    case MHG_AUTH_SMS_HTTP_STAGE_TICKET_REDIRECT:
        return "ticket_redirect";
    case MHG_AUTH_SMS_HTTP_STAGE_TOKEN_LOGIN: return "token_login";
    case MHG_AUTH_SMS_HTTP_STAGE_SERVICE_REDIRECT:
        return "service_redirect";
    default: return "unknown";
    }
}

const char *mhg_ticket_candidate_source_name(
    enum mhg_ticket_candidate_source source)
{
    switch (source) {
    case MHG_TICKET_CANDIDATE_NONE: return "none";
    case MHG_TICKET_CANDIDATE_JSON: return "json";
    case MHG_TICKET_CANDIDATE_REDIRECT_COOKIE:
        return "redirect_cookie";
    }
    return "unknown";
}

enum mhg_auth_sms_result mhg_auth_sms_http_complete(
    struct mhg_auth_sms *auth, const struct mhg_auth_sms_work *completed,
    const struct mhg_auth_sms_http_result *result, uint64_t now_ms,
    struct mhg_auth_sms_work *next)
{
    if (!auth || !completed || !result || !next)
        return MHG_AUTH_SMS_REJECTED_INPUT;
    if (completed->kind == MHG_AUTH_SMS_WORK_PASSPORT)
        return mhg_auth_sms_complete_passport(
            auth, completed, result->cloud_error,
            result->cloud_error == MHG_CLOUD_OK ||
                    result->cloud_error == MHG_CLOUD_SERVICE ?
                &result->passport : NULL,
            result->passport_device_id.data ?
                (const char *)result->passport_device_id.data : NULL,
            now_ms, next);
    if (completed->kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE)
        return mhg_auth_sms_complete_rotation(
            auth, completed, result->cloud_error,
            result->rotated_device_id.data ?
                (const char *)result->rotated_device_id.data : NULL,
            result->rotated_user_id.data ?
                (const char *)result->rotated_user_id.data : NULL,
            result->rotated_pass_token.data ?
                (const char *)result->rotated_pass_token.data : NULL,
            result->provider.scope != MHG_AUTH_SMS_PROVIDER_SCOPE_NONE ?
                &result->provider : NULL,
            next);
    return MHG_AUTH_SMS_REJECTED_INPUT;
}
