#include "xiaomi_service.h"

#include <cjson/cJSON.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "json_strict.h"
#include "secret_json.h"
#include "wire_scalar.h"
#include "xiaomi_account_url.h"

static int base64_decode(const char *input, struct mhg_secret_buf *output)
{
    unsigned char *decoded;
    size_t input_len;
    size_t padding = 0u;
    int length;

    if (!input) return -1;
    input_len = strlen(input);
    if (input_len == 0u || input_len % 4u != 0u || input_len > (size_t)INT_MAX)
        return -1;
    if (input[input_len - 1u] == '=') ++padding;
    if (input_len > 1u && input[input_len - 2u] == '=') ++padding;
    decoded = OPENSSL_malloc(input_len);
    if (!decoded) return -1;
    length = EVP_DecodeBlock(decoded, (const unsigned char *)input,
                             (int)input_len);
    if (length < 0 || (size_t)length <= padding ||
        mhg_secret_buf_set(output, decoded, (size_t)length - padding) != 0) {
        OPENSSL_clear_free(decoded, input_len);
        return -1;
    }
    OPENSSL_clear_free(decoded, input_len);
    return 0;
}

const char *mhg_service_login_base_url(void)
{
    return "https://account.xiaomi.com";
}

const char *mhg_service_login_path(void)
{
    return "/pass/serviceLogin";
}

const char *mhg_service_login_response_prefix(void)
{
    return "&&&START&&&";
}

int mhg_service_redirect_is_trusted(enum mhg_xiaomi_sid sid,
                                    const char *url)
{
    /* Both hosts are exact results from authorized, value-free token-login
     * probes. SID selection remains typed so one service cannot consume the
     * other's redirect. */
    const char *host = mhg_service_sts_host(sid);
    return host ? mhg_https_url_is_trusted_for_exact_host(url, host) : 0;
}

const char *mhg_service_sts_host(enum mhg_xiaomi_sid sid)
{
    if (sid == MHG_XIAOMI_SID_XIAOMIIO) return "sts.api.io.mi.com";
    if (sid == MHG_XIAOMI_SID_MIJIA) return "sts.api.mijia.tech";
    return NULL;
}

int mhg_service_sts_request_path(enum mhg_xiaomi_sid sid, const char *url,
                                 const char **path_out, size_t *length_out)
{
    const char *authority;
    const char *path;
    const char *query;
    const char *end;

    if (path_out) *path_out = NULL;
    if (length_out) *length_out = 0u;
    if (!path_out || !length_out ||
        !mhg_service_redirect_is_trusted(sid, url))
        return -1;
    authority = url + sizeof("https://") - 1u;
    path = strchr(authority, '/');
    query = strchr(authority, '?');
    if (!path || (query && query < path)) {
        *path_out = "/";
        *length_out = 1u;
        return 0;
    }
    end = strchr(path, '?');
    *path_out = path;
    *length_out = end ? (size_t)(end - path) : strlen(path);
    return 0;
}

static int domain_matches_one(const char *domain, size_t length,
                              const char *suffix)
{
    size_t suffix_length = strlen(suffix);
    return length == suffix_length &&
           strncasecmp(domain, suffix, suffix_length) == 0;
}

int mhg_service_cookie_domain_matches(enum mhg_xiaomi_sid sid,
                                      const char *domain, size_t length)
{
    static const char http_only[] = "#HttpOnly_";
    static const char *const mijia_candidates[] = {
        "sts.api.mijia.tech", "api.mijia.tech", "mijia.tech",
    };
    static const char *const xiaomiio_candidates[] = {
        "sts.api.io.mi.com", "api.io.mi.com", "io.mi.com", "mi.com",
    };
    const char *const *candidates;
    size_t count;
    size_t index;

    if (!domain) return 0;
    if (length >= sizeof(http_only) - 1u &&
        memcmp(domain, http_only, sizeof(http_only) - 1u) == 0) {
        domain += sizeof(http_only) - 1u;
        length -= sizeof(http_only) - 1u;
    }
    if (length && domain[0] == '.') {
        ++domain;
        --length;
    }
    if (sid == MHG_XIAOMI_SID_MIJIA) {
        candidates = mijia_candidates;
        count = sizeof(mijia_candidates) / sizeof(mijia_candidates[0]);
    } else if (sid == MHG_XIAOMI_SID_XIAOMIIO) {
        candidates = xiaomiio_candidates;
        count = sizeof(xiaomiio_candidates) / sizeof(xiaomiio_candidates[0]);
    } else {
        return 0;
    }
    for (index = 0u; index < count; ++index)
        if (domain_matches_one(domain, length, candidates[index])) return 1;
    return 0;
}

int mhg_service_cookie_path_matches(const char *cookie_path,
                                    size_t cookie_length,
                                    const char *request_path,
                                    size_t request_length)
{
    if (!cookie_path || !request_path || cookie_length == 0u ||
        cookie_path[0] != '/' || cookie_length > request_length ||
        memcmp(cookie_path, request_path, cookie_length) != 0)
        return 0;
    return cookie_length == request_length ||
           cookie_path[cookie_length - 1u] == '/' ||
           request_path[cookie_length] == '/';
}

const struct mhg_service_login_request_contract *
mhg_service_login_request_contract(void)
{
    static const struct mhg_service_login_request_contract contract = {
        "GET", "/pass/serviceLogin", "_json", "true", "sid",
        "userId", "passToken",
    };
    return &contract;
}

enum mhg_cloud_error mhg_service_login_cookie_header(
    const char *user_id, const char *pass_token,
    struct mhg_secret_buf *cookie_header)
{
    const struct mhg_service_login_request_contract *contract =
        mhg_service_login_request_contract();
    char *formatted;
    size_t user_length;
    size_t token_length;
    size_t capacity;
    size_t index;
    int wrote;
    enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;

    if (cookie_header) mhg_secret_buf_clear(cookie_header);
    if (!user_id || !pass_token || !pass_token[0] || !cookie_header)
        return MHG_CLOUD_INPUT;
    user_length = strlen(user_id);
    token_length = strlen(pass_token);
    if (user_length == 0u) return MHG_CLOUD_INPUT;
    for (index = 0u; index < user_length; ++index)
        if (user_id[index] < '0' || user_id[index] > '9')
            return MHG_CLOUD_INPUT;
    if (user_length > SIZE_MAX - 64u ||
        token_length > SIZE_MAX - 64u - user_length)
        return MHG_CLOUD_INPUT;
    capacity = user_length + token_length + 64u;
    formatted = OPENSSL_malloc(capacity);
    if (!formatted) return MHG_CLOUD_INTERNAL;
    wrote = snprintf(formatted, capacity, "%s=%s; %s=%s",
                     contract->user_cookie_name, user_id,
                     contract->pass_token_cookie_name, pass_token);
    if (wrote >= 0 && (size_t)wrote < capacity &&
        mhg_secret_buf_set(cookie_header, formatted, (size_t)wrote) == 0)
        result = MHG_CLOUD_OK;
    OPENSSL_clear_free(formatted, capacity);
    return result;
}

void mhg_service_login_clear(struct mhg_service_login *login)
{
    if (!login) return;
    mhg_secret_buf_clear(&login->ssecurity);
    mhg_secret_buf_clear(&login->pass_token);
    mhg_secret_buf_clear(&login->location);
    mhg_secure_clear(login, sizeof(*login));
}

enum mhg_cloud_error mhg_service_parse_token_login(
    enum mhg_xiaomi_sid sid, struct mhg_bytes_view response,
    struct mhg_service_login *login,
    struct mhg_service_provider_diagnostic *diagnostic)
{
    const char *prefix = mhg_service_login_response_prefix();
    size_t prefix_len = strlen(prefix);
    struct mhg_bytes_view json;
    cJSON *root = NULL;
    cJSON *code;
    cJSON *ssecurity;
    cJSON *pass_token;
    cJSON *location;
    struct mhg_json_slice code_raw = {0};
    int provider_code;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (login) mhg_service_login_clear(login);
    if (diagnostic)
        *diagnostic = (struct mhg_service_provider_diagnostic)
            MHG_SERVICE_PROVIDER_DIAGNOSTIC_INIT;
    if (!mhg_xiaomi_sid_name(sid) ||
        (!response.data && response.len != 0u) || !login || !diagnostic)
        return MHG_CLOUD_INPUT;
    if (response.len < prefix_len ||
        memcmp(response.data, prefix, prefix_len) != 0)
        return MHG_CLOUD_MALFORMED;
    json = MHG_BYTES_VIEW(response.data + prefix_len,
                          response.len - prefix_len);
    root = mhg_secret_json_parse_len(json.data, json.len);
    if (!root || !cJSON_IsObject(root)) goto out;
    code = cJSON_GetObjectItemCaseSensitive(root, "code");
    if (mhg_json_object_member_slice((const char *)json.data, json.len,
                                     "code", &code_raw) != 0 ||
        mhg_json_decimal_int_parse(code, &code_raw, &provider_code) !=
            MHG_CLOUD_OK)
        goto out;
    if (provider_code != 0) {
        diagnostic->provider_code = provider_code;
        if (provider_code == 70016) {
            diagnostic->provider_class =
                MHG_SERVICE_PROVIDER_CREDENTIAL_REJECTED;
            result = MHG_CLOUD_AUTH_REJECTED;
        } else {
            diagnostic->provider_class = MHG_SERVICE_PROVIDER_OTHER;
            result = MHG_CLOUD_SERVICE;
        }
        goto out;
    }
    ssecurity = cJSON_GetObjectItemCaseSensitive(root, "ssecurity");
    pass_token = cJSON_GetObjectItemCaseSensitive(root, "passToken");
    location = cJSON_GetObjectItemCaseSensitive(root, "location");
    if (!cJSON_IsString(ssecurity) || !cJSON_IsString(pass_token) ||
        !pass_token->valuestring[0] || !cJSON_IsString(location) ||
        !mhg_service_redirect_is_trusted(sid, location->valuestring) ||
        base64_decode(ssecurity->valuestring, &login->ssecurity) != 0 ||
        mhg_secret_buf_set(&login->pass_token, pass_token->valuestring,
                           strlen(pass_token->valuestring)) != 0 ||
        mhg_secret_buf_set(&login->location, location->valuestring,
                           strlen(location->valuestring)) != 0)
        goto out;
    login->sid = sid;
    result = MHG_CLOUD_OK;

out:
    mhg_secret_json_delete(root);
    if (result != MHG_CLOUD_OK) mhg_service_login_clear(login);
    return result;
}

void mhg_service_session_clear(struct mhg_service_session *session)
{
    if (!session) return;
    mhg_secret_buf_clear(&session->user_id);
    mhg_secret_buf_clear(&session->pass_token);
    mhg_secret_buf_clear(&session->cuser_id);
    mhg_secret_buf_clear(&session->service_token);
    mhg_secret_buf_clear(&session->ssecurity);
    mhg_secure_clear(session, sizeof(*session));
}

const char *mhg_service_provider_class_name(
    enum mhg_service_provider_class provider_class)
{
    switch (provider_class) {
    case MHG_SERVICE_PROVIDER_NONE: return "none";
    case MHG_SERVICE_PROVIDER_CREDENTIAL_REJECTED:
        return "credential_rejected";
    case MHG_SERVICE_PROVIDER_OTHER: return "other";
    }
    return NULL;
}

static const char *find_cookie(const struct mhg_cookie_pair *cookies,
                               size_t cookie_count, const char *name)
{
    size_t index;
    for (index = 0u; index < cookie_count; ++index)
        if (cookies[index].name && cookies[index].value &&
            strcmp(cookies[index].name, name) == 0)
            return cookies[index].value;
    return NULL;
}

enum mhg_cloud_error mhg_service_finish_redirect(
    const struct mhg_service_login *login, const char *expected_user_id,
    const struct mhg_cookie_pair *cookies, size_t cookie_count,
    struct mhg_bytes_view extension_pragma_json,
    struct mhg_service_session *session)
{
    const char *user_id;
    const char *cuser_id;
    const char *service_token;
    const char *pass_token;
    const unsigned char *ssecurity;
    size_t ssecurity_len;
    struct mhg_secret_buf header_security = MHG_SECRET_BUF_INIT;
    cJSON *header = NULL;
    cJSON *item;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (session) mhg_service_session_clear(session);
    if (!login || !mhg_xiaomi_sid_name(login->sid) || !expected_user_id ||
        !cookies || cookie_count == 0u ||
        (!extension_pragma_json.data && extension_pragma_json.len != 0u) ||
        !session)
        return MHG_CLOUD_INPUT;
    user_id = find_cookie(cookies, cookie_count, "userId");
    cuser_id = find_cookie(cookies, cookie_count, "cUserId");
    service_token = find_cookie(cookies, cookie_count, "serviceToken");
    pass_token = find_cookie(cookies, cookie_count, "passToken");
    if (!pass_token || !pass_token[0])
        pass_token = login->pass_token.data ?
            (const char *)login->pass_token.data : NULL;
    if (!user_id || strcmp(user_id, expected_user_id) != 0 || !cuser_id ||
        !cuser_id[0] || !service_token || !service_token[0] ||
        !pass_token || !pass_token[0])
        goto out;
    ssecurity = login->ssecurity.data;
    ssecurity_len = login->ssecurity.len;
    if (extension_pragma_json.len != 0u) {
        header = mhg_secret_json_parse_len(extension_pragma_json.data,
                                           extension_pragma_json.len);
        if (!header || !cJSON_IsObject(header)) goto out;
        item = cJSON_GetObjectItemCaseSensitive(header, "ssecurity");
        if (!cJSON_IsString(item) ||
            base64_decode(item->valuestring, &header_security) != 0)
            goto out;
        ssecurity = header_security.data;
        ssecurity_len = header_security.len;
    }
    if (!ssecurity || ssecurity_len == 0u ||
        mhg_secret_buf_set(&session->user_id, user_id, strlen(user_id)) != 0 ||
        mhg_secret_buf_set(&session->pass_token, pass_token,
                           strlen(pass_token)) != 0 ||
        mhg_secret_buf_set(&session->cuser_id, cuser_id, strlen(cuser_id)) != 0 ||
        mhg_secret_buf_set(&session->service_token, service_token,
                           strlen(service_token)) != 0 ||
        mhg_secret_buf_set(&session->ssecurity, ssecurity, ssecurity_len) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    session->sid = login->sid;
    result = MHG_CLOUD_OK;

out:
    mhg_secret_json_delete(header);
    mhg_secret_buf_clear(&header_security);
    if (result != MHG_CLOUD_OK) mhg_service_session_clear(session);
    return result;
}

enum mhg_cloud_error mhg_service_cookie_profile(
    const struct mhg_service_session *session, const char *passport_device_id,
    struct mhg_secret_buf *cookie_header)
{
    char *output;
    size_t length;
    int wrote;
    size_t index;

    if (cookie_header) mhg_secret_buf_clear(cookie_header);
    if (!session || !mhg_xiaomi_sid_name(session->sid) ||
        !session->user_id.data || !session->cuser_id.data ||
        !session->service_token.data || !passport_device_id ||
        strlen(passport_device_id) != 16u || !cookie_header)
        return MHG_CLOUD_INPUT;
    for (index = 0u; index < 16u; ++index) {
        unsigned char byte = (unsigned char)passport_device_id[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9')))
            return MHG_CLOUD_INPUT;
    }
    length = session->user_id.len + session->cuser_id.len +
             session->service_token.len * 2u + 16u + 256u;
    output = OPENSSL_malloc(length);
    if (!output) return MHG_CLOUD_INTERNAL;
    wrote = snprintf(output, length,
                     "userId=%s; cUserId=%s; yetAnotherServiceToken=%s; "
                     "serviceToken=%s; timezone_id=Asia/Shanghai; "
                     "timezone=GMT+08:00; is_daylight=0; dst_offset=0; "
                     "channel=MI_APP_STORE; countryCode=CN; "
                     "PassportDeviceId=%s; locale=zh_CN",
                     (char *)session->user_id.data,
                     (char *)session->cuser_id.data,
                     (char *)session->service_token.data,
                     (char *)session->service_token.data,
                     passport_device_id);
    if (wrote < 0 || (size_t)wrote >= length ||
        mhg_secret_buf_set(cookie_header, output, (size_t)wrote) != 0) {
        OPENSSL_clear_free(output, length);
        return MHG_CLOUD_INTERNAL;
    }
    OPENSSL_clear_free(output, length);
    return MHG_CLOUD_OK;
}

const char *mhg_catalog_base_url(void)
{
    return "https://api.io.mi.com/app";
}

const char *mhg_catalog_path(void)
{
    return "/v2/home/device_list_page";
}

const char *mhg_catalog_initial_params(void)
{
    return "{}";
}

enum mhg_cloud_error mhg_catalog_next_params(
    const char *start_did, struct mhg_secret_buf *params_json)
{
    cJSON *root;
    char *json;
    enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;

    if (params_json) mhg_secret_buf_clear(params_json);
    if (!start_did || !start_did[0] || !params_json) return MHG_CLOUD_INPUT;
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddStringToObject(root, "start_did", start_did)) {
        mhg_secret_json_delete(root);
        return MHG_CLOUD_INTERNAL;
    }
    json = cJSON_PrintUnformatted(root);
    mhg_secret_json_delete(root);
    if (json && mhg_secret_buf_set(params_json, json, strlen(json)) == 0)
        result = MHG_CLOUD_OK;
    if (json) {
        mhg_secure_clear(json, strlen(json));
        cJSON_free(json);
    }
    return result;
}

void mhg_catalog_page_clear(struct mhg_catalog_page *page)
{
    size_t index;

    if (!page) return;
    for (index = 0u; index < page->device_count; ++index) {
        mhg_secret_buf_clear(&page->devices[index].did);
        mhg_secret_buf_clear(&page->devices[index].model);
        mhg_secret_buf_clear(&page->devices[index].local_ip);
        mhg_secret_buf_clear(&page->devices[index].token);
    }
    OPENSSL_clear_free(page->devices,
                       page->device_count * sizeof(*page->devices));
    page->devices = NULL;
    mhg_secret_buf_clear(&page->next_start_did);
    mhg_secure_clear(page, sizeof(*page));
}

/* `model`, `localip` and `token` are not present on every entry of a real
 * directory: a device that never reported a LAN address simply has no
 * `localip`, and one without a LAN key has no `token`. Absent, null and empty
 * and mistyped values mean "this entry has no such value". */
static void catalog_entry_clear(struct mhg_catalog_device *entry)
{
    mhg_secret_buf_clear(&entry->did);
    mhg_secret_buf_clear(&entry->model);
    mhg_secret_buf_clear(&entry->local_ip);
    mhg_secret_buf_clear(&entry->token);
    mhg_secure_clear(entry, sizeof(*entry));
}

static enum mhg_cloud_error catalog_optional_text(
    const cJSON *device, const char *name, struct mhg_secret_buf *output)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(device, name);

    if (!item || cJSON_IsNull(item)) return MHG_CLOUD_OK;
    if (!cJSON_IsString(item)) return MHG_CLOUD_OK;
    if (!item->valuestring[0]) return MHG_CLOUD_OK;
    return mhg_secret_buf_set(output, item->valuestring,
                              strlen(item->valuestring)) == 0 ?
           MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
}

enum mhg_cloud_error mhg_catalog_parse_page(
    const struct mhg_service_session *session,
    struct mhg_bytes_view result_json,
    struct mhg_catalog_page *page)
{
    cJSON *root = NULL;
    cJSON *list;
    cJSON *has_more;
    cJSON *device;
    struct mhg_json_slice list_raw = {0};
    struct mhg_json_slice cursor_raw = {0};
    struct mhg_catalog_page parsed = MHG_CATALOG_PAGE_INIT;
    size_t index = 0u;
    int count = 0;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (page) mhg_catalog_page_clear(page);
    if (!session || session->sid != MHG_XIAOMI_SID_XIAOMIIO ||
        (!result_json.data && result_json.len != 0u) || !page)
        return session && session->sid == MHG_XIAOMI_SID_MIJIA ?
               MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    root = mhg_secret_json_parse_len(result_json.data, result_json.len);
    if (!root || !cJSON_IsObject(root)) goto out;
    list = cJSON_GetObjectItemCaseSensitive(root, "list");
    has_more = cJSON_GetObjectItemCaseSensitive(root, "has_more");
    if (!cJSON_IsBool(has_more)) goto out;
    if (cJSON_IsNull(list)) {
        /* A page that holds nothing is answered either as an empty array or as
         * a null list; a null list can never be a page that still has more. */
        if (cJSON_IsTrue(has_more)) goto out;
    } else {
        if (!cJSON_IsArray(list) ||
            mhg_json_object_member_slice((const char *)result_json.data,
                                         result_json.len,
                                         "list", &list_raw) != 0)
            goto out;
        count = cJSON_GetArraySize(list);
        if (count < 0) goto out;
    }
    if (count != 0) {
        parsed.devices = OPENSSL_zalloc((size_t)count * sizeof(*parsed.devices));
        if (!parsed.devices) {
            result = MHG_CLOUD_INTERNAL;
            goto out;
        }
        parsed.device_count = (size_t)count;
    }
    if (count != 0) {
        size_t position = 0u;

        cJSON_ArrayForEach(device, list) {
            cJSON *did_item = cJSON_GetObjectItemCaseSensitive(device, "did");
            struct mhg_json_slice device_raw = {0};
            struct mhg_json_slice did_raw = {0};
            struct mhg_catalog_device candidate = MHG_CATALOG_DEVICE_INIT;

            /* One unusable entry must not hide the rest of the account: it is
             * skipped and counted. An entry without a usable DID could
             * not participate in target matching anyway, so skipping it cannot
             * create a false hit; only allocation failures stay page-level. */
            if (cJSON_IsObject(device) &&
                mhg_json_array_item_slice(&list_raw, position, &device_raw) == 0 &&
                mhg_json_object_member_slice(device_raw.data, device_raw.len,
                                             "did", &did_raw) == 0) {
                result = mhg_catalog_value_parse(did_item, &did_raw,
                                                 &candidate.did);
            } else {
                result = MHG_CLOUD_MALFORMED;
            }
            if (result == MHG_CLOUD_OK)
                result = catalog_optional_text(device, "model",
                                               &candidate.model);
            if (result == MHG_CLOUD_OK)
                result = catalog_optional_text(device, "localip",
                                               &candidate.local_ip);
            if (result == MHG_CLOUD_OK)
                result = catalog_optional_text(device, "token",
                                               &candidate.token);
            if (result == MHG_CLOUD_INTERNAL) {
                catalog_entry_clear(&candidate);
                goto out;
            }
            if (result != MHG_CLOUD_OK) {
                catalog_entry_clear(&candidate);
                parsed.skipped += 1u;
                position += 1u;
                result = MHG_CLOUD_MALFORMED;
                continue;
            }
            const cJSON *online = cJSON_GetObjectItemCaseSensitive(device, "isOnline");
            candidate.online = cJSON_IsBool(online) ?
                (cJSON_IsTrue(online) ? MHG_CATALOG_ONLINE : MHG_CATALOG_OFFLINE) :
                MHG_CATALOG_ONLINE_UNKNOWN;
            parsed.devices[index] = candidate;
            index += 1u;
            position += 1u;
            result = MHG_CLOUD_MALFORMED;
        }
        parsed.device_count = index;
    }
    parsed.has_more = cJSON_IsTrue(has_more);
    if (parsed.has_more) {
        if (mhg_json_object_member_slice((const char *)result_json.data,
                                         result_json.len,
                                         "next_start_did", &cursor_raw) != 0)
            goto out;
        result = mhg_catalog_value_parse(
            cJSON_GetObjectItemCaseSensitive(root, "next_start_did"),
            &cursor_raw, &parsed.next_start_did);
        if (result != MHG_CLOUD_OK) goto out;
    }
    *page = parsed;
    parsed = (struct mhg_catalog_page)MHG_CATALOG_PAGE_INIT;
    result = MHG_CLOUD_OK;

out:
    mhg_secret_json_delete(root);
    mhg_catalog_page_clear(&parsed);
    return result;
}
