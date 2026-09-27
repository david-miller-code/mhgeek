#include "spec_action.h"

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_json.h"

#define MHG_SPEC_LIMIT (256u * 1024u)

struct spec_buffer {
    char *data;
    size_t length;
    size_t limit;
    int overflow;
};

static size_t collect(void *contents, size_t size, size_t count, void *userdata)
{
    struct spec_buffer *buffer = userdata;
    if (size && count > SIZE_MAX / size) return 0;
    size_t bytes = size * count;

    if (buffer->overflow) return 0;
    if (bytes > buffer->limit - buffer->length) {
        buffer->overflow = 1;
        return 0;
    }
    memcpy(buffer->data + buffer->length, contents, bytes);
    buffer->length += bytes;
    return bytes;
}

static bool positive_id(const cJSON *value)
{
    return cJSON_IsNumber(value) && isfinite(value->valuedouble) &&
           value->valuedouble >= 1 && value->valuedouble <= INT_MAX &&
           value->valuedouble == (double)(int)value->valuedouble;
}

static int property_format(const cJSON *service, int iid, const char **format)
{
    const cJSON *properties =
        cJSON_GetObjectItemCaseSensitive(service, "properties");
    const cJSON *property;

    cJSON_ArrayForEach(property, properties) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(property, "iid");
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(property, "format");

        if (positive_id(id) && (int)id->valuedouble == iid) {
            *format = cJSON_IsString(value) ? value->valuestring : NULL;
            return 0;
        }
    }
    return -1;
}

int mhg_spec_action_from_json(const char *spec_json, size_t length,
                              struct mhg_spec_action *action,
                              struct mhg_error *error)
{
    cJSON *root = NULL;
    const cJSON *services;
    const cJSON *service;
    int found = 0;
    struct mhg_spec_action candidate = {0, 0, 0};

    if (!spec_json || !action || length == 0u || length == SIZE_MAX) return -1;
    if (memchr(spec_json, '\0', length)) {
        mhg_errorf(error, EPROTO, "spec document contains a NUL byte");
        return -1;
    }
    root = mhg_secret_json_parse_len((const unsigned char *)spec_json, length);
    if (!root) {
        mhg_errorf(error, EPROTO, "spec document is not strict JSON");
        return -1;
    }
    services = cJSON_GetObjectItemCaseSensitive(root, "services");
    if (!cJSON_IsArray(services)) {
        mhg_errorf(error, EPROTO, "spec has no services array");
        cJSON_Delete(root);
        return -1;
    }
    cJSON_ArrayForEach(service, services) {
        const cJSON *actions =
            cJSON_GetObjectItemCaseSensitive(service, "actions");
        const cJSON *entry;
        const cJSON *siid = cJSON_GetObjectItemCaseSensitive(service, "iid");

        if (!cJSON_IsArray(actions) || !positive_id(siid)) continue;
        cJSON_ArrayForEach(entry, actions) {
            const cJSON *aiid = cJSON_GetObjectItemCaseSensitive(entry, "iid");
            const cJSON *ins = cJSON_GetObjectItemCaseSensitive(entry, "in");
            const cJSON *piid;
            const char *format = NULL;

            if (!positive_id(aiid) || !cJSON_IsArray(ins) ||
                cJSON_GetArraySize(ins) != 1)
                continue;
            piid = cJSON_GetArrayItem(ins, 0);
            if (!positive_id(piid)) continue;
            if (property_format(service, (int)piid->valuedouble, &format) != 0 ||
                !format || strcmp(format, "string") != 0)
                continue;
            candidate.siid = (int)siid->valuedouble;
            candidate.aiid = (int)aiid->valuedouble;
            candidate.piid = (int)piid->valuedouble;
            found += 1;
        }
    }
    cJSON_Delete(root);
    if (found != 1) {
        /* Zero means the device has no text-output Action; several means the
         * choice would be a guess. Neither is acceptable. */
        mhg_errorf(error, EPROTO,
                   "spec exposes %d string-input actions, expected one", found);
        return -1;
    }
    *action = candidate;
    return 0;
}

int mhg_spec_action_derive(const char *urn, const char *ca_info,
                           struct mhg_spec_action *action,
                           struct mhg_error *error)
{
    struct spec_buffer buffer = {0};
    char url[1024];
    char *encoded_urn = NULL;
    CURL *handle = NULL;
    CURLcode code;
    long status = 0;
    int written;
    int result = -1;

    if (!urn || !action || !ca_info || !ca_info[0]) return -1;
    handle = curl_easy_init();
    if (!handle) return mhg_errorf(error, ENOMEM, "spec curl allocation failed");
    encoded_urn = curl_easy_escape(handle, urn, 0);
    if (!encoded_urn) {
        mhg_errorf(error, ENOMEM, "spec query allocation failed");
        goto done;
    }
    written = snprintf(url, sizeof(url),
                       "https://miot-spec.org/miot-spec-v2/instance?type=%s",
                       encoded_urn);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        mhg_errorf(error, ENAMETOOLONG, "spec url is too long");
        goto done;
    }
    buffer.data = calloc(1u, MHG_SPEC_LIMIT + 1u);
    buffer.limit = MHG_SPEC_LIMIT;
    if (!buffer.data) {
        mhg_errorf(error, ENOMEM, "spec buffer allocation failed");
        goto done;
    }
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_PROXY, "");
    /* The product ships its own CA bundle; without it the board has no trust
     * store for a public HTTPS endpoint. */
    if (ca_info && ca_info[0])
        curl_easy_setopt(handle, CURLOPT_CAINFO, ca_info);
    code = curl_easy_perform(handle);
    if (code != CURLE_OK) {
        mhg_errorf(error, EIO, "spec fetch failed (%s)", curl_easy_strerror(code));
        goto done;
    }
    if (buffer.overflow) {
        mhg_errorf(error, EFBIG, "spec document exceeded the response cap");
        goto done;
    }
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) {
        mhg_errorf(error, EPROTO, "spec endpoint answered %ld", status);
        goto done;
    }
    buffer.data[buffer.length] = '\0';
    result = mhg_spec_action_from_json(buffer.data, buffer.length, action, error);

done:
    curl_free(encoded_urn);
    if (handle) curl_easy_cleanup(handle);
    if (buffer.data) {
        OPENSSL_clear_free(buffer.data, buffer.limit + 1u);
    }
    return result;
}
