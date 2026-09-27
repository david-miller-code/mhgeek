#include "mijia_core.h"

#include <cjson/cJSON.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

#include "json_strict.h"
#include "secret_json.h"

static const struct mhg_core_header compatible_headers[] = {
    {"MIOT-REQUEST-MODEL", NULL, MHG_CORE_HEADER_MODEL},
    {"Accept", "*/*", MHG_CORE_HEADER_CONSTANT},
    {"Accept-Encoding", "identity", MHG_CORE_HEADER_CONSTANT},
    {"User-Agent", "Android-15-11.0.701-Xiaomi-SmartHome-MI_APP_STORE-64",
     MHG_CORE_HEADER_CONSTANT},
    {"domain-refer", "core.api.mijia.tech", MHG_CORE_HEADER_CONSTANT},
    {"miot-encrypt-algorithm", "ENCRYPT-RC4", MHG_CORE_HEADER_CONSTANT},
    {"X-XIAOMI-PROTOCAL-FLAG-CLI", "PROTOCAL-HTTP2",
     MHG_CORE_HEADER_CONSTANT},
};

const char *mhg_core_base_url(void)
{
    return "https://core.api.mijia.tech/app";
}

const char *mhg_core_method_name(enum mhg_core_method method)
{
    if (method == MHG_CORE_AUTOWEBCONFIG)
        return "miIO.get_autowebconfig_url";
    if (method == MHG_CORE_CENTRAL_LINK_PASSCODE)
        return "miIO.get_central_link_passcode";
    return NULL;
}

const struct mhg_core_header *mhg_core_compatible_headers(size_t *count)
{
    if (count) *count = sizeof(compatible_headers) / sizeof(compatible_headers[0]);
    return compatible_headers;
}

static int unreserved(unsigned char byte)
{
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
           byte == '.' || byte == '~';
}

enum mhg_cloud_error mhg_core_canonical_path(
    const struct mhg_service_session *session, const char *did,
    struct mhg_secret_buf *path)
{
    static const char prefix[] = "/home/rpc/";
    static const char hex[] = "0123456789ABCDEF";
    size_t index;
    size_t length = sizeof(prefix) - 1u;
    char *output;
    char *cursor;

    if (path) mhg_secret_buf_clear(path);
    if (!session || session->sid != MHG_XIAOMI_SID_MIJIA || !did || !did[0] ||
        !path)
        return session && session->sid == MHG_XIAOMI_SID_XIAOMIIO ?
               MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    for (index = 0u; did[index]; ++index)
        length += unreserved((unsigned char)did[index]) ? 1u : 3u;
    output = OPENSSL_malloc(length + 1u);
    if (!output) return MHG_CLOUD_INTERNAL;
    memcpy(output, prefix, sizeof(prefix) - 1u);
    cursor = output + sizeof(prefix) - 1u;
    for (index = 0u; did[index]; ++index) {
        unsigned char byte = (unsigned char)did[index];
        if (unreserved(byte)) {
            *cursor++ = (char)byte;
        } else {
            *cursor++ = '%';
            *cursor++ = hex[byte >> 4];
            *cursor++ = hex[byte & 0x0fu];
        }
    }
    *cursor = '\0';
    if (mhg_secret_buf_set(path, output, length) != 0) {
        OPENSSL_clear_free(output, length + 1u);
        return MHG_CLOUD_INTERNAL;
    }
    OPENSSL_clear_free(output, length + 1u);
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_core_build_data(
    enum mhg_core_method method, uint64_t id, const char *access_key,
    struct mhg_secret_buf *data_json)
{
    cJSON *root = NULL;
    cJSON *params = NULL;
    char id_text[32];
    char *json = NULL;
    int wrote;
    enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;
    const char *method_name = mhg_core_method_name(method);

    if (data_json) mhg_secret_buf_clear(data_json);
    if (!method_name || !access_key || !access_key[0] || !data_json ||
        id > UINT64_C(9007199254740991))
        return MHG_CLOUD_INPUT;
    wrote = snprintf(id_text, sizeof(id_text), "%llu",
                     (unsigned long long)id);
    if (wrote <= 0 || (size_t)wrote >= sizeof(id_text)) return MHG_CLOUD_INTERNAL;
    root = cJSON_CreateObject();
    params = cJSON_CreateArray();
    if (!root || !params ||
        !cJSON_AddRawToObject(root, "id", id_text) ||
        !cJSON_AddStringToObject(root, "method", method_name) ||
        !cJSON_AddStringToObject(root, "accessKey", access_key) ||
        !cJSON_AddItemToObject(root, "params", params))
        goto out;
    params = NULL;
    json = cJSON_PrintUnformatted(root);
    if (json && mhg_secret_buf_set(data_json, json, strlen(json)) == 0)
        result = MHG_CLOUD_OK;

out:
    cJSON_Delete(params);
    mhg_secret_json_delete(root);
    if (json) {
        mhg_secure_clear(json, strlen(json));
        cJSON_free(json);
    }
    return result;
}

enum mhg_cloud_error mhg_core_validate_data(const char *data_json)
{
    cJSON *root;
    cJSON *id;
    cJSON *method;
    cJSON *access_key;
    cJSON *params;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (!data_json) return MHG_CLOUD_INPUT;
    root = mhg_secret_json_parse(data_json);
    if (!root || !cJSON_IsObject(root)) goto out;
    id = cJSON_GetObjectItemCaseSensitive(root, "id");
    method = cJSON_GetObjectItemCaseSensitive(root, "method");
    access_key = cJSON_GetObjectItemCaseSensitive(root, "accessKey");
    params = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (cJSON_GetArraySize(root) == 4 && cJSON_IsNumber(id) &&
        id->valuedouble >= 0.0 && id->valuedouble <= 9007199254740991.0 &&
        id->valuedouble == (double)(uint64_t)id->valuedouble &&
        cJSON_IsString(method) && mhg_core_method_name(MHG_CORE_AUTOWEBCONFIG) &&
        (strcmp(method->valuestring,
                mhg_core_method_name(MHG_CORE_AUTOWEBCONFIG)) == 0 ||
         strcmp(method->valuestring,
                mhg_core_method_name(MHG_CORE_CENTRAL_LINK_PASSCODE)) == 0) &&
        cJSON_IsString(access_key) && access_key->valuestring[0] &&
        cJSON_IsArray(params) && cJSON_GetArraySize(params) == 0)
        result = MHG_CLOUD_OK;
out:
    mhg_secret_json_delete(root);
    return result;
}

void mhg_core_passcode_clear(struct mhg_core_passcode *passcode)
{
    if (!passcode) return;
    mhg_secret_buf_clear(&passcode->value);
    mhg_secure_clear(passcode, sizeof(*passcode));
}

void mhg_core_autowebconfig_clear(
    struct mhg_core_autowebconfig *autowebconfig)
{
    if (!autowebconfig) return;
    mhg_secret_buf_clear(&autowebconfig->url);
    mhg_secure_clear(autowebconfig, sizeof(*autowebconfig));
}

enum mhg_cloud_error mhg_core_parse_passcode(
    const struct mhg_service_session *session,
    struct mhg_bytes_view result_json,
    struct mhg_core_passcode *passcode)
{
    cJSON *root;
    cJSON *item;
    size_t index;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (passcode) mhg_core_passcode_clear(passcode);
    if (!session || session->sid != MHG_XIAOMI_SID_MIJIA ||
        (!result_json.data && result_json.len != 0u) || !passcode)
        return session && session->sid == MHG_XIAOMI_SID_XIAOMIIO ?
               MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    root = mhg_secret_json_parse_len(result_json.data, result_json.len);
    if (!root || !cJSON_IsObject(root)) goto out;
    item = cJSON_GetObjectItemCaseSensitive(root, "passcode");
    if (!cJSON_IsString(item) || strlen(item->valuestring) != 6u) goto out;
    for (index = 0u; index < 6u; ++index)
        if (item->valuestring[index] < '0' || item->valuestring[index] > '9')
            goto out;
    result = mhg_secret_buf_set(&passcode->value, item->valuestring, 6u) == 0 ?
             MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
out:
    mhg_secret_json_delete(root);
    if (result != MHG_CLOUD_OK) mhg_core_passcode_clear(passcode);
    return result;
}

enum mhg_cloud_error mhg_core_parse_autowebconfig(
    const struct mhg_service_session *session,
    struct mhg_bytes_view result_json,
    struct mhg_core_autowebconfig *autowebconfig)
{
    cJSON *root;
    cJSON *url;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (autowebconfig) mhg_core_autowebconfig_clear(autowebconfig);
    if (!session || session->sid != MHG_XIAOMI_SID_MIJIA ||
        (!result_json.data && result_json.len != 0u) || !autowebconfig)
        return session && session->sid == MHG_XIAOMI_SID_XIAOMIIO ?
               MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    root = mhg_secret_json_parse_len(result_json.data, result_json.len);
    if (!root || !cJSON_IsObject(root)) goto out;
    url = cJSON_GetObjectItemCaseSensitive(root, "url");
    if (!cJSON_IsString(url) || !url->valuestring[0]) goto out;
    result = mhg_secret_buf_set(&autowebconfig->url, url->valuestring,
                                strlen(url->valuestring)) == 0 ?
             MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
out:
    mhg_secret_json_delete(root);
    if (result != MHG_CLOUD_OK)
        mhg_core_autowebconfig_clear(autowebconfig);
    return result;
}
