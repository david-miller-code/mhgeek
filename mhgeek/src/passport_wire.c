#include "passport_wire.h"

#include <cjson/cJSON.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_strict.h"
#include "secret_json.h"
#include "wire_scalar.h"
#include "xiaomi_account_url.h"

static const char client_user_agent[] =
    "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"; /* MHG_PUBLIC_PROTOCOL_MATERIAL */

static const struct mhg_passport_field common_headers[] = {
    {"Accept", "application/json, text/plain, */*", MHG_PASSPORT_CONSTANT},
    {"Accept-Language", "zh-CN,zh;q=0.9", MHG_PASSPORT_CONSTANT},
    {"Cache-Control", "no-cache", MHG_PASSPORT_CONSTANT},
    {"Origin", "https://account.xiaomi.com", MHG_PASSPORT_CONSTANT},
    {"Pragma", "no-cache", MHG_PASSPORT_CONSTANT},
    {"Referer", "https://account.xiaomi.com/fe/service/login/phone", MHG_PASSPORT_CONSTANT},
    {"X-Requested-With", "XMLHttpRequest", MHG_PASSPORT_CONSTANT},
    {"User-Agent", client_user_agent, MHG_PASSPORT_CONSTANT},
};
static const struct mhg_passport_field form_headers[] = {
    {"Accept", "application/json, text/plain, */*", MHG_PASSPORT_CONSTANT},
    {"Accept-Language", "zh-CN,zh;q=0.9", MHG_PASSPORT_CONSTANT},
    {"Cache-Control", "no-cache", MHG_PASSPORT_CONSTANT},
    {"Origin", "https://account.xiaomi.com", MHG_PASSPORT_CONSTANT},
    {"Pragma", "no-cache", MHG_PASSPORT_CONSTANT},
    {"Referer", "https://account.xiaomi.com/fe/service/login/phone", MHG_PASSPORT_CONSTANT},
    {"X-Requested-With", "XMLHttpRequest", MHG_PASSPORT_CONSTANT},
    {"User-Agent", client_user_agent, MHG_PASSPORT_CONSTANT},
    {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", MHG_PASSPORT_CONSTANT},
};
static const struct mhg_passport_field initial_cookies[] = {
    {"deviceId", NULL, MHG_PASSPORT_GENERATED},
    {"uLocale", "zh_CN", MHG_PASSPORT_CONSTANT},
    {"pass_ua", "web", MHG_PASSPORT_CONSTANT},
    {"pass_ptd", "1", MHG_PASSPORT_CONSTANT},
    {"passInfo", "login-end", MHG_PASSPORT_CONSTANT},
};
static const struct mhg_passport_field ticket_auth_cookies[] = {
    {"deviceId", NULL, MHG_PASSPORT_GENERATED},
    {"uLocale", "zh_CN", MHG_PASSPORT_CONSTANT},
    {"pass_ua", "web", MHG_PASSPORT_CONSTANT},
    {"pass_ptd", "1", MHG_PASSPORT_CONSTANT},
    {"passInfo", "login-end", MHG_PASSPORT_CONSTANT},
    {"ticketToken", NULL, MHG_PASSPORT_SECRET},
};
static const char *const phone_info_response_cookies[] = {"ticketToken"};
static const char *const ticket_auth_response_cookies[] = {
    "deviceId", "userId", "passToken",
};

static const struct mhg_passport_field policy_query[] = {
    {"_locale", "zh_CN", MHG_PASSPORT_CONSTANT},
};
static const struct mhg_passport_field preference_form[] = {
    {"phone", NULL, MHG_PASSPORT_EUI_ENCRYPTED},
};
static const struct mhg_passport_field send_form[] = {
    {"sid", "passport", MHG_PASSPORT_CONSTANT},
    {"user", NULL, MHG_PASSPORT_EUI_ENCRYPTED},
    {"captCode", "", MHG_PASSPORT_CONSTANT},
};
static const struct mhg_passport_field phone_info_form[] = {
    {"sid", "passport", MHG_PASSPORT_CONSTANT},
    {"user", NULL, MHG_PASSPORT_SESSION},
    {"ticket", NULL, MHG_PASSPORT_SECRET},
    {"policyName", NULL, MHG_PASSPORT_SESSION},
};
static const struct mhg_passport_field ticket_auth_form[] = {
    {"callback", "https://account.xiaomi.com", MHG_PASSPORT_CONSTANT},
    {"sid", "passport", MHG_PASSPORT_CONSTANT},
    {"qs", "%3Fsid%3Dpassport", MHG_PASSPORT_CONSTANT},
    {"serviceParam", "", MHG_PASSPORT_CONSTANT},
    {"_sign", "", MHG_PASSPORT_CONSTANT},
    {"user", NULL, MHG_PASSPORT_SESSION},
    {"ticket", NULL, MHG_PASSPORT_SECRET},
    {"_json", "true", MHG_PASSPORT_CONSTANT},
    {"_locale", "zh_CN", MHG_PASSPORT_CONSTANT},
    {"deviceFingerprint", NULL, MHG_PASSPORT_GENERATED},
};

#define ARRAY_LEN(value) (sizeof(value) / sizeof((value)[0]))

static const struct mhg_passport_request_contract contracts[] = {
    {MHG_PASSPORT_POLICY, "GET", "/fe/service/login/phone",
     policy_query, ARRAY_LEN(policy_query), NULL, 0u,
     common_headers, ARRAY_LEN(common_headers), initial_cookies,
     ARRAY_LEN(initial_cookies), 0, 0, NULL, NULL, 0u},
    {MHG_PASSPORT_PREFERENCE, "POST", "/pass/preference",
     NULL, 0u, preference_form, ARRAY_LEN(preference_form),
     form_headers, ARRAY_LEN(form_headers), initial_cookies,
     ARRAY_LEN(initial_cookies), 1, 0, "EUI", NULL, 0u},
    {MHG_PASSPORT_SEND_TICKET, "POST", "/pass/sendServiceLoginTicket",
     NULL, 0u, send_form, ARRAY_LEN(send_form),
     form_headers, ARRAY_LEN(form_headers), initial_cookies,
     ARRAY_LEN(initial_cookies), 1, 0, "EUI", NULL, 0u},
    {MHG_PASSPORT_PHONE_INFO, "POST", "/pass/phoneInfo",
     NULL, 0u, phone_info_form, ARRAY_LEN(phone_info_form),
     form_headers, ARRAY_LEN(form_headers), initial_cookies,
     ARRAY_LEN(initial_cookies), 0, 1, NULL,
     phone_info_response_cookies, ARRAY_LEN(phone_info_response_cookies)},
    {MHG_PASSPORT_TICKET_AUTH, "POST", "/pass/serviceLoginTicketAuth",
     NULL, 0u, ticket_auth_form, ARRAY_LEN(ticket_auth_form),
     form_headers, ARRAY_LEN(form_headers), ticket_auth_cookies,
     ARRAY_LEN(ticket_auth_cookies), 0, 1, NULL,
     ticket_auth_response_cookies, ARRAY_LEN(ticket_auth_response_cookies)},
};

const char *mhg_passport_client_user_agent(void)
{
    return client_user_agent;
}

const char *mhg_passport_base_url(void)
{
    return "https://account.xiaomi.com";
}

const struct mhg_passport_request_contract *mhg_passport_contract(
    enum mhg_passport_step step)
{
    size_t index;

    for (index = 0u; index < ARRAY_LEN(contracts); ++index)
        if (contracts[index].step == step) return &contracts[index];
    return NULL;
}

void mhg_passport_response_clear(struct mhg_passport_response *response)
{
    if (!response) return;
    mhg_secret_buf_clear(&response->user_id);
    mhg_secret_buf_clear(&response->pass_token);
    mhg_secret_buf_clear(&response->location);
    mhg_secure_clear(response, sizeof(*response));
}

static enum mhg_cloud_error passport_user_id_from_text(
    const char *text, struct mhg_secret_buf *output)
{
    const char *digits = text;
    size_t length;
    size_t index;
    if (!text || !output) return MHG_CLOUD_INPUT;
    length = strlen(text);
    if (length == 0u) return MHG_CLOUD_MALFORMED;
    for (index = 0u; index < length; ++index)
        if ((unsigned char)text[index] < '0' ||
            (unsigned char)text[index] > '9')
            return MHG_CLOUD_MALFORMED;
    while (length > 1u && *digits == '0') {
        ++digits;
        --length;
    }
    return mhg_secret_buf_set(output, digits, length) == 0 ?
           MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
}

enum mhg_cloud_error mhg_passport_apply_ticket_redirect(
    struct mhg_passport_response *response, const char *user_id_cookie,
    const char *pass_token_cookie)
{
    struct mhg_secret_buf user_id = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf pass_token = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cookie_user_id = MHG_SECRET_BUF_INIT;
    const char *json_user;
    const char *json_token;
    const char *selected_user;
    const char *selected_token;
    int has_cookie_user;
    int has_cookie_token;
    enum mhg_cloud_error result;

    if (!response || !response->user_id.data || !response->location.data)
        return MHG_CLOUD_INPUT;
    json_user = (const char *)response->user_id.data;
    json_token = (const char *)response->pass_token.data;
    has_cookie_user = user_id_cookie && user_id_cookie[0];
    has_cookie_token = pass_token_cookie && pass_token_cookie[0];

    /* A redirect cookie token is valid only as part of its complete identity
     * pair. The JSON pair remains the fallback when the jar has no complete
     * pair; values from the two sources are never spliced together. */
    if (has_cookie_user) {
        result = passport_user_id_from_text(user_id_cookie, &cookie_user_id);
        if (result != MHG_CLOUD_OK) goto out;
        if (cookie_user_id.len != response->user_id.len ||
            memcmp(cookie_user_id.data, response->user_id.data,
                   response->user_id.len) != 0) {
            result = MHG_CLOUD_MALFORMED;
            goto out;
        }
    }
    if (has_cookie_user && has_cookie_token) {
        selected_user = (const char *)cookie_user_id.data;
        selected_token = pass_token_cookie;
    } else {
        selected_user = json_user;
        selected_token = json_token;
    }
    result = passport_user_id_from_text(selected_user, &user_id);
    if (result != MHG_CLOUD_OK) goto out;
    if (!selected_token || !selected_token[0]) {
        result = MHG_CLOUD_MALFORMED;
        goto out;
    }
    if (mhg_secret_buf_set(&pass_token, selected_token,
                           strlen(selected_token)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    mhg_secret_buf_clear(&response->user_id);
    response->user_id = user_id;
    user_id = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    mhg_secret_buf_clear(&response->pass_token);
    response->pass_token = pass_token;
    pass_token = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    result = MHG_CLOUD_OK;

out:
    mhg_secret_buf_clear(&cookie_user_id);
    mhg_secret_buf_clear(&user_id);
    mhg_secret_buf_clear(&pass_token);
    if (result != MHG_CLOUD_OK) mhg_passport_response_clear(response);
    return result;
}

static struct mhg_bytes_view strip_prefix(struct mhg_bytes_view body)
{
    static const char prefix[] = "&&&START&&&";

    if (body.len >= sizeof(prefix) - 1u &&
        memcmp(body.data, prefix, sizeof(prefix) - 1u) == 0) {
        body.data += sizeof(prefix) - 1u;
        body.len -= sizeof(prefix) - 1u;
    }
    return body;
}

static const unsigned char *find_bytes(const unsigned char *haystack,
                                       size_t haystack_len,
                                       const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t index;

    if (needle_len == 0u || needle_len > haystack_len) return NULL;
    for (index = 0u; index <= haystack_len - needle_len; ++index)
        if (memcmp(haystack + index, needle, needle_len) == 0)
            return haystack + index;
    return NULL;
}

enum mhg_cloud_error mhg_passport_parse_response(
    enum mhg_passport_step step, struct mhg_bytes_view body,
    struct mhg_passport_response *response)
{
    cJSON *root = NULL;
    cJSON *data;
    cJSON *item;
    struct mhg_json_slice code_raw = {0};
    struct mhg_json_slice data_raw = {0};
    struct mhg_json_slice field_raw = {0};
    struct mhg_json_slice user_id_raw = {0};
    struct mhg_bytes_view json_body;
    int code;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (response) mhg_passport_response_clear(response);
    if ((!body.data && body.len != 0u) || !response ||
        !mhg_passport_contract(step))
        return MHG_CLOUD_INPUT;
    if (step == MHG_PASSPORT_POLICY) {
        static const char marker_text[] = "window.region=\"";
        const unsigned char *marker;
        const unsigned char *end;
        size_t length;
        size_t index;
        char region[32];

        if (!body.data || body.len == 0u ||
            memchr(body.data, '\0', body.len) != NULL)
            return MHG_CLOUD_MALFORMED;
        marker = find_bytes(body.data, body.len, marker_text);
        if (!marker) return MHG_CLOUD_MALFORMED;
        marker += sizeof(marker_text) - 1u;
        end = memchr(marker, '"',
                     body.len - (size_t)(marker - body.data));
        if (!end || end == marker) return MHG_CLOUD_MALFORMED;
        length = (size_t)(end - marker);
        if (length >= sizeof(region)) return MHG_CLOUD_MALFORMED;
        for (index = 0u; index < length; ++index) {
            unsigned char byte = (unsigned char)marker[index];
            if (!((byte >= 'A' && byte <= 'Z') ||
                  (byte >= 'a' && byte <= 'z') ||
                  (byte >= '0' && byte <= '9') || byte == '_' || byte == '-'))
                return MHG_CLOUD_MALFORMED;
            region[index] = byte >= 'A' && byte <= 'Z' ?
                            (char)(byte - 'A' + 'a') : (char)byte;
        }
        region[length] = '\0';
        if (strstr(region, "cnbj") || strstr(region, "staging"))
            memcpy(response->policy_name, "miaccount", 10u);
        else
            memcpy(response->policy_name, "globalmiaccount", 16u);
        return MHG_CLOUD_OK;
    }

    json_body = strip_prefix(body);
    root = mhg_secret_json_parse_len(json_body.data, json_body.len);
    if (!root || !cJSON_IsObject(root) ||
        mhg_json_object_member_slice((const char *)json_body.data,
                                     json_body.len, "code",
                                     &code_raw) != 0 ||
        mhg_json_decimal_int_parse(
            cJSON_GetObjectItemCaseSensitive(root, "code"), &code_raw,
            &code) != MHG_CLOUD_OK)
        goto out;
    if (code != 0) {
        response->provider_code = code;
        response->provider_class = mhg_passport_provider_classify(code);
        result = MHG_CLOUD_SERVICE;
        goto out;
    }
    data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (cJSON_IsObject(data) &&
        mhg_json_object_member_slice((const char *)json_body.data,
                                     json_body.len, "data",
                                     &data_raw) != 0)
        goto out;
    if (step == MHG_PASSPORT_PREFERENCE) {
        item = cJSON_GetObjectItemCaseSensitive(data, "type");
        if (cJSON_IsObject(data) && cJSON_IsString(item) &&
            strcmp(item->valuestring, "ticket") == 0)
            result = MHG_CLOUD_OK;
    } else if (step == MHG_PASSPORT_SEND_TICKET) {
        int code_length;
        int wait;
        if (cJSON_IsObject(data) &&
            mhg_json_object_member_slice(data_raw.data, data_raw.len,
                                         "vCodeLen", &field_raw) == 0 &&
            mhg_json_decimal_int_parse(
                cJSON_GetObjectItemCaseSensitive(data, "vCodeLen"),
                &field_raw, &code_length) == MHG_CLOUD_OK &&
            code_length > 0 &&
            mhg_json_object_member_slice(data_raw.data, data_raw.len,
                                         "wt", &field_raw) == 0 &&
            mhg_json_decimal_int_parse(
                cJSON_GetObjectItemCaseSensitive(data, "wt"),
                &field_raw, &wait) == MHG_CLOUD_OK && wait >= 0) {
            response->code_length = (unsigned int)code_length;
            response->retry_after_seconds = (unsigned int)wait;
            result = MHG_CLOUD_OK;
        }
    } else if (step == MHG_PASSPORT_PHONE_INFO) {
        int status;
        if (cJSON_IsObject(data) &&
            mhg_json_object_member_slice(data_raw.data, data_raw.len,
                                         "status", &field_raw) == 0 &&
            mhg_json_decimal_int_parse(
                cJSON_GetObjectItemCaseSensitive(data, "status"),
                &field_raw, &status) == MHG_CLOUD_OK)
            result = status == 2 ? MHG_CLOUD_OK : MHG_CLOUD_AUTH_REJECTED;
    } else if (step == MHG_PASSPORT_TICKET_AUTH) {
        const cJSON *location = cJSON_GetObjectItemCaseSensitive(root, "location");
        const cJSON *pass_token = cJSON_GetObjectItemCaseSensitive(root, "passToken");
        const cJSON *user_id = cJSON_GetObjectItemCaseSensitive(root, "userId");
        if (!cJSON_IsString(location) ||
            !mhg_xiaomi_account_redirect_is_trusted(location->valuestring) ||
            (pass_token &&
             (!cJSON_IsString(pass_token) || !pass_token->valuestring[0])))
            goto out;
        if (mhg_json_object_member_slice((const char *)json_body.data,
                                         json_body.len,
                                         "userId", &user_id_raw) != 0)
            goto out;
        result = mhg_passport_user_id_parse(user_id, &user_id_raw,
                                             &response->user_id);
        if (result != MHG_CLOUD_OK) goto out;
        if ((pass_token &&
             mhg_secret_buf_set(&response->pass_token,
                                pass_token->valuestring,
                                strlen(pass_token->valuestring)) != 0) ||
            mhg_secret_buf_set(&response->location, location->valuestring,
                               strlen(location->valuestring)) != 0) {
            result = MHG_CLOUD_INTERNAL;
            goto out;
        }
        result = MHG_CLOUD_OK;
    }

out:
    mhg_secret_json_delete(root);
    if (result != MHG_CLOUD_OK) {
        mhg_secret_buf_clear(&response->user_id);
        mhg_secret_buf_clear(&response->pass_token);
        mhg_secret_buf_clear(&response->location);
        memset(response->policy_name, 0, sizeof(response->policy_name));
        response->code_length = 0u;
        response->retry_after_seconds = 0u;
    }
    return result;
}

enum mhg_cloud_error mhg_passport_eui_aes_encrypt(
    const unsigned char key[16], const unsigned char *plaintext,
    size_t plaintext_len, struct mhg_secret_buf *ciphertext)
{
    static const unsigned char iv[16] = "0102030405060708";
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *output = NULL;
    int first = 0;
    int final = 0;
    enum mhg_cloud_error result = MHG_CLOUD_CRYPTO;

    if (ciphertext) mhg_secret_buf_clear(ciphertext);
    if (!key || !plaintext || plaintext_len == 0u || !ciphertext ||
        plaintext_len > INT_MAX - 16)
        return MHG_CLOUD_INPUT;
    context = EVP_CIPHER_CTX_new();
    output = OPENSSL_malloc(plaintext_len + 16u);
    if (!context || !output) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    if (EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(context, output, &first, plaintext,
                          (int)plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(context, output + first, &final) != 1)
        goto out;
    if (mhg_secret_buf_set(ciphertext, output, (size_t)(first + final)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    result = MHG_CLOUD_OK;

out:
    if (output) OPENSSL_clear_free(output, plaintext_len + 16u);
    EVP_CIPHER_CTX_free(context);
    return result;
}

static int base64_encode(const unsigned char *input, size_t input_len,
                         struct mhg_secret_buf *output)
{
    unsigned char *encoded;
    size_t capacity;
    int length;

    if (input_len > (size_t)INT_MAX) return -1;
    capacity = 4u * ((input_len + 2u) / 3u);
    encoded = OPENSSL_malloc(capacity + 1u);
    if (!encoded) return -1;
    length = EVP_EncodeBlock(encoded, input, (int)input_len);
    if (length < 0 || mhg_secret_buf_set(output, encoded, (size_t)length) != 0) {
        OPENSSL_clear_free(encoded, capacity + 1u);
        return -1;
    }
    OPENSSL_clear_free(encoded, capacity + 1u);
    return 0;
}

enum mhg_cloud_error mhg_passport_eui_header(
    EVP_PKEY *public_key, const unsigned char aes_key[16],
    const char *field_name, struct mhg_secret_buf *header_value)
{
    EVP_PKEY_CTX *context = NULL;
    struct mhg_secret_buf key_b64 = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf wrapped = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf wrapped_b64 = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf field_b64 = MHG_SECRET_BUF_INIT;
    unsigned char *joined = NULL;
    size_t wrapped_len = 0u;
    size_t joined_len;
    enum mhg_cloud_error result = MHG_CLOUD_CRYPTO;

    if (header_value) mhg_secret_buf_clear(header_value);
    if (!public_key || !aes_key || !field_name || !field_name[0] || !header_value)
        return MHG_CLOUD_INPUT;
    if (base64_encode(aes_key, 16u, &key_b64) != 0) goto out;
    context = EVP_PKEY_CTX_new(public_key, NULL);
    if (!context || EVP_PKEY_encrypt_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(context, NULL, &wrapped_len,
                         key_b64.data, key_b64.len) <= 0)
        goto out;
    wrapped.data = OPENSSL_malloc(wrapped_len + 1u);
    if (!wrapped.data) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    wrapped.len = wrapped_len;
    wrapped.data[wrapped_len] = '\0';
    if (EVP_PKEY_encrypt(context, wrapped.data, &wrapped.len,
                         key_b64.data, key_b64.len) <= 0)
        goto out;
    wrapped.data[wrapped.len] = '\0';
    if (base64_encode(wrapped.data, wrapped.len, &wrapped_b64) != 0 ||
        base64_encode((const unsigned char *)field_name, strlen(field_name),
                      &field_b64) != 0)
        goto out;
    joined_len = wrapped_b64.len + 1u + field_b64.len;
    joined = OPENSSL_malloc(joined_len);
    if (!joined) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    memcpy(joined, wrapped_b64.data, wrapped_b64.len);
    joined[wrapped_b64.len] = '.';
    memcpy(joined + wrapped_b64.len + 1u, field_b64.data, field_b64.len);
    if (mhg_secret_buf_set(header_value, joined, joined_len) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    result = MHG_CLOUD_OK;

out:
    if (joined) OPENSSL_clear_free(joined, joined_len);
    mhg_secret_buf_clear(&key_b64);
    mhg_secret_buf_clear(&wrapped);
    mhg_secret_buf_clear(&wrapped_b64);
    mhg_secret_buf_clear(&field_b64);
    EVP_PKEY_CTX_free(context);
    return result;
}

EVP_PKEY *mhg_passport_eui_protocol_public_key(void)
{
    static const char der_b64[] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYEVrK/4Mahiv0pUJgTybx4J9P5dUT/Y0PuwMbk+gMU+jrZnBiXGv6/hCH1avIhoBcE535F8nJQQN3UavZdFkYidsoXuEnat3+eVTp3FslyhRwIBDF09v4vDhRtxFOT+R7uH7h/mzmyA2/+lfIMWGIrffXprYizbV76+YQKhoqFQIDAQAB"; /* MHG_PUBLIC_PROTOCOL_MATERIAL */
    unsigned char der[256];
    const unsigned char *cursor = der;
    int length;
    EVP_PKEY *key;

    length = EVP_DecodeBlock(der, (const unsigned char *)der_b64,
                             (int)strlen(der_b64));
    if (length <= 0) return NULL;
    if (der_b64[strlen(der_b64) - 1u] == '=') --length;
    if (der_b64[strlen(der_b64) - 2u] == '=') --length;
    key = d2i_PUBKEY(NULL, &cursor, length);
    mhg_secure_clear(der, sizeof(der));
    return key;
}

int mhg_passport_ticket_is_valid(const char *ticket, size_t expected_length)
{
    size_t index;

    if (!ticket || expected_length == 0u || strlen(ticket) != expected_length)
        return 0;
    for (index = 0u; index < expected_length; ++index)
        if (ticket[index] < '0' || ticket[index] > '9') return 0;
    return 1;
}

const char *mhg_passport_provider_class_name(
    enum mhg_passport_provider_class provider_class)
{
    switch (provider_class) {
    case MHG_PASSPORT_PROVIDER_NONE: return "none";
    case MHG_PASSPORT_SMS_SEND_LIMIT_TOMORROW:
        return "sms_send_limit_tomorrow";
    case MHG_PASSPORT_SMS_CODE_INVALID_OR_EXPIRED:
        return "sms_code_invalid_or_expired";
    case MHG_PASSPORT_ADDITIONAL_VERIFICATION_REQUIRED:
        return "additional_verification_required";
    case MHG_PASSPORT_PROVIDER_OTHER: return "provider";
    }
    return NULL;
}

enum mhg_passport_provider_class mhg_passport_provider_classify(int code)
{
    if (code == 0) return MHG_PASSPORT_PROVIDER_NONE;
    if (code == 70022) return MHG_PASSPORT_SMS_SEND_LIMIT_TOMORROW;
    if (code == 70016 || code == 70017 || code == 70018)
        return MHG_PASSPORT_SMS_CODE_INVALID_OR_EXPIRED;
    if (code == 70069 || code == 70070)
        return MHG_PASSPORT_ADDITIONAL_VERIFICATION_REQUIRED;
    return MHG_PASSPORT_PROVIDER_OTHER;
}
