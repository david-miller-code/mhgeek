#include "cloud_crypto.h"

#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_strict.h"
#include "rc4_drop1024.h"
#include "secret_json.h"
#include "wire_scalar.h"

static int base64_encode(const unsigned char *input, size_t input_len,
                         struct mhg_secret_buf *output)
{
    unsigned char *encoded;
    size_t capacity;
    int length;

    if (!input || input_len == 0u || input_len > (size_t)INT_MAX) return -1;
    capacity = 4u * ((input_len + 2u) / 3u);
    encoded = OPENSSL_malloc(capacity + 1u);
    if (!encoded) return -1;
    length = EVP_EncodeBlock(encoded, input, (int)input_len);
    if (length <= 0 || mhg_secret_buf_set(output, encoded, (size_t)length) != 0) {
        OPENSSL_clear_free(encoded, capacity + 1u);
        return -1;
    }
    OPENSSL_clear_free(encoded, capacity + 1u);
    return 0;
}

static int base64_decode(struct mhg_bytes_view input,
                         struct mhg_secret_buf *output)
{
    unsigned char *decoded;
    size_t padding = 0u;
    int length;

    if ((!input.data && input.len != 0u) || input.len == 0u ||
        input.len % 4u != 0u || input.len > (size_t)INT_MAX ||
        memchr(input.data, '\0', input.len) != NULL)
        return -1;
    if (input.data[input.len - 1u] == '=') ++padding;
    if (input.len > 1u && input.data[input.len - 2u] == '=') ++padding;
    decoded = OPENSSL_malloc(input.len);
    if (!decoded) return -1;
    length = EVP_DecodeBlock(decoded, input.data, (int)input.len);
    if (length < 0 || (size_t)length < padding ||
        mhg_secret_buf_set(output, decoded, (size_t)length - padding) != 0) {
        OPENSSL_clear_free(decoded, input.len);
        return -1;
    }
    OPENSSL_clear_free(decoded, input.len);
    return 0;
}

void mhg_cloud_nonce(const unsigned char random_prefix[8], uint32_t minute,
                     unsigned char nonce[12])
{
    if (!nonce) return;
    memset(nonce, 0, 12u);
    if (!random_prefix) return;
    memcpy(nonce, random_prefix, 8u);
    nonce[8] = (unsigned char)(minute >> 24);
    nonce[9] = (unsigned char)(minute >> 16);
    nonce[10] = (unsigned char)(minute >> 8);
    nonce[11] = (unsigned char)minute;
}

enum mhg_cloud_error mhg_cloud_signed_nonce(
    const unsigned char *ssecurity, size_t ssecurity_len,
    const unsigned char nonce[12], unsigned char output[32])
{
    EVP_MD_CTX *context;
    unsigned int length = 0u;
    enum mhg_cloud_error result = MHG_CLOUD_CRYPTO;

    if (output) mhg_secure_clear(output, 32u);
    if (!ssecurity || ssecurity_len == 0u || !nonce || !output)
        return MHG_CLOUD_INPUT;
    context = EVP_MD_CTX_new();
    if (!context) return MHG_CLOUD_INTERNAL;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, ssecurity, ssecurity_len) == 1 &&
        EVP_DigestUpdate(context, nonce, 12u) == 1 &&
        EVP_DigestFinal_ex(context, output, &length) == 1 && length == 32u)
        result = MHG_CLOUD_OK;
    EVP_MD_CTX_free(context);
    return result;
}

enum mhg_cloud_error mhg_cloud_signature(
    const char *canonical_path, const char *data_value,
    const char *rc4_hash_value, const unsigned char signed_nonce[32],
    struct mhg_secret_buf *signature_b64)
{
    struct mhg_secret_buf nonce_b64 = MHG_SECRET_BUF_INIT;
    unsigned char digest[SHA_DIGEST_LENGTH];
    char *input = NULL;
    size_t length;
    size_t offset;
    unsigned int digest_len = 0u;
    EVP_MD_CTX *context = NULL;
    enum mhg_cloud_error result = MHG_CLOUD_CRYPTO;

    if (signature_b64) mhg_secret_buf_clear(signature_b64);
    if (!canonical_path || canonical_path[0] != '/' ||
        !data_value || !signed_nonce || !signature_b64)
        return MHG_CLOUD_INPUT;
    if (base64_encode(signed_nonce, 32u, &nonce_b64) != 0)
        return MHG_CLOUD_INTERNAL;
    length = strlen("POST&&data=&") + strlen(canonical_path) +
             strlen(data_value) + nonce_b64.len;
    if (rc4_hash_value) length += strlen("&rc4_hash__=") + strlen(rc4_hash_value);
    input = OPENSSL_malloc(length + 1u);
    if (!input) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    offset = (size_t)snprintf(input, length + 1u, "POST&%s&data=%s",
                              canonical_path, data_value);
    if (offset > length) goto out;
    if (rc4_hash_value) {
        int wrote = snprintf(input + offset, length + 1u - offset,
                             "&rc4_hash__=%s", rc4_hash_value);
        if (wrote < 0 || (size_t)wrote >= length + 1u - offset) goto out;
        offset += (size_t)wrote;
    }
    if (offset + 1u + nonce_b64.len != length) goto out;
    input[offset++] = '&';
    memcpy(input + offset, nonce_b64.data, nonce_b64.len);
    input[length] = '\0';

    context = EVP_MD_CTX_new();
    if (!context) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    if (EVP_DigestInit_ex(context, EVP_sha1(), NULL) != 1 ||
        EVP_DigestUpdate(context, input, length) != 1 ||
        EVP_DigestFinal_ex(context, digest, &digest_len) != 1 ||
        digest_len != SHA_DIGEST_LENGTH ||
        base64_encode(digest, sizeof(digest), signature_b64) != 0)
        goto out;
    result = MHG_CLOUD_OK;

out:
    EVP_MD_CTX_free(context);
    mhg_secure_clear(digest, sizeof(digest));
    if (input) OPENSSL_clear_free(input, length + 1u);
    mhg_secret_buf_clear(&nonce_b64);
    return result;
}

void mhg_cloud_form_clear(struct mhg_cloud_form *form)
{
    if (!form) return;
    mhg_secret_buf_clear(&form->nonce_b64);
    mhg_secret_buf_clear(&form->data_b64);
    mhg_secret_buf_clear(&form->rc4_hash_b64);
    mhg_secret_buf_clear(&form->signature_b64);
    mhg_secure_clear(form, sizeof(*form));
}

static enum mhg_cloud_error encrypt_b64(
    const unsigned char key[32], const unsigned char *plaintext,
    size_t plaintext_len, struct mhg_secret_buf *output)
{
    unsigned char *encrypted;
    enum mhg_cloud_error result = MHG_CLOUD_CRYPTO;

    encrypted = OPENSSL_malloc(plaintext_len);
    if (!encrypted) return MHG_CLOUD_INTERNAL;
    if (mhg_rc4_drop1024(key, 32u, plaintext, plaintext_len, encrypted) == 0 &&
        base64_encode(encrypted, plaintext_len, output) == 0)
        result = MHG_CLOUD_OK;
    OPENSSL_clear_free(encrypted, plaintext_len);
    return result;
}

enum mhg_cloud_error mhg_cloud_build_form(
    const char *canonical_path, const char *data_json,
    const unsigned char *ssecurity, size_t ssecurity_len,
    const unsigned char nonce[12], struct mhg_cloud_form *form)
{
    struct mhg_secret_buf first_hash = MHG_SECRET_BUF_INIT;
    unsigned char signed_nonce[32];
    enum mhg_cloud_error result;

    if (form) mhg_cloud_form_clear(form);
    if (!canonical_path || !data_json || !ssecurity || ssecurity_len == 0u ||
        !nonce || !form)
        return MHG_CLOUD_INPUT;
    result = mhg_cloud_signed_nonce(ssecurity, ssecurity_len, nonce, signed_nonce);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_cloud_signature(canonical_path, data_json, NULL,
                                 signed_nonce, &first_hash);
    if (result != MHG_CLOUD_OK) goto out;
    result = encrypt_b64(signed_nonce, (const unsigned char *)data_json,
                         strlen(data_json), &form->data_b64);
    if (result != MHG_CLOUD_OK) goto out;
    result = encrypt_b64(signed_nonce, first_hash.data, first_hash.len,
                         &form->rc4_hash_b64);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_cloud_signature(canonical_path,
                                 (const char *)form->data_b64.data,
                                 (const char *)form->rc4_hash_b64.data,
                                 signed_nonce, &form->signature_b64);
    if (result != MHG_CLOUD_OK) goto out;
    if (base64_encode(nonce, 12u, &form->nonce_b64) != 0)
        result = MHG_CLOUD_INTERNAL;

out:
    mhg_secure_clear(signed_nonce, sizeof(signed_nonce));
    mhg_secret_buf_clear(&first_hash);
    if (result != MHG_CLOUD_OK) mhg_cloud_form_clear(form);
    return result;
}

static int is_unreserved(unsigned char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '_' ||
           value == '.' || value == '~';
}

static size_t encoded_length(const struct mhg_secret_buf *value)
{
    size_t length = 0u;
    size_t index;
    for (index = 0u; index < value->len; ++index)
        length += is_unreserved(value->data[index]) ? 1u : 3u;
    return length;
}

static char *encode_value(char *output, const struct mhg_secret_buf *value)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t index;
    for (index = 0u; index < value->len; ++index) {
        unsigned char byte = value->data[index];
        if (is_unreserved(byte)) {
            *output++ = (char)byte;
        } else {
            *output++ = '%';
            *output++ = hex[byte >> 4];
            *output++ = hex[byte & 0x0fu];
        }
    }
    return output;
}

enum mhg_cloud_error mhg_cloud_form_encode(
    const struct mhg_cloud_form *form, struct mhg_secret_buf *encoded)
{
    static const char names[] = "_nonce=&data=&rc4_hash__=&signature=";
    const struct mhg_secret_buf *values[4];
    const char *keys[4] = {"_nonce=", "data=", "rc4_hash__=", "signature="};
    size_t length = sizeof(names) - 1u;
    size_t index;
    char *output;
    char *cursor;

    if (encoded) mhg_secret_buf_clear(encoded);
    if (!form || !encoded) return MHG_CLOUD_INPUT;
    values[0] = &form->nonce_b64;
    values[1] = &form->data_b64;
    values[2] = &form->rc4_hash_b64;
    values[3] = &form->signature_b64;
    for (index = 0u; index < 4u; ++index) {
        if (!values[index]->data || values[index]->len == 0u)
            return MHG_CLOUD_INPUT;
        length += encoded_length(values[index]);
    }
    output = OPENSSL_malloc(length + 1u);
    if (!output) return MHG_CLOUD_INTERNAL;
    cursor = output;
    for (index = 0u; index < 4u; ++index) {
        size_t key_len = strlen(keys[index]);
        if (index != 0u) *cursor++ = '&';
        memcpy(cursor, keys[index], key_len);
        cursor += key_len;
        cursor = encode_value(cursor, values[index]);
    }
    *cursor = '\0';
    if ((size_t)(cursor - output) != length ||
        mhg_secret_buf_set(encoded, output, length) != 0) {
        OPENSSL_clear_free(output, length + 1u);
        return MHG_CLOUD_INTERNAL;
    }
    OPENSSL_clear_free(output, length + 1u);
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_cloud_classify_http(int status)
{
    if (status == 401) return MHG_CLOUD_AUTH_REJECTED;
    if (status < 200 || status >= 300) return MHG_CLOUD_HTTP;
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_cloud_classify_http_for_sid(
    enum mhg_xiaomi_sid expected, enum mhg_xiaomi_sid actual, int status)
{
    if (!mhg_xiaomi_sid_name(expected) || !mhg_xiaomi_sid_name(actual))
        return MHG_CLOUD_INPUT;
    if (expected != actual) return MHG_CLOUD_SID_MISMATCH;
    return mhg_cloud_classify_http(status);
}

void mhg_cloud_envelope_clear(struct mhg_cloud_envelope *envelope)
{
    if (!envelope) return;
    mhg_secret_buf_clear(&envelope->result_json);
    mhg_secure_clear(envelope, sizeof(*envelope));
}

enum mhg_cloud_error mhg_cloud_decrypt_envelope(
    struct mhg_bytes_view response_b64,
    const unsigned char signed_nonce[32],
    struct mhg_cloud_envelope *envelope)
{
    struct mhg_secret_buf ciphertext = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf plaintext = MHG_SECRET_BUF_INIT;
    cJSON *root = NULL;
    cJSON *code;
    cJSON *result_item;
    struct mhg_json_slice code_raw = {0};
    char *rendered_result_json = NULL;
    enum mhg_cloud_error result = MHG_CLOUD_DECRYPT;

    if (envelope) mhg_cloud_envelope_clear(envelope);
    if ((!response_b64.data && response_b64.len != 0u) ||
        !signed_nonce || !envelope)
        return MHG_CLOUD_INPUT;
    if (base64_decode(response_b64, &ciphertext) != 0 ||
        mhg_secret_buf_set(&plaintext, ciphertext.data, ciphertext.len) != 0 ||
        mhg_rc4_drop1024(signed_nonce, 32u, plaintext.data,
                         plaintext.len, plaintext.data) != 0)
        goto out;
    root = mhg_secret_json_parse_len(plaintext.data, plaintext.len);
    if (!root || !cJSON_IsObject(root)) {
        result = MHG_CLOUD_MALFORMED;
        goto out;
    }
    code = cJSON_GetObjectItemCaseSensitive(root, "code");
    if (mhg_json_object_member_slice((const char *)plaintext.data,
                                     plaintext.len, "code", &code_raw) != 0 ||
        mhg_json_decimal_int_parse(code, &code_raw,
                                   &envelope->provider_code) != MHG_CLOUD_OK) {
        result = MHG_CLOUD_MALFORMED;
        goto out;
    }
    if (envelope->provider_code != 0) {
        result = MHG_CLOUD_SERVICE;
        goto out;
    }
    result_item = cJSON_GetObjectItemCaseSensitive(root, "result");
    if (!result_item || cJSON_IsNull(result_item)) {
        result = MHG_CLOUD_MALFORMED;
        goto out;
    }
    rendered_result_json = cJSON_PrintUnformatted(result_item);
    if (!rendered_result_json ||
        mhg_secret_buf_set(&envelope->result_json, rendered_result_json,
                           strlen(rendered_result_json)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    result = MHG_CLOUD_OK;

out:
    if (rendered_result_json) {
        mhg_secure_clear(rendered_result_json,
                         strlen(rendered_result_json));
        cJSON_free(rendered_result_json);
    }
    mhg_secret_json_delete(root);
    mhg_secret_buf_clear(&plaintext);
    mhg_secret_buf_clear(&ciphertext);
    if (result == MHG_CLOUD_SERVICE) {
        /* A provider rejection keeps only the fixed nonsecret code so callers
         * can classify it; no result, message or other response field is
         * retained. */
        mhg_secret_buf_clear(&envelope->result_json);
    } else if (result != MHG_CLOUD_OK) {
        mhg_cloud_envelope_clear(envelope);
    }
    return result;
}
