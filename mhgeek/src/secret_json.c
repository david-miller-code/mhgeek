#include "secret_json.h"

#include <openssl/crypto.h>

#include <string.h>

#include "cloud_wire_types.h"
#include "json_strict.h"

static int has_decoded_nul_escape(const unsigned char *text, size_t length)
{
    size_t index = 0u;
    int in_string = 0;

    while (index < length) {
        unsigned char byte = text[index++];
        if (!in_string) {
            if (byte == '"') in_string = 1;
            continue;
        }
        if (byte == '"') {
            in_string = 0;
            continue;
        }
        if (byte != '\\') continue;
        if (index >= length) return 0;
        byte = text[index++];
        if (byte == 'u' && index + 4u <= length &&
            text[index] == '0' && text[index + 1u] == '0' &&
            text[index + 2u] == '0' && text[index + 3u] == '0')
            return 1;
        if (byte == 'u') index += 4u;
    }
    return 0;
}

cJSON *mhg_secret_json_parse_len(const unsigned char *text, size_t length)
{
    char *terminated;
    cJSON *value;

    if (!text || length == 0u || length == SIZE_MAX || memchr(text, '\0', length) ||
        has_decoded_nul_escape(text, length))
        return NULL;
    terminated = OPENSSL_malloc(length + 1u);
    if (!terminated) return NULL;
    memcpy(terminated, text, length);
    terminated[length] = '\0';
    value = subsys_json_parse_strict(terminated);
    OPENSSL_clear_free(terminated, length + 1u);
    return value;
}

cJSON *mhg_secret_json_parse(const char *text)
{
    if (!text) return NULL;
    return mhg_secret_json_parse_len((const unsigned char *)text,
                                     strlen(text));
}

static void clear_tree(cJSON *value)
{
    cJSON *child;

    if (!value) return;
    if (value->string) mhg_secure_clear(value->string, strlen(value->string));
    if (value->valuestring)
        mhg_secure_clear(value->valuestring, strlen(value->valuestring));
    cJSON_ArrayForEach(child, value) clear_tree(child);
}

void mhg_secret_json_delete(cJSON *value)
{
    clear_tree(value);
    cJSON_Delete(value);
}
