#include "wire_scalar.h"

#include <limits.h>
#include <string.h>

static const char *skip_ws(const char *cursor, const char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\t' ||
           *cursor == '\r' || *cursor == '\n'))
        ++cursor;
    return cursor;
}

static const char *skip_string(const char *cursor, const char *end)
{
    if (cursor >= end || *cursor != '"') return NULL;
    ++cursor;
    while (cursor < end) {
        if (*cursor == '"') return cursor + 1;
        if (*cursor == '\\') {
            ++cursor;
            if (cursor >= end) return NULL;
        }
        ++cursor;
    }
    return NULL;
}

static const char *skip_value(const char *cursor, const char *end)
{
    char close;

    cursor = skip_ws(cursor, end);
    if (cursor >= end) return NULL;
    if (*cursor == '"') return skip_string(cursor, end);
    if (*cursor != '{' && *cursor != '[') {
        while (cursor < end && *cursor != ',' && *cursor != '}' &&
               *cursor != ']' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\r' && *cursor != '\n')
            ++cursor;
        return cursor;
    }
    close = *cursor == '{' ? '}' : ']';
    ++cursor;
    while (cursor < end) {
        cursor = skip_ws(cursor, end);
        if (cursor >= end) return NULL;
        if (*cursor == close) return cursor + 1;
        if (*cursor == '"') {
            cursor = skip_string(cursor, end);
        } else if (*cursor == '{' || *cursor == '[') {
            cursor = skip_value(cursor, end);
        } else {
            ++cursor;
        }
        if (!cursor) return NULL;
    }
    return NULL;
}

int mhg_json_object_member_slice(
    const char *object_json, size_t object_len, const char *member,
    struct mhg_json_slice *value)
{
    const char *cursor;
    const char *end;
    size_t member_len;

    if (!object_json || !member || !value) return -1;
    value->data = NULL;
    value->len = 0u;
    end = object_json + object_len;
    cursor = skip_ws(object_json, end);
    if (cursor >= end || *cursor++ != '{') return -1;
    member_len = strlen(member);
    for (;;) {
        const char *key_start;
        const char *key_end;
        const char *value_start;
        const char *value_end;
        int matches;

        cursor = skip_ws(cursor, end);
        if (cursor >= end || *cursor == '}') return -1;
        key_start = cursor;
        key_end = skip_string(key_start, end);
        if (!key_end) return -1;
        matches = (size_t)(key_end - key_start) == member_len + 2u &&
                  memcmp(key_start + 1, member, member_len) == 0;
        cursor = skip_ws(key_end, end);
        if (cursor >= end || *cursor++ != ':') return -1;
        value_start = skip_ws(cursor, end);
        value_end = skip_value(value_start, end);
        if (!value_end) return -1;
        if (matches) {
            value->data = value_start;
            value->len = (size_t)(value_end - value_start);
            return 0;
        }
        cursor = skip_ws(value_end, end);
        if (cursor >= end || *cursor != ',') return -1;
        ++cursor;
    }
}

int mhg_json_array_item_slice(
    const struct mhg_json_slice *array, size_t index,
    struct mhg_json_slice *value)
{
    const char *cursor;
    const char *end;
    size_t current = 0u;

    if (!array || !array->data || !value) return -1;
    value->data = NULL;
    value->len = 0u;
    end = array->data + array->len;
    cursor = skip_ws(array->data, end);
    if (cursor >= end || *cursor++ != '[') return -1;
    for (;;) {
        const char *start;
        const char *finish;

        start = skip_ws(cursor, end);
        if (start >= end || *start == ']') return -1;
        finish = skip_value(start, end);
        if (!finish) return -1;
        if (current == index) {
            value->data = start;
            value->len = (size_t)(finish - start);
            return 0;
        }
        ++current;
        cursor = skip_ws(finish, end);
        if (cursor >= end || *cursor != ',') return -1;
        ++cursor;
    }
}

static int all_digits(const char *text, size_t length)
{
    size_t index;
    if (!text || length == 0u) return 0;
    for (index = 0u; index < length; ++index)
        if (text[index] < '0' || text[index] > '9') return 0;
    return 1;
}

enum mhg_cloud_error mhg_json_decimal_int_parse(
    const cJSON *item, const struct mhg_json_slice *raw, int *output)
{
    const char *cursor;
    size_t remaining;
    unsigned int limit;
    unsigned int value = 0u;
    int negative = 0;

    if (output) *output = 0;
    if (!output || !cJSON_IsNumber(item) || !raw || !raw->data ||
        raw->len == 0u)
        return MHG_CLOUD_MALFORMED;
    cursor = raw->data;
    remaining = raw->len;
    if (*cursor == '-') {
        negative = 1;
        ++cursor;
        --remaining;
    }
    if (!all_digits(cursor, remaining)) return MHG_CLOUD_MALFORMED;
    limit = negative ? (unsigned int)INT_MAX + 1u : (unsigned int)INT_MAX;
    while (remaining-- > 0u) {
        unsigned int digit = (unsigned int)(*cursor++ - '0');
        if (value > (limit - digit) / 10u) return MHG_CLOUD_MALFORMED;
        value = value * 10u + digit;
    }
    if (negative) {
        *output = value == (unsigned int)INT_MAX + 1u ? INT_MIN : -(int)value;
    } else {
        *output = (int)value;
    }
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_passport_user_id_parse(
    const cJSON *item, const struct mhg_json_slice *raw,
    struct mhg_secret_buf *output)
{
    const char *digits;
    size_t length;

    if (!output) return MHG_CLOUD_INPUT;
    mhg_secret_buf_clear(output);
    if (!item || !raw || !raw->data || raw->len == 0u)
        return MHG_CLOUD_MALFORMED;
    if (cJSON_IsString(item) && raw->data[0] == '"') {
        digits = item->valuestring;
        length = digits ? strlen(digits) : 0u;
    } else if (cJSON_IsNumber(item) && raw->data[0] != '"') {
        digits = raw->data;
        length = raw->len;
    } else {
        return MHG_CLOUD_MALFORMED;
    }
    if (!all_digits(digits, length)) return MHG_CLOUD_MALFORMED;
    while (length > 1u && *digits == '0') {
        ++digits;
        --length;
    }
    return mhg_secret_buf_set(output, digits, length) == 0 ?
           MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
}

enum mhg_cloud_error mhg_catalog_value_parse(
    const cJSON *item, const struct mhg_json_slice *raw,
    struct mhg_secret_buf *output)
{
    const char *text;
    size_t length;

    if (!output) return MHG_CLOUD_INPUT;
    mhg_secret_buf_clear(output);
    if (!item || !raw || !raw->data || raw->len == 0u)
        return MHG_CLOUD_MALFORMED;
    if (cJSON_IsString(item) && raw->data[0] == '"') {
        text = item->valuestring;
        length = text ? strlen(text) : 0u;
        if (length == 0u) return MHG_CLOUD_MALFORMED;
    } else if (cJSON_IsNumber(item) && raw->data[0] != '"' &&
               all_digits(raw->data, raw->len)) {
        text = raw->data;
        length = raw->len;
    } else {
        return MHG_CLOUD_MALFORMED;
    }
    return mhg_secret_buf_set(output, text, length) == 0 ?
           MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
}
