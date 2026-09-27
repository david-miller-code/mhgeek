#ifndef MHGEEK_WIRE_SCALAR_H
#define MHGEEK_WIRE_SCALAR_H

#include <stddef.h>

#include <cjson/cJSON.h>

#include "cloud_wire_types.h"

struct mhg_json_slice {
    const char *data;
    size_t len;
};

/* These helpers operate on already strict-parsed JSON. They retain the raw
 * scalar token so exponent/fraction syntax cannot be lost through cJSON's
 * double representation. */
int mhg_json_object_member_slice(
    const char *object_json, size_t object_len, const char *member,
    struct mhg_json_slice *value);
int mhg_json_array_item_slice(
    const struct mhg_json_slice *array, size_t index,
    struct mhg_json_slice *value);

/* Parses one already strict-parsed raw JSON number as a base-10 C int.
 * Decimal points and exponent notation are rejected even when cJSON's double
 * value is mathematically integral. */
enum mhg_cloud_error mhg_json_decimal_int_parse(
    const cJSON *item, const struct mhg_json_slice *raw, int *output);

/* Passport userId follows passportUserID: decoded strings and raw numeric
 * tokens must contain only ASCII decimal digits; leading zeroes are removed,
 * with an all-zero value normalized to "0". */
enum mhg_cloud_error mhg_passport_user_id_parse(
    const cJSON *item, const struct mhg_json_slice *raw,
    struct mhg_secret_buf *output);

/* Catalog DID/cursor follows xiaomiValue: a decoded string need only be
 * non-empty and is preserved; an unquoted token must be ASCII decimal digits
 * and is copied exactly. */
enum mhg_cloud_error mhg_catalog_value_parse(
    const cJSON *item, const struct mhg_json_slice *raw,
    struct mhg_secret_buf *output);

#endif
