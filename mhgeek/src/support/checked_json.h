#ifndef SUBSYS_CHECKED_JSON_H
#define SUBSYS_CHECKED_JSON_H

#include <cjson/cJSON.h>

#include <errno.h>
#include <stdbool.h>

/*
 * cJSON's convenience add helpers return NULL on allocation/admission failure.
 * These helpers give callers one ownership rule: an item remains owned by the
 * caller until a successful attach clears the owner pointer.
 */
static inline int subsys_json_attach_object(cJSON *object,
                                            const char *name,
                                            cJSON **item_owner)
{
    if (!cJSON_IsObject(object) || !name || !item_owner || !*item_owner) {
        errno = EINVAL;
        return -1;
    }
    if (!cJSON_AddItemToObject(object, name, *item_owner)) {
        errno = ENOMEM;
        return -1;
    }
    *item_owner = NULL;
    return 0;
}

static inline int subsys_json_attach_array(cJSON *array, cJSON **item_owner)
{
    if (!cJSON_IsArray(array) || !item_owner || !*item_owner) {
        errno = EINVAL;
        return -1;
    }
    if (!cJSON_AddItemToArray(array, *item_owner)) {
        errno = ENOMEM;
        return -1;
    }
    *item_owner = NULL;
    return 0;
}

static inline int subsys_json_replace_object(cJSON *object,
                                             const char *name,
                                             cJSON **item_owner)
{
    cJSON *existing;

    if (!cJSON_IsObject(object) || !name || !item_owner || !*item_owner) {
        errno = EINVAL;
        return -1;
    }
    existing = cJSON_GetObjectItemCaseSensitive(object, name);
    if (existing) {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(object, name, *item_owner)) {
            errno = ENOMEM;
            return -1;
        }
        *item_owner = NULL;
        return 0;
    }
    return subsys_json_attach_object(object, name, item_owner);
}

static inline int subsys_json_set_string(cJSON *object,
                                         const char *name,
                                         const char *value)
{
    cJSON *item = cJSON_CreateString(value ? value : "");

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_replace_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_set_number(cJSON *object,
                                         const char *name,
                                         double value)
{
    cJSON *item = cJSON_CreateNumber(value);

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_replace_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_set_bool(cJSON *object,
                                       const char *name,
                                       bool value)
{
    cJSON *item = cJSON_CreateBool(value);

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_replace_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_add_string(cJSON *object,
                                         const char *name,
                                         const char *value)
{
    cJSON *item = cJSON_CreateString(value ? value : "");

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_add_number(cJSON *object,
                                         const char *name,
                                         double value)
{
    cJSON *item = cJSON_CreateNumber(value);

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_add_bool(cJSON *object,
                                       const char *name,
                                       bool value)
{
    cJSON *item = cJSON_CreateBool(value);

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_add_null(cJSON *object, const char *name)
{
    cJSON *item = cJSON_CreateNull();

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_set_null(cJSON *object, const char *name)
{
    cJSON *item = cJSON_CreateNull();

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_replace_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_add_duplicate(cJSON *object,
                                             const char *name,
                                             const cJSON *source,
                                             bool recurse)
{
    cJSON *item;

    if (!source) {
        errno = EINVAL;
        return -1;
    }
    item = cJSON_Duplicate(source, recurse ? 1 : 0);
    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_set_duplicate(cJSON *object,
                                             const char *name,
                                             const cJSON *source,
                                             bool recurse)
{
    cJSON *item;

    if (!source) {
        errno = EINVAL;
        return -1;
    }
    item = cJSON_Duplicate(source, recurse ? 1 : 0);
    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_replace_object(object, name, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static inline int subsys_json_array_add_string(cJSON *array,
                                               const char *value)
{
    cJSON *item = cJSON_CreateString(value ? value : "");

    if (!item) {
        errno = ENOMEM;
        return -1;
    }
    if (subsys_json_attach_array(array, &item) != 0) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

#endif
