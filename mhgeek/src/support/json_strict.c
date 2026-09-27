#define _POSIX_C_SOURCE 200809L

#include "json_strict.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef SUBSYS_JSON_STRICT_TESTING
static int g_subsys_json_strict_fail_next_parse_allocation;

void subsys_json_strict_test_fail_next_parse_allocation(void)
{
    g_subsys_json_strict_fail_next_parse_allocation = 1;
}
#endif

static int subsys_json_key_compare(const void *left, const void *right)
{
    const char *const *left_key = left;
    const char *const *right_key = right;

    return strcmp(*left_key, *right_key);
}

static int subsys_json_deadline_check(uint64_t deadline_ms)
{
    struct timespec now;
    uint64_t now_ms;

    if (deadline_ms == 0u) return 0;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    now_ms = (uint64_t)now.tv_sec * 1000u +
             (uint64_t)now.tv_nsec / 1000000u;
    if (now_ms >= deadline_ms) {
        errno = ETIMEDOUT;
        return -1;
    }
    return 0;
}

int subsys_json_deadline_after_ms(unsigned int timeout_ms,
                                  uint64_t *deadline_ms)
{
    struct timespec now;
    uint64_t now_ms;

    if (!deadline_ms || timeout_ms == 0u) {
        errno = EINVAL;
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    now_ms = (uint64_t)now.tv_sec * 1000u +
             (uint64_t)now.tv_nsec / 1000000u;
    if ((uint64_t)timeout_ms > UINT64_MAX - now_ms) {
        errno = EOVERFLOW;
        return -1;
    }
    *deadline_ms = now_ms + (uint64_t)timeout_ms;
    return 0;
}

int subsys_json_value_has_unique_keys_deadline(const cJSON *value,
                                               uint64_t deadline_ms)
{
    if (!value) {
        errno = EINVAL;
        return 0;
    }
    if (subsys_json_deadline_check(deadline_ms) != 0) return 0;
    if (cJSON_IsObject(value)) {
        const cJSON *child;
        const char **keys;
        size_t count = 0u;
        size_t index = 0u;

        for (child = value->child; child; child = child->next) {
            if (!child->string) {
                errno = EINVAL;
                return 0;
            }
            if ((count & 63u) == 0u &&
                subsys_json_deadline_check(deadline_ms) != 0) {
                return 0;
            }
            count++;
        }
        if (count > SIZE_MAX / sizeof(*keys)) {
            errno = ENOMEM;
            return 0;
        }
        keys = count > 1u ? malloc(count * sizeof(*keys)) : NULL;
        if (count > 1u && !keys) {
            errno = ENOMEM;
            return 0;
        }
        for (child = value->child; child; child = child->next) {
            if (!subsys_json_value_has_unique_keys_deadline(child,
                                                             deadline_ms)) {
                free(keys);
                return 0;
            }
            if (keys) keys[index] = child->string;
            index++;
        }
        if (keys) {
            qsort(keys, count, sizeof(*keys), subsys_json_key_compare);
            if (subsys_json_deadline_check(deadline_ms) != 0) {
                free(keys);
                return 0;
            }
            for (index = 1u; index < count; ++index) {
                if (strcmp(keys[index - 1u], keys[index]) == 0) {
                    free(keys);
                    errno = EINVAL;
                    return 0;
                }
            }
            free(keys);
        }
    } else if (cJSON_IsArray(value)) {
        size_t index = 0u;

        for (const cJSON *item = value->child; item; item = item->next) {
            if ((index & 63u) == 0u &&
                subsys_json_deadline_check(deadline_ms) != 0) {
                return 0;
            }
            if (!subsys_json_value_has_unique_keys_deadline(item,
                                                             deadline_ms)) {
                return 0;
            }
            index++;
        }
    }
    return 1;
}

int subsys_json_value_has_unique_keys(const cJSON *value)
{
    return subsys_json_value_has_unique_keys_deadline(value, 0u);
}

cJSON *subsys_json_parse_strict_deadline(const char *text,
                                         uint64_t deadline_ms)
{
    cJSON *value;
    int saved;

    if (!text) {
        errno = EINVAL;
        return NULL;
    }
    if (subsys_json_deadline_check(deadline_ms) != 0) return NULL;
#ifdef SUBSYS_JSON_STRICT_TESTING
    if (g_subsys_json_strict_fail_next_parse_allocation) {
        g_subsys_json_strict_fail_next_parse_allocation = 0;
        errno = ENOMEM;
        return NULL;
    }
#endif
    errno = 0;
    value = cJSON_ParseWithOpts(text, NULL, 1);
    if (!value) {
        saved = errno;
        errno = saved == ENOMEM ? ENOMEM : EINVAL;
        return NULL;
    }
    if (subsys_json_deadline_check(deadline_ms) != 0) {
        cJSON_Delete(value);
        return NULL;
    }
    errno = 0;
    if (!subsys_json_value_has_unique_keys_deadline(value, deadline_ms)) {
        saved = errno;
        cJSON_Delete(value);
        errno = saved == ENOMEM || saved == ETIMEDOUT ? saved : EINVAL;
        return NULL;
    }
    return value;
}

cJSON *subsys_json_parse_strict(const char *text)
{
    return subsys_json_parse_strict_deadline(text, 0u);
}
