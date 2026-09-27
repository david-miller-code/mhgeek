#ifndef SUBSYS_SECURE_MEMORY_H
#define SUBSYS_SECURE_MEMORY_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static inline void subsys_secure_clear(void *data, size_t size)
{
    if (data && size > 0u) explicit_bzero(data, size);
}

static inline void subsys_secure_clear_free(void *data, size_t size)
{
    subsys_secure_clear(data, size);
    free(data);
}

static inline void subsys_secure_clear_string_free(char **value)
{
    if (!value || !*value) return;
    subsys_secure_clear_free(*value, strlen(*value));
    *value = NULL;
}

#endif
