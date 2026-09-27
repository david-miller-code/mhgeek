#define _GNU_SOURCE

#include "atomic_file.h"
#include "secure_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int atomic_file_parent(const char *path, char *out, size_t out_size)
{
    char *slash;
    int written;

    written = snprintf(out, out_size, "%s", path);
    if (written < 0 || (size_t)written >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    slash = strrchr(out, '/');
    if (!slash) {
        snprintf(out, out_size, ".");
    } else if (slash == out) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    return 0;
}

static void atomic_file_cleanup(const struct atomic_file_ops *ops,
                                void *userdata,
                                const char *path)
{
    if (ops->unlink_path) (void)ops->unlink_path(userdata, path);
    else (void)unlink(path);
}

enum atomic_file_result atomic_file_replace_bytes(const char *path,
                              const void *data,
                              size_t size,
                              mode_t mode,
                              size_t max_bytes,
                              const struct atomic_file_ops *ops,
                              void *userdata)
{
    char parent[PATH_MAX];
    char temporary[PATH_MAX];
    const unsigned char *bytes = (const unsigned char *)data;
    size_t written_total = 0u;
    int fd;
    int written;

    if (!path || path[0] == '\0' || (!data && size > 0u) || !ops ||
        !ops->rename_path ||
        !ops->sync_parent) {
        errno = EINVAL;
        return ATOMIC_FILE_FAILED;
    }
    if (size > max_bytes) {
        errno = EMSGSIZE;
        return ATOMIC_FILE_FAILED;
    }
    if (atomic_file_parent(path, parent, sizeof(parent)) != 0)
        return ATOMIC_FILE_FAILED;
    if (ops->prepare_parent && ops->prepare_parent(userdata, parent) != 0)
        return ATOMIC_FILE_FAILED;
    written = snprintf(temporary,
                       sizeof(temporary),
                       "%s.tmp.XXXXXX",
                       path);
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        errno = ENAMETOOLONG;
        return ATOMIC_FILE_FAILED;
    }
    fd = mkostemp(temporary, O_CLOEXEC);
    if (fd < 0) return ATOMIC_FILE_FAILED;
    while (written_total < size) {
        ssize_t count = write(fd,
                              bytes + written_total,
                              size - written_total);

        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = EIO;
            break;
        }
        written_total += (size_t)count;
    }
    if (written_total == size && fchmod(fd, mode) == 0) {
        int sync_result;

        do {
            sync_result = fsync(fd);
        } while (sync_result != 0 && errno == EINTR);
        if (sync_result != 0) written_total = SIZE_MAX;
    } else {
        written_total = SIZE_MAX;
    }
    if (written_total != size) {
        int saved = errno ? errno : EIO;

        (void)close(fd);
        atomic_file_cleanup(ops, userdata, temporary);
        errno = saved;
        return ATOMIC_FILE_FAILED;
    }
    if (close(fd) != 0) {
        int saved = errno;

        atomic_file_cleanup(ops, userdata, temporary);
        errno = saved;
        return ATOMIC_FILE_FAILED;
    }
    if (ops->rename_path(userdata, temporary, path) != 0) {
        int saved = errno;

        atomic_file_cleanup(ops, userdata, temporary);
        errno = saved;
        return ATOMIC_FILE_FAILED;
    }
    if (ops->sync_parent(userdata, parent) != 0)
        return ATOMIC_FILE_COMMITTED_NOT_DURABLE;
    return ATOMIC_FILE_COMMITTED_DURABLE;
}

enum atomic_file_result atomic_file_replace_text(const char *path,
                             const char *data,
                             mode_t mode,
                             size_t max_bytes,
                             const struct atomic_file_ops *ops,
                             void *userdata)
{
    if (!data) {
        errno = EINVAL;
        return ATOMIC_FILE_FAILED;
    }
    return atomic_file_replace_bytes(path,
                                     data,
                                     strlen(data),
                                     mode,
                                     max_bytes,
                                     ops,
                                     userdata);
}

enum atomic_file_result atomic_file_replace_json(const char *path,
                             const cJSON *root,
                             mode_t mode,
                             size_t max_bytes,
                             const struct atomic_file_ops *ops,
                             void *userdata)
{
    char *text;
    enum atomic_file_result result;
    int saved;

    if (!root) {
        errno = EINVAL;
        return ATOMIC_FILE_FAILED;
    }
    text = cJSON_Print(root);
    if (!text) {
        errno = ENOMEM;
        return ATOMIC_FILE_FAILED;
    }
    result = atomic_file_replace_text(path,
                                      text,
                                      mode,
                                      max_bytes,
                                      ops,
                                      userdata);
    saved = result == ATOMIC_FILE_COMMITTED_DURABLE ? 0 : errno;
    subsys_secure_clear(text, strlen(text));
    cJSON_free(text);
    if (saved) errno = saved;
    return result;
}
