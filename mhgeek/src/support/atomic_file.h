#ifndef AINICE_COMMON_ATOMIC_FILE_H
#define AINICE_COMMON_ATOMIC_FILE_H

#include <cjson/cJSON.h>

#include <stddef.h>
#include <sys/types.h>

typedef int (*atomic_file_parent_fn)(void *userdata, const char *parent);
typedef int (*atomic_file_path_fn)(void *userdata,
                                   const char *source,
                                   const char *target);
typedef int (*atomic_file_unlink_fn)(void *userdata, const char *path);

struct atomic_file_ops {
    atomic_file_parent_fn prepare_parent;
    atomic_file_path_fn rename_path;
    atomic_file_unlink_fn unlink_path;
    atomic_file_parent_fn sync_parent;
};

/*
 * Replacement has one irreversible commit point: rename_path().  Callers must
 * distinguish a failure before that point from a directory-sync failure after
 * the new file is already visible.
 */
enum atomic_file_result {
    ATOMIC_FILE_FAILED = -1,
    ATOMIC_FILE_COMMITTED_DURABLE = 0,
    ATOMIC_FILE_COMMITTED_NOT_DURABLE = 1,
};

static inline int atomic_file_result_committed(int result)
{
    return result == ATOMIC_FILE_COMMITTED_DURABLE ||
           result == ATOMIC_FILE_COMMITTED_NOT_DURABLE;
}

enum atomic_file_result atomic_file_replace_bytes(const char *path,
                              const void *data,
                              size_t size,
                              mode_t mode,
                              size_t max_bytes,
                              const struct atomic_file_ops *ops,
                              void *userdata);

enum atomic_file_result atomic_file_replace_text(const char *path,
                             const char *data,
                             mode_t mode,
                             size_t max_bytes,
                             const struct atomic_file_ops *ops,
                             void *userdata);
enum atomic_file_result atomic_file_replace_json(const char *path,
                             const cJSON *root,
                             mode_t mode,
                             size_t max_bytes,
                             const struct atomic_file_ops *ops,
                             void *userdata);

#endif
