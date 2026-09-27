#define _GNU_SOURCE

#include "target_store.h"

#include <cjson/cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_json.h"

#define MHG_TARGET_FILE_LIMIT 4096u
#define MHG_TARGET_NEXT_LEAF ".target.json.mhg-next"

#ifdef MHG_TARGET_STORE_TESTING
static int fail_commit_sync_once;
static int fail_clear_sync_once;

void mhg_target_store_test_fail_commit_sync_once(void)
{
    fail_commit_sync_once = 1;
}

void mhg_target_store_test_fail_clear_sync_once(void)
{
    fail_clear_sync_once = 1;
}
#endif

static int commit_directory_sync(int dir_fd)
{
#ifdef MHG_TARGET_STORE_TESTING
    if (fail_commit_sync_once) {
        fail_commit_sync_once = 0;
        errno = EIO;
        return -1;
    }
#endif
    return fsync(dir_fd);
}

static int clear_directory_sync(int dir_fd)
{
#ifdef MHG_TARGET_STORE_TESTING
    if (fail_clear_sync_once) {
        fail_clear_sync_once = 0;
        errno = EIO;
        return -1;
    }
#endif
    return fsync(dir_fd);
}

static int safe_path(const char *path)
{
    const unsigned char *cursor;
    size_t length;

    if (!path || path[0] != '/' || strcmp(path, "/") == 0) return -1;
    length = strlen(path);
    if (length >= PATH_MAX || strstr(path, "/../") ||
        (length >= 3u && strcmp(path + length - 3u, "/..") == 0))
        return -1;
    for (cursor = (const unsigned char *)path; *cursor; ++cursor) {
        if ((*cursor >= 'a' && *cursor <= 'z') ||
            (*cursor >= 'A' && *cursor <= 'Z') ||
            (*cursor >= '0' && *cursor <= '9') || *cursor == '/' ||
            *cursor == '.' || *cursor == '_' || *cursor == '-')
            continue;
        return -1;
    }
    return 0;
}

static int split_path(const char *path, char directory[PATH_MAX],
                      const char **leaf)
{
    char *slash;

    if (!directory || !leaf || safe_path(path) != 0) {
        errno = EINVAL;
        return -1;
    }
    snprintf(directory, PATH_MAX, "%s", path);
    slash = strrchr(directory, '/');
    if (!slash || slash == directory || slash[1] == '\0') {
        errno = EINVAL;
        return -1;
    }
    *leaf = path + (slash - directory) + 1;
    *slash = '\0';
    return 0;
}

static int ensure_private_directory(const char *path)
{
    struct stat metadata;

    if (safe_path(path) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &metadata) != 0) {
        if (errno != ENOENT || mkdir(path, 0700) != 0 ||
            lstat(path, &metadata) != 0)
            return -1;
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid()) {
        errno = EPERM;
        return -1;
    }
    if ((metadata.st_mode & 0777) != 0700 && chmod(path, 0700) != 0)
        return -1;
    return 0;
}

static int open_private_directory(const char *path)
{
    struct stat metadata;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) return -1;
    if (fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0777) != 0700) {
        int saved = errno ? errno : EPERM;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int mhg_target_field_is_valid(const char *text, size_t limit)
{
    const unsigned char *cursor;
    size_t index;
    size_t length;

    if (!text || limit == 0u) return 0;
    length = strlen(text);
    if (length == 0u || length > limit) return 0;
    for (index = 0u, cursor = (const unsigned char *)text; index < length;
         ++index, ++cursor) {
        if (*cursor <= 0x20u || *cursor == 0x7fu || *cursor >= 0x80u) return 0;
    }
    return 1;
}

static int field_valid(const struct mhg_secret_buf *value, size_t limit)
{
    return value->data && value->len != 0u &&
           value->len == strlen((const char *)value->data) &&
           mhg_target_field_is_valid((const char *)value->data, limit);
}

static int record_valid(const struct mhg_target_record *record)
{
    if (!record ||
        (record->version != MHG_TARGET_VERSION_V1 &&
         record->version != MHG_TARGET_VERSION_V2) ||
        record->catalog_generation == 0u ||
        !field_valid(&record->ip, MHG_TARGET_IP_LIMIT) ||
        !field_valid(&record->did, MHG_TARGET_DID_LIMIT) ||
        !field_valid(&record->model, MHG_TARGET_MODEL_LIMIT))
        return 0;
    if (record->action_state == MHG_TARGET_ACTION_SELECTED)
        return !record->action_urn.data && record->action_siid == 0 &&
               record->action_aiid == 0 && record->action_piid == 0;
    return record->version == MHG_TARGET_VERSION_V2 &&
           record->action_state == MHG_TARGET_ACTION_VERIFIED &&
           field_valid(&record->action_urn, MHG_TARGET_URN_LIMIT) &&
           record->action_siid > 0 && record->action_aiid > 0 &&
           record->action_piid > 0;
}

void mhg_target_record_clear(struct mhg_target_record *record)
{
    if (!record) return;
    mhg_secret_buf_clear(&record->ip);
    mhg_secret_buf_clear(&record->did);
    mhg_secret_buf_clear(&record->model);
    mhg_secret_buf_clear(&record->action_urn);
    mhg_secure_clear(record, sizeof(*record));
}

bool mhg_target_record_same_device(const struct mhg_target_record *left,
                                   const struct mhg_target_record *right)
{
    return left && right && left->did.data && right->did.data &&
           left->model.data && right->model.data &&
           left->did.len == right->did.len &&
           left->model.len == right->model.len &&
           memcmp(left->did.data, right->did.data, left->did.len) == 0 &&
           memcmp(left->model.data, right->model.data, left->model.len) == 0;
}

int mhg_target_record_action_for_urn(const struct mhg_target_record *record,
                                     const char *live_urn, int *siid,
                                     int *aiid, int *piid)
{
    if (!record || !live_urn || !siid || !aiid || !piid ||
        !record_valid(record) ||
        !mhg_target_field_is_valid(live_urn, MHG_TARGET_URN_LIMIT))
        return -1;
    if (record->action_state == MHG_TARGET_ACTION_SELECTED) return 1;
    if (strcmp((const char *)record->action_urn.data, live_urn) != 0)
        return -1;
    *siid = record->action_siid;
    *aiid = record->action_aiid;
    *piid = record->action_piid;
    return 0;
}

int mhg_target_record_clone(struct mhg_target_record *destination,
                            const struct mhg_target_record *source)
{
    struct mhg_target_record copy = MHG_TARGET_RECORD_INIT;

    if (!destination || !source || destination == source) return -1;
    copy.version = source->version;
    copy.catalog_generation = source->catalog_generation;
    copy.action_state = source->action_state;
    copy.action_siid = source->action_siid;
    copy.action_aiid = source->action_aiid;
    copy.action_piid = source->action_piid;
#define COPY_FIELD(name) \
    do { \
        if (source->name.data && \
            mhg_secret_buf_set(&copy.name, source->name.data, \
                               source->name.len) != 0) \
            goto fail; \
    } while (0)
    COPY_FIELD(ip);
    COPY_FIELD(did);
    COPY_FIELD(model);
    COPY_FIELD(action_urn);
#undef COPY_FIELD
    mhg_target_record_clear(destination);
    *destination = copy;
    return 0;

fail:
    mhg_target_record_clear(&copy);
    return -1;
}

static int object_exact(const cJSON *root, const char *const *keys,
                        size_t key_count)
{
    const cJSON *item;
    size_t count = 0u;

    if (!cJSON_IsObject(root)) return 0;
    cJSON_ArrayForEach(item, root) {
        size_t index;
        if (!item->string) return 0;
        for (index = 0u; index < key_count; ++index)
            if (strcmp(item->string, keys[index]) == 0) break;
        if (index == key_count) return 0;
        ++count;
    }
    if (count != key_count) return 0;
    for (size_t index = 0u; index < key_count; ++index) {
        size_t matches = 0u;

        cJSON_ArrayForEach(item, root)
            if (strcmp(item->string, keys[index]) == 0) matches += 1u;
        if (matches != 1u) return 0;
    }
    return 1;
}

static int parse_u64(const char *text, uint64_t *value)
{
    uint64_t parsed = 0u;
    size_t index;
    size_t length;

    if (!text || !value) return -1;
    length = strlen(text);
    if (length == 0u || (length > 1u && text[0] == '0')) return -1;
    for (index = 0u; index < length; ++index) {
        unsigned int digit;
        if (text[index] < '0' || text[index] > '9') return -1;
        digit = (unsigned int)(text[index] - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) return -1;
        parsed = parsed * 10u + digit;
    }
    if (parsed == 0u) return -1;
    *value = parsed;
    return 0;
}

static int read_record_at(int dir_fd, const char *leaf,
                          struct mhg_target_record *record)
{
    static const char *const v1_keys[] = {
        "version", "catalog_generation", "ip", "did", "model"
    };
    static const char *const v2_keys[] = {
        "version", "catalog_generation", "ip", "did", "model", "action"
    };
    static const char *const action_keys[] = {
        "urn", "siid", "aiid", "piid"
    };
    struct mhg_target_record parsed = MHG_TARGET_RECORD_INIT;
    struct stat metadata;
    unsigned char *data = NULL;
    cJSON *root = NULL;
    const cJSON *version;
    const cJSON *generation;
    const cJSON *ip;
    const cJSON *did;
    const cJSON *model;
    const cJSON *action;
    size_t used = 0u;
    int fd = -1;
    int result = MHG_TARGET_STORE_ERROR;

    mhg_target_record_clear(record);
    fd = openat(dir_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) return MHG_TARGET_STORE_ABSENT;
    if (fd < 0 || fstat(fd, &metadata) != 0) goto done;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0777) != 0600) {
        errno = EPERM;
        goto done;
    }
    if (metadata.st_size <= 0 ||
        metadata.st_size > (off_t)MHG_TARGET_FILE_LIMIT) {
        errno = EFBIG;
        goto done;
    }
    data = malloc((size_t)metadata.st_size);
    if (!data) goto done;
    while (used < (size_t)metadata.st_size) {
        ssize_t got = read(fd, data + used, (size_t)metadata.st_size - used);
        if (got > 0) used += (size_t)got;
        else if (got < 0 && errno == EINTR) continue;
        else {
            if (got == 0) errno = EIO;
            goto done;
        }
    }
    {
        unsigned char extra;
        ssize_t got;
        do {
            got = read(fd, &extra, 1u);
        } while (got < 0 && errno == EINTR);
        if (got != 0) {
            if (got > 0) errno = EFBIG;
            goto done;
        }
    }
    root = mhg_secret_json_parse_len(data, used);
    if (!root) {
        errno = EPROTO;
        goto done;
    }
    version = cJSON_GetObjectItemCaseSensitive(root, "version");
    generation = cJSON_GetObjectItemCaseSensitive(root, "catalog_generation");
    ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
    did = cJSON_GetObjectItemCaseSensitive(root, "did");
    model = cJSON_GetObjectItemCaseSensitive(root, "model");
    if (!cJSON_IsNumber(version) ||
        (version->valuedouble != (double)MHG_TARGET_VERSION_V1 &&
         version->valuedouble != (double)MHG_TARGET_VERSION_V2) ||
        !object_exact(root,
                      version->valuedouble == (double)MHG_TARGET_VERSION_V1 ?
                          v1_keys : v2_keys,
                      version->valuedouble == (double)MHG_TARGET_VERSION_V1 ?
                          sizeof(v1_keys) / sizeof(v1_keys[0]) :
                          sizeof(v2_keys) / sizeof(v2_keys[0])) ||
        !cJSON_IsString(generation) ||
        parse_u64(generation->valuestring, &parsed.catalog_generation) != 0 ||
        !cJSON_IsString(ip) || !cJSON_IsString(did) || !cJSON_IsString(model) ||
        mhg_secret_buf_set(&parsed.ip, ip->valuestring,
                           strlen(ip->valuestring)) != 0 ||
        mhg_secret_buf_set(&parsed.did, did->valuestring,
                           strlen(did->valuestring)) != 0 ||
        mhg_secret_buf_set(&parsed.model, model->valuestring,
                           strlen(model->valuestring)) != 0 ||
        !field_valid(&parsed.ip, MHG_TARGET_IP_LIMIT) ||
        !field_valid(&parsed.did, MHG_TARGET_DID_LIMIT) ||
        !field_valid(&parsed.model, MHG_TARGET_MODEL_LIMIT)) {
        errno = EPROTO;
        goto done;
    }
    parsed.version = (uint64_t)version->valuedouble;
    if (parsed.version == MHG_TARGET_VERSION_V2) {
        action = cJSON_GetObjectItemCaseSensitive(root, "action");
        if (!cJSON_IsNull(action)) {
            const cJSON *urn = cJSON_GetObjectItemCaseSensitive(action, "urn");
            const cJSON *siid = cJSON_GetObjectItemCaseSensitive(action, "siid");
            const cJSON *aiid = cJSON_GetObjectItemCaseSensitive(action, "aiid");
            const cJSON *piid = cJSON_GetObjectItemCaseSensitive(action, "piid");

            if (!object_exact(action, action_keys,
                              sizeof(action_keys) / sizeof(action_keys[0])) ||
                !cJSON_IsString(urn) || !cJSON_IsNumber(siid) ||
                !cJSON_IsNumber(aiid) || !cJSON_IsNumber(piid) ||
                siid->valuedouble < 1.0 || siid->valuedouble > INT_MAX ||
                aiid->valuedouble < 1.0 || aiid->valuedouble > INT_MAX ||
                piid->valuedouble < 1.0 || piid->valuedouble > INT_MAX ||
                siid->valuedouble != (double)(int)siid->valuedouble ||
                aiid->valuedouble != (double)(int)aiid->valuedouble ||
                piid->valuedouble != (double)(int)piid->valuedouble ||
                mhg_secret_buf_set(&parsed.action_urn, urn->valuestring,
                                   strlen(urn->valuestring)) != 0) {
                errno = EPROTO;
                goto done;
            }
            parsed.action_state = MHG_TARGET_ACTION_VERIFIED;
            parsed.action_siid = (int)siid->valuedouble;
            parsed.action_aiid = (int)aiid->valuedouble;
            parsed.action_piid = (int)piid->valuedouble;
        }
    }
    if (!record_valid(&parsed)) {
        errno = EPROTO;
        goto done;
    }
    *record = parsed;
    parsed = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    result = MHG_TARGET_STORE_PRESENT;

done:
    {
        int saved = errno;
        if (fd >= 0) close(fd);
        mhg_secret_json_delete(root);
        free(data);
        mhg_target_record_clear(&parsed);
        errno = saved;
    }
    return result;
}

int mhg_target_store_prepare(const char *data_root, char *target_path,
                             size_t target_path_size)
{
    int written;

    if (!target_path || target_path_size == 0u || !data_root ||
        ensure_private_directory(data_root) != 0)
        return -1;
    written = snprintf(target_path, target_path_size, "%s/target.json",
                       data_root);
    if (written < 0 || (size_t)written >= target_path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int mhg_target_store_load(const char *target_path,
                          struct mhg_target_record *record)
{
    char directory[PATH_MAX];
    const char *leaf;
    int dir_fd;
    int result;

    if (!record) {
        errno = EINVAL;
        return MHG_TARGET_STORE_ERROR;
    }
    mhg_target_record_clear(record);
    if (split_path(target_path, directory, &leaf) != 0)
        return MHG_TARGET_STORE_ERROR;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0) return MHG_TARGET_STORE_ERROR;
    result = read_record_at(dir_fd, leaf, record);
    if (result == MHG_TARGET_STORE_PRESENT ||
        result == MHG_TARGET_STORE_ABSENT) {
        if (unlinkat(dir_fd, MHG_TARGET_NEXT_LEAF, 0) == 0)
            (void)fsync(dir_fd);
        else if (errno != ENOENT)
            errno = 0;
    }
    close(dir_fd);
    return result;
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
    size_t written = 0u;

    while (written < size) {
        ssize_t put = write(fd, data + written, size - written);
        if (put > 0) written += (size_t)put;
        else if (put < 0 && errno == EINTR) continue;
        else {
            if (put == 0) errno = EIO;
            return -1;
        }
    }
    return 0;
}

static int record_equal(const struct mhg_target_record *left,
                        const struct mhg_target_record *right)
{
    if (left->version != right->version ||
        left->catalog_generation != right->catalog_generation ||
        left->action_state != right->action_state ||
        left->action_siid != right->action_siid ||
        left->action_aiid != right->action_aiid ||
        left->action_piid != right->action_piid ||
        left->action_urn.len != right->action_urn.len ||
        (left->action_urn.len != 0u &&
         memcmp(left->action_urn.data, right->action_urn.data,
                left->action_urn.len) != 0))
        return 0;
    return
           left->ip.len == right->ip.len &&
           memcmp(left->ip.data, right->ip.data, left->ip.len) == 0 &&
           left->did.len == right->did.len &&
           memcmp(left->did.data, right->did.data, left->did.len) == 0 &&
           left->model.len == right->model.len &&
           memcmp(left->model.data, right->model.data, left->model.len) == 0;
}

static char *render_record(const struct mhg_target_record *record)
{
    char generation[32];
    cJSON *root = NULL;
    cJSON *action = NULL;
    char *json = NULL;

    snprintf(generation, sizeof(generation), "%llu",
             (unsigned long long)record->catalog_generation);
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddNumberToObject(root, "version", 2.0) ||
        !cJSON_AddStringToObject(root, "catalog_generation", generation) ||
        !cJSON_AddStringToObject(root, "ip", (const char *)record->ip.data) ||
        !cJSON_AddStringToObject(root, "did",
                                 (const char *)record->did.data) ||
        !cJSON_AddStringToObject(root, "model",
                                 (const char *)record->model.data)) {
        mhg_secret_json_delete(root);
        errno = ENOMEM;
        return NULL;
    }
    if (record->action_state == MHG_TARGET_ACTION_VERIFIED) {
        action = cJSON_CreateObject();
        if (!action ||
            !cJSON_AddStringToObject(action, "urn",
                                     (const char *)record->action_urn.data) ||
            !cJSON_AddNumberToObject(action, "siid",
                                     (double)record->action_siid) ||
            !cJSON_AddNumberToObject(action, "aiid",
                                     (double)record->action_aiid) ||
            !cJSON_AddNumberToObject(action, "piid",
                                     (double)record->action_piid) ||
            !cJSON_AddItemToObject(root, "action", action)) {
            cJSON_Delete(action);
            mhg_secret_json_delete(root);
            errno = ENOMEM;
            return NULL;
        }
        action = NULL;
    } else if (!cJSON_AddNullToObject(root, "action")) {
        mhg_secret_json_delete(root);
        errno = ENOMEM;
        return NULL;
    }
    json = cJSON_PrintUnformatted(root);
    mhg_secret_json_delete(root);
    if (!json) errno = ENOMEM;
    return json;
}

int mhg_target_store_commit(const char *target_path,
                            const struct mhg_target_record *record)
{
    char directory[PATH_MAX];
    const char *leaf;
    struct mhg_target_record readback = MHG_TARGET_RECORD_INIT;
    char *json = NULL;
    int dir_fd = -1;
    int file_fd = -1;
    bool renamed = false;
    int result = MHG_TARGET_STORE_FAILED;

    if (!record_valid(record) ||
        record->version != MHG_TARGET_VERSION_V2 ||
        split_path(target_path, directory, &leaf) != 0) {
        errno = EINVAL;
        return MHG_TARGET_STORE_FAILED;
    }
    json = render_record(record);
    if (!json) return MHG_TARGET_STORE_FAILED;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0) goto done;
    if (unlinkat(dir_fd, MHG_TARGET_NEXT_LEAF, 0) != 0 && errno != ENOENT)
        goto done;
    file_fd = openat(dir_fd, MHG_TARGET_NEXT_LEAF,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (file_fd < 0) goto done;
    if (write_all(file_fd, (const unsigned char *)json, strlen(json)) != 0 ||
        fchmod(file_fd, 0600) != 0 || fsync(file_fd) != 0)
        goto done;
    if (close(file_fd) != 0) {
        file_fd = -1;
        goto done;
    }
    file_fd = -1;
    if (renameat(dir_fd, MHG_TARGET_NEXT_LEAF, dir_fd, leaf) != 0) goto done;
    renamed = true;
    {
        int synced = commit_directory_sync(dir_fd) == 0;

        if (read_record_at(dir_fd, leaf, &readback) !=
                MHG_TARGET_STORE_PRESENT ||
            !record_equal(record, &readback)) {
            /* The file may have replaced the old authority. Never unlink it
             * after rename just because verification failed: the resolver
             * freezes and reloads the actual on-disk record. */
            if (!errno) errno = EIO;
            goto done;
        }
        result = synced ? MHG_TARGET_STORE_COMMITTED_DURABLE :
                          MHG_TARGET_STORE_COMMITTED_NOT_DURABLE;
    }

done:
    {
        int saved = errno;
        if (file_fd >= 0) close(file_fd);
        if (dir_fd >= 0 && !renamed)
            (void)unlinkat(dir_fd, MHG_TARGET_NEXT_LEAF, 0);
        if (dir_fd >= 0) close(dir_fd);
        mhg_target_record_clear(&readback);
        if (json) {
            mhg_secure_clear(json, strlen(json));
            cJSON_free(json);
        }
        errno = saved;
    }
    return result;
}

int mhg_target_store_clear(const char *target_path)
{
    char directory[PATH_MAX];
    const char *leaf;
    int dir_fd;
    int result = MHG_TARGET_STORE_FAILED;
    int failure = 0;

    if (split_path(target_path, directory, &leaf) != 0)
        return MHG_TARGET_STORE_FAILED;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0) return MHG_TARGET_STORE_FAILED;
    if (unlinkat(dir_fd, leaf, 0) != 0 && errno != ENOENT) failure = 1;
    if (!failure && unlinkat(dir_fd, MHG_TARGET_NEXT_LEAF, 0) != 0 &&
        errno != ENOENT)
        failure = 1;
    if (!failure) {
        result = clear_directory_sync(dir_fd) == 0 ?
                                      MHG_TARGET_STORE_COMMITTED_DURABLE :
                                      MHG_TARGET_STORE_COMMITTED_NOT_DURABLE;
    }
    {
        int saved = errno;
        close(dir_fd);
        errno = saved;
    }
    return result;
}
