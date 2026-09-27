#define _GNU_SOURCE

#include "account_store.h"

#include <cjson/cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_json.h"
#include "passport_device_id.h"

#define MHG_ACCOUNT_FILE_LIMIT 65536u
#define MHG_ACCOUNT_NEXT_LEAF ".account.json.mhg-next"
#define MHG_ACCOUNT_TXN_LEAF ".account.json.mhg-txn"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1u << 1)
#endif

#ifdef MHG_ACCOUNT_STORE_TESTING
static enum mhg_account_store_test_point mhg_test_failures[2];

void mhg_account_store_test_fail_once(
    enum mhg_account_store_test_point point)
{
    mhg_test_failures[0] = point;
    mhg_test_failures[1] = MHG_ACCOUNT_STORE_TEST_NONE;
}

void mhg_account_store_test_fail_then(
    enum mhg_account_store_test_point first,
    enum mhg_account_store_test_point second)
{
    mhg_test_failures[0] = first;
    mhg_test_failures[1] = second;
}

static int test_checkpoint(enum mhg_account_store_test_point point)
{
    if (mhg_test_failures[0] != point) return 0;
    mhg_test_failures[0] = mhg_test_failures[1];
    mhg_test_failures[1] = MHG_ACCOUNT_STORE_TEST_NONE;
    errno = EIO;
    return -1;
}
#else
#define test_checkpoint(point) (0)
#endif

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

static int decimal_text(const unsigned char *value, size_t length)
{
    size_t index;

    if (!value || length == 0u) return 0;
    for (index = 0u; index < length; ++index)
        if (value[index] < '0' || value[index] > '9') return 0;
    return 1;
}

static int record_valid(const struct mhg_account_record *record)
{
    return record && record->generation != 0u &&
           mhg_passport_device_id_is_valid(record->device_id.data,
                                           record->device_id.len) &&
           decimal_text(record->user_id.data, record->user_id.len) &&
           record->pass_token.data && record->pass_token.len != 0u &&
           !memchr(record->pass_token.data, '\0', record->pass_token.len);
}

void mhg_account_record_clear(struct mhg_account_record *record)
{
    if (!record) return;
    mhg_secret_buf_clear(&record->device_id);
    mhg_secret_buf_clear(&record->user_id);
    mhg_secret_buf_clear(&record->pass_token);
    mhg_secure_clear(record, sizeof(*record));
}

static int object_exact(const cJSON *root, bool authorized)
{
    static const char *const keys[] = {
        "version", "login_method", "account_generation", "authorized",
        "deviceId", "userId", "passToken",
    };
    const cJSON *item;
    size_t count = 0u;

    if (!cJSON_IsObject(root)) return 0;
    cJSON_ArrayForEach(item, root) {
        size_t index;
        if (!item->string) return 0;
        for (index = 0u; index < sizeof(keys) / sizeof(keys[0]); ++index)
            if (strcmp(item->string, keys[index]) == 0) break;
        if (index == sizeof(keys) / sizeof(keys[0]) ||
            (!authorized && index >= 4u))
            return 0;
        ++count;
    }
    return count == (authorized ? sizeof(keys) / sizeof(keys[0]) : 4u);
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
                          struct mhg_account_record *record)
{
    struct mhg_account_record parsed = MHG_ACCOUNT_RECORD_INIT;
    struct stat metadata;
    unsigned char *data = NULL;
    cJSON *root = NULL;
    const cJSON *version;
    const cJSON *method;
    const cJSON *generation;
    const cJSON *authorized;
    const cJSON *device_id;
    const cJSON *user_id;
    const cJSON *pass_token;
    size_t used = 0u;
    int fd = -1;
    int result = MHG_ACCOUNT_STORE_ERROR;

    mhg_account_record_clear(record);
    fd = openat(dir_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) return MHG_ACCOUNT_STORE_ABSENT;
    if (fd < 0 || fstat(fd, &metadata) != 0) goto done;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0777) != 0600) {
        errno = EPERM;
        goto done;
    }
    if (metadata.st_size <= 0 ||
        metadata.st_size > (off_t)MHG_ACCOUNT_FILE_LIMIT) {
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
    authorized = root ? cJSON_GetObjectItemCaseSensitive(root,
                                                          "authorized") : NULL;
    if (!root || (!cJSON_IsTrue(authorized) &&
                  !cJSON_IsFalse(authorized)) ||
        !object_exact(root, cJSON_IsTrue(authorized))) {
        errno = EPROTO;
        goto done;
    }
    version = cJSON_GetObjectItemCaseSensitive(root, "version");
    method = cJSON_GetObjectItemCaseSensitive(root, "login_method");
    generation = cJSON_GetObjectItemCaseSensitive(root, "account_generation");
    device_id = cJSON_GetObjectItemCaseSensitive(root, "deviceId");
    user_id = cJSON_GetObjectItemCaseSensitive(root, "userId");
    pass_token = cJSON_GetObjectItemCaseSensitive(root, "passToken");
    if (!cJSON_IsNumber(version) || version->valuedouble != 2.0 ||
        !cJSON_IsString(method) || strcmp(method->valuestring, "phone") != 0 ||
        !cJSON_IsString(generation) ||
        parse_u64(generation->valuestring, &parsed.generation) != 0) {
        errno = EPROTO;
        goto done;
    }
    if (cJSON_IsFalse(authorized)) {
        *record = parsed;
        parsed = (struct mhg_account_record)MHG_ACCOUNT_RECORD_INIT;
        result = MHG_ACCOUNT_STORE_ABSENT;
        goto done;
    }
    if (!cJSON_IsString(device_id) ||
        !mhg_passport_device_id_is_valid(
            (const unsigned char *)device_id->valuestring,
            strlen(device_id->valuestring)) ||
        !cJSON_IsString(user_id) ||
        !decimal_text((const unsigned char *)user_id->valuestring,
                      strlen(user_id->valuestring)) ||
        !cJSON_IsString(pass_token) || !pass_token->valuestring[0] ||
        mhg_secret_buf_set(&parsed.device_id, device_id->valuestring,
                           strlen(device_id->valuestring)) != 0 ||
        mhg_secret_buf_set(&parsed.user_id, user_id->valuestring,
                           strlen(user_id->valuestring)) != 0 ||
        mhg_secret_buf_set(&parsed.pass_token, pass_token->valuestring,
                           strlen(pass_token->valuestring)) != 0) {
        errno = EPROTO;
        goto done;
    }
    *record = parsed;
    parsed = (struct mhg_account_record)MHG_ACCOUNT_RECORD_INIT;
    result = MHG_ACCOUNT_STORE_PRESENT;

done:
    {
        int saved = errno;
        mhg_account_record_clear(&parsed);
        mhg_secret_json_delete(root);
        if (data) {
            mhg_secure_clear(data, used);
            free(data);
        }
        if (fd >= 0) close(fd);
        if (result == MHG_ACCOUNT_STORE_ERROR)
            mhg_account_record_clear(record);
        errno = saved;
    }
    return result;
}

int mhg_account_store_prepare(const char *data_root,
                              char *account_path,
                              size_t account_path_size)
{
    int length;

    if (!account_path || account_path_size == 0u ||
        ensure_private_directory(data_root) != 0)
        return -1;
    length = snprintf(account_path, account_path_size, "%s/account.json",
                      data_root);
    if (length < 0 || (size_t)length >= account_path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
    size_t offset = 0u;

    while (offset < size) {
        ssize_t wrote = write(fd, data + offset, size - offset);
        if (wrote > 0) offset += (size_t)wrote;
        else if (wrote < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

static int record_equal(const struct mhg_account_record *left,
                        const struct mhg_account_record *right)
{
    return left->generation == right->generation &&
           left->device_id.len == right->device_id.len &&
           left->user_id.len == right->user_id.len &&
           left->pass_token.len == right->pass_token.len &&
           memcmp(left->device_id.data, right->device_id.data,
                  left->device_id.len) == 0 &&
           memcmp(left->user_id.data, right->user_id.data,
                  left->user_id.len) == 0 &&
           memcmp(left->pass_token.data, right->pass_token.data,
                  left->pass_token.len) == 0;
}

static int exchange_at(int dir_fd, const char *left, const char *right)
{
    return (int)syscall(SYS_renameat2, dir_fd, left, dir_fd, right,
                        RENAME_EXCHANGE);
}

struct account_slot {
    bool exists;
    int load_result;
    struct mhg_account_record record;
};

struct account_transaction {
    bool exists;
    bool had_previous;
    uint64_t old_generation;
    uint64_t new_generation;
};

#define ACCOUNT_SLOT_INIT \
    {false, MHG_ACCOUNT_STORE_ABSENT, MHG_ACCOUNT_RECORD_INIT}

static void slot_clear(struct account_slot *slot)
{
    if (!slot) return;
    mhg_account_record_clear(&slot->record);
    memset(slot, 0, sizeof(*slot));
    slot->load_result = MHG_ACCOUNT_STORE_ABSENT;
}

static int read_slot_at(int dir_fd, const char *leaf,
                        struct account_slot *slot)
{
    struct stat metadata;

    slot_clear(slot);
    if (fstatat(dir_fd, leaf, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    slot->exists = true;
    slot->load_result = read_record_at(dir_fd, leaf, &slot->record);
    if (slot->load_result == MHG_ACCOUNT_STORE_ERROR) {
        slot_clear(slot);
        return -1;
    }
    return 0;
}

static int read_small_file_at(int dir_fd, const char *leaf,
                              unsigned char **data_out, size_t *size_out)
{
    struct stat metadata;
    unsigned char *data = NULL;
    size_t used = 0u;
    int fd = -1;
    int result = -1;

    *data_out = NULL;
    *size_out = 0u;
    fd = openat(dir_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0777) != 0600) {
        errno = EPERM;
        goto done;
    }
    if (metadata.st_size <= 0 ||
        metadata.st_size > (off_t)MHG_ACCOUNT_FILE_LIMIT) {
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
    *data_out = data;
    *size_out = used;
    data = NULL;
    result = 0;

done:
    {
        int saved = errno;
        if (data) {
            mhg_secure_clear(data, used);
            free(data);
        }
        if (fd >= 0) close(fd);
        errno = saved;
    }
    return result;
}

static int transaction_object_exact(const cJSON *root)
{
    static const char *const keys[] = {
        "version", "had_previous", "old_generation", "new_generation",
    };
    const cJSON *item;
    size_t count = 0u;

    if (!cJSON_IsObject(root)) return 0;
    cJSON_ArrayForEach(item, root) {
        size_t index;
        if (!item->string) return 0;
        for (index = 0u; index < sizeof(keys) / sizeof(keys[0]); ++index)
            if (strcmp(item->string, keys[index]) == 0) break;
        if (index == sizeof(keys) / sizeof(keys[0])) return 0;
        ++count;
    }
    return count == sizeof(keys) / sizeof(keys[0]);
}

static int read_transaction_at(int dir_fd,
                               struct account_transaction *transaction)
{
    unsigned char *data = NULL;
    size_t size = 0u;
    cJSON *root = NULL;
    const cJSON *version;
    const cJSON *had_previous;
    const cJSON *old_generation;
    const cJSON *new_generation;
    int result = -1;

    memset(transaction, 0, sizeof(*transaction));
    if (faccessat(dir_fd, MHG_ACCOUNT_TXN_LEAF, F_OK, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    transaction->exists = true;
    if (read_small_file_at(dir_fd, MHG_ACCOUNT_TXN_LEAF,
                           &data, &size) != 0)
        goto done;
    root = mhg_secret_json_parse_len(data, size);
    version = root ? cJSON_GetObjectItemCaseSensitive(root, "version") : NULL;
    had_previous = root ? cJSON_GetObjectItemCaseSensitive(
                              root, "had_previous") : NULL;
    old_generation = root ? cJSON_GetObjectItemCaseSensitive(
                                 root, "old_generation") : NULL;
    new_generation = root ? cJSON_GetObjectItemCaseSensitive(
                                 root, "new_generation") : NULL;
    if (!root || !transaction_object_exact(root) ||
        !cJSON_IsNumber(version) || version->valuedouble != 1.0 ||
        (!cJSON_IsTrue(had_previous) && !cJSON_IsFalse(had_previous)) ||
        !cJSON_IsString(old_generation) ||
        !cJSON_IsString(new_generation) ||
        parse_u64(new_generation->valuestring,
                  &transaction->new_generation) != 0) {
        errno = EPROTO;
        goto done;
    }
    transaction->had_previous = cJSON_IsTrue(had_previous);
    if (transaction->had_previous) {
        if (parse_u64(old_generation->valuestring,
                      &transaction->old_generation) != 0 ||
            transaction->old_generation >= transaction->new_generation) {
            errno = EPROTO;
            goto done;
        }
    } else if (strcmp(old_generation->valuestring, "0") != 0) {
        errno = EPROTO;
        goto done;
    }
    result = 0;

done:
    {
        int saved = errno;
        mhg_secret_json_delete(root);
        if (data) {
            mhg_secure_clear(data, size);
            free(data);
        }
        errno = saved;
    }
    return result;
}

static int slot_has_generation(const struct account_slot *slot,
                               uint64_t generation)
{
    return slot->exists && slot->record.generation == generation;
}

static int recover_transaction(int dir_fd, const char *leaf)
{
    struct account_transaction transaction;
    struct account_slot target = ACCOUNT_SLOT_INIT;
    struct account_slot next = ACCOUNT_SLOT_INIT;
    int result = -1;

    if (read_transaction_at(dir_fd, &transaction) != 0) goto done;
    if (!transaction.exists) {
        result = 0;
        goto done;
    }
    if (read_slot_at(dir_fd, leaf, &target) != 0 ||
        read_slot_at(dir_fd, MHG_ACCOUNT_NEXT_LEAF, &next) != 0)
        goto done;
    if (transaction.had_previous) {
        if (!slot_has_generation(&target, transaction.old_generation)) {
            if (!slot_has_generation(&next, transaction.old_generation)) {
                errno = EPROTO;
                goto done;
            }
            if (target.exists) {
                if (test_checkpoint(
                        MHG_ACCOUNT_STORE_TEST_ROLLBACK_EXCHANGE) != 0 ||
                    exchange_at(dir_fd, leaf, MHG_ACCOUNT_NEXT_LEAF) != 0)
                    goto done;
            } else {
                if (test_checkpoint(
                        MHG_ACCOUNT_STORE_TEST_ROLLBACK_RENAME) != 0 ||
                    renameat(dir_fd, MHG_ACCOUNT_NEXT_LEAF,
                             dir_fd, leaf) != 0)
                    goto done;
            }
        }
    } else if (target.exists) {
        if (!slot_has_generation(&target, transaction.new_generation) ||
            next.exists ||
            test_checkpoint(MHG_ACCOUNT_STORE_TEST_ROLLBACK_RENAME) != 0 ||
            renameat(dir_fd, leaf, dir_fd, MHG_ACCOUNT_NEXT_LEAF) != 0)
            goto done;
    }
    if (test_checkpoint(MHG_ACCOUNT_STORE_TEST_ROLLBACK_DIRECTORY_SYNC) != 0 ||
        fsync(dir_fd) != 0)
        goto done;
    slot_clear(&target);
    if (transaction.had_previous &&
        (read_slot_at(dir_fd, leaf, &target) != 0 ||
         !slot_has_generation(&target, transaction.old_generation))) {
        errno = EPROTO;
        goto done;
    }
    if (unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0) != 0 && errno != ENOENT)
        goto done;
    if (unlinkat(dir_fd, MHG_ACCOUNT_TXN_LEAF, 0) != 0) goto done;
    if (fsync(dir_fd) != 0) goto done;
    result = 0;

done:
    {
        int saved = errno;
        slot_clear(&target);
        slot_clear(&next);
        errno = saved;
    }
    return result;
}

int mhg_account_store_load(const char *account_path,
                           struct mhg_account_record *record)
{
    char directory[PATH_MAX];
    const char *leaf;
    int dir_fd;
    int result;

    if (!record) {
        errno = EINVAL;
        return MHG_ACCOUNT_STORE_ERROR;
    }
    mhg_account_record_clear(record);
    if (split_path(account_path, directory, &leaf) != 0) return -1;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0) return -1;
    if (recover_transaction(dir_fd, leaf) != 0) {
        close(dir_fd);
        return MHG_ACCOUNT_STORE_ERROR;
    }
    result = read_record_at(dir_fd, leaf, record);
    if (result == MHG_ACCOUNT_STORE_PRESENT ||
        result == MHG_ACCOUNT_STORE_ABSENT) {
        if (unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0) == 0)
            (void)fsync(dir_fd);
        else if (errno != ENOENT)
            errno = 0;
    }
    close(dir_fd);
    return result;
}

static int write_transaction_at(int dir_fd, bool had_previous,
                                uint64_t old_generation,
                                uint64_t new_generation)
{
    char old_text[32];
    char new_text[32];
    cJSON *root = NULL;
    char *json = NULL;
    int fd = -1;
    int result = -1;

    snprintf(old_text, sizeof(old_text), "%llu",
             (unsigned long long)old_generation);
    snprintf(new_text, sizeof(new_text), "%llu",
             (unsigned long long)new_generation);
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddNumberToObject(root, "version", 1.0) ||
        !cJSON_AddBoolToObject(root, "had_previous", had_previous) ||
        !cJSON_AddStringToObject(root, "old_generation", old_text) ||
        !cJSON_AddStringToObject(root, "new_generation", new_text)) {
        errno = ENOMEM;
        goto done;
    }
    json = cJSON_PrintUnformatted(root);
    if (!json) {
        errno = ENOMEM;
        goto done;
    }
    fd = openat(dir_fd, MHG_ACCOUNT_TXN_LEAF,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (fd < 0 || write_all(fd, (const unsigned char *)json,
                            strlen(json)) != 0 ||
        fchmod(fd, 0600) != 0 || fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    result = 0;

done:
    {
        int saved = errno;
        if (fd >= 0) close(fd);
        mhg_secret_json_delete(root);
        if (json) {
            mhg_secure_clear(json, strlen(json));
            cJSON_free(json);
        }
        errno = saved;
    }
    return result;
}

static int install_json(const char *account_path,
                        const char *json,
                        const struct mhg_account_record *expected,
                        uint64_t cleared_generation,
                        bool clearing)
{
    char directory[PATH_MAX];
    const char *leaf;
    struct account_slot previous = ACCOUNT_SLOT_INIT;
    struct mhg_account_record readback = MHG_ACCOUNT_RECORD_INIT;
    int dir_fd = -1;
    int file_fd = -1;
    uint64_t new_generation;
    bool transaction_written = false;
    int result = MHG_ACCOUNT_STORE_FAILED;

    if (!json || split_path(account_path, directory, &leaf) != 0) {
        errno = EINVAL;
        return -1;
    }
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0) goto done;
    if (recover_transaction(dir_fd, leaf) != 0 ||
        read_slot_at(dir_fd, leaf, &previous) != 0)
        goto done;
    new_generation = clearing ? cleared_generation : expected->generation;
    if (new_generation == 0u) {
        errno = EINVAL;
        goto done;
    }
    if (previous.exists && new_generation == previous.record.generation) {
        bool same = clearing ?
            previous.load_result == MHG_ACCOUNT_STORE_ABSENT :
            (previous.load_result == MHG_ACCOUNT_STORE_PRESENT &&
             record_equal(expected, &previous.record));

        if (!same) {
            errno = EINVAL;
            goto done;
        }
        if (test_checkpoint(MHG_ACCOUNT_STORE_TEST_COMMIT_DIRECTORY_SYNC) != 0 ||
            fsync(dir_fd) != 0) {
            result = MHG_ACCOUNT_STORE_COMMITTED_NOT_DURABLE;
            goto done;
        }
        result = MHG_ACCOUNT_STORE_COMMITTED_DURABLE;
        if (unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0) == 0)
            (void)fsync(dir_fd);
        goto done;
    }
    if (previous.exists && new_generation < previous.record.generation) {
        errno = EINVAL;
        goto done;
    }
    if (unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0) != 0 && errno != ENOENT)
        goto done;
    if (test_checkpoint(MHG_ACCOUNT_STORE_TEST_TEMP_OPEN) != 0) goto done;
    file_fd = openat(dir_fd, MHG_ACCOUNT_NEXT_LEAF,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (file_fd < 0) goto done;
    if (test_checkpoint(MHG_ACCOUNT_STORE_TEST_WRITE) != 0 ||
        write_all(file_fd, (const unsigned char *)json, strlen(json)) != 0 ||
        test_checkpoint(MHG_ACCOUNT_STORE_TEST_FILE_MODE) != 0 ||
        fchmod(file_fd, 0600) != 0 ||
        test_checkpoint(MHG_ACCOUNT_STORE_TEST_FILE_SYNC) != 0 ||
        fsync(file_fd) != 0)
        goto done;
    if (close(file_fd) != 0) {
        file_fd = -1;
        goto done;
    }
    file_fd = -1;
    if (write_transaction_at(dir_fd, previous.exists,
                             previous.exists ? previous.record.generation : 0u,
                             new_generation) != 0)
        goto done;
    transaction_written = true;
    if (fsync(dir_fd) != 0) goto rollback;
    if (test_checkpoint(clearing ? MHG_ACCOUNT_STORE_TEST_CLEAR_INSTALL :
                                   MHG_ACCOUNT_STORE_TEST_INSTALL) != 0 ||
        (previous.exists ? exchange_at(dir_fd, leaf, MHG_ACCOUNT_NEXT_LEAF) :
         renameat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, dir_fd, leaf)) != 0)
        goto rollback;
    if (test_checkpoint(clearing ?
            MHG_ACCOUNT_STORE_TEST_CLEAR_DIRECTORY_SYNC :
            MHG_ACCOUNT_STORE_TEST_DIRECTORY_SYNC) != 0 ||
        fsync(dir_fd) != 0 ||
        test_checkpoint(MHG_ACCOUNT_STORE_TEST_READBACK) != 0 ||
        (clearing ?
         (read_record_at(dir_fd, leaf, &readback) !=
              MHG_ACCOUNT_STORE_ABSENT ||
          readback.generation != cleared_generation) :
         (read_record_at(dir_fd, leaf, &readback) !=
              MHG_ACCOUNT_STORE_PRESENT ||
          !record_equal(expected, &readback)))) {
        if (!errno) errno = EIO;
        goto rollback;
    }
    if (unlinkat(dir_fd, MHG_ACCOUNT_TXN_LEAF, 0) != 0) goto rollback;
    transaction_written = false;
    if (test_checkpoint(MHG_ACCOUNT_STORE_TEST_COMMIT_DIRECTORY_SYNC) != 0 ||
        fsync(dir_fd) != 0) {
        result = MHG_ACCOUNT_STORE_COMMITTED_NOT_DURABLE;
        goto done;
    }
    result = MHG_ACCOUNT_STORE_COMMITTED_DURABLE;
    if (previous.exists &&
        unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0) == 0)
        (void)fsync(dir_fd);
    goto done;

rollback:
    {
        int saved = errno ? errno : EIO;
        if (transaction_written)
            (void)recover_transaction(dir_fd, leaf);
        errno = saved;
    }

done:
    {
        int saved = errno;
        if (file_fd >= 0) close(file_fd);
        if (!transaction_written && result == MHG_ACCOUNT_STORE_FAILED &&
            dir_fd >= 0) {
            (void)unlinkat(dir_fd, MHG_ACCOUNT_NEXT_LEAF, 0);
            (void)unlinkat(dir_fd, MHG_ACCOUNT_TXN_LEAF, 0);
            (void)fsync(dir_fd);
        }
        if (dir_fd >= 0) close(dir_fd);
        slot_clear(&previous);
        mhg_account_record_clear(&readback);
        errno = saved;
    }
    return result;
}

int mhg_account_store_commit(const char *account_path,
                             const struct mhg_account_record *record)
{
    char generation[32];
    cJSON *root = NULL;
    char *json = NULL;
    int result;

    if (!record_valid(record)) {
        errno = EINVAL;
        return -1;
    }
    snprintf(generation, sizeof(generation), "%llu",
             (unsigned long long)record->generation);
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddNumberToObject(root, "version", 2.0) ||
        !cJSON_AddStringToObject(root, "login_method", "phone") ||
        !cJSON_AddStringToObject(root, "account_generation", generation) ||
        !cJSON_AddBoolToObject(root, "authorized", true) ||
        !cJSON_AddStringToObject(root, "deviceId",
                                 (const char *)record->device_id.data) ||
        !cJSON_AddStringToObject(root, "userId",
                                 (const char *)record->user_id.data) ||
        !cJSON_AddStringToObject(root, "passToken",
                                 (const char *)record->pass_token.data)) {
        errno = ENOMEM;
        result = -1;
        goto done;
    }
    json = cJSON_PrintUnformatted(root);
    if (!json) {
        errno = ENOMEM;
        result = -1;
        goto done;
    }
    result = install_json(account_path, json, record, 0u, false);

done:
    {
        int saved = errno;
        mhg_secret_json_delete(root);
        if (json) {
            mhg_secure_clear(json, strlen(json));
            cJSON_free(json);
        }
        errno = saved;
    }
    return result;
}

int mhg_account_store_clear(const char *account_path,
                            uint64_t cleared_generation)
{
    char generation[32];
    cJSON *root = NULL;
    char *json = NULL;
    int result;

    if (cleared_generation == 0u) {
        errno = EINVAL;
        return -1;
    }
    snprintf(generation, sizeof(generation), "%llu",
             (unsigned long long)cleared_generation);
    root = cJSON_CreateObject();
    if (!root || !cJSON_AddNumberToObject(root, "version", 2.0) ||
        !cJSON_AddStringToObject(root, "login_method", "phone") ||
        !cJSON_AddStringToObject(root, "account_generation", generation) ||
        !cJSON_AddBoolToObject(root, "authorized", false)) {
        errno = ENOMEM;
        result = -1;
        goto done;
    }
    json = cJSON_PrintUnformatted(root);
    if (!json) {
        errno = ENOMEM;
        result = -1;
        goto done;
    }
    result = install_json(account_path, json, NULL, cleared_generation, true);

done:
    {
        int saved = errno;
        mhg_secret_json_delete(root);
        if (json) {
            mhg_secure_clear(json, strlen(json));
            cJSON_free(json);
        }
        errno = saved;
    }
    return result;
}
