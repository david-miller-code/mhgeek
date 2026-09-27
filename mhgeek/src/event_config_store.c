#define _GNU_SOURCE

#include "event_config_store.h"

#include <cjson/cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "atomic_file.h"
#include "secret_json.h"

#define MHG_EVENT_NEXT_LEAF ".events.json.mhg-next"

static int sync_directory(const char *path)
{
    int descriptor;
    int result;

    descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0)
        return -1;
    do {
        result = fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    if (close(descriptor) != 0 && result == 0)
        result = -1;
    return result;
}

static int atomic_rename(void *userdata, const char *source, const char *target)
{
    (void)userdata;
    return rename(source, target);
}

static int atomic_unlink(void *userdata, const char *path)
{
    (void)userdata;
    return unlink(path);
}

#ifdef MHG_EVENT_CONFIG_TESTING
static int g_test_fail_parent_sync;

void mhg_event_config_test_fail_parent_sync_once(void)
{
    g_test_fail_parent_sync = 1;
}
#endif

static int atomic_sync_parent(void *userdata, const char *parent)
{
    (void)userdata;
#ifdef MHG_EVENT_CONFIG_TESTING
    if (g_test_fail_parent_sync) {
        g_test_fail_parent_sync = 0;
        errno = EIO;
        return -1;
    }
#endif
    return sync_directory(parent);
}

static const struct atomic_file_ops g_event_atomic_ops = {
    .prepare_parent = NULL,
    .rename_path = atomic_rename,
    .unlink_path = atomic_unlink,
    .sync_parent = atomic_sync_parent,
};

int mhg_event_config_seconds_valid(double seconds)
{
    return isfinite(seconds) && seconds >= 1.0 &&
           seconds <= 9007199254740.0 &&
           (double)(uint64_t)seconds == seconds;
}

int mhg_event_config_text_is_valid(const char *text, size_t limit)
{
    const unsigned char *cursor;
    size_t length;

    if (!text)
        return 0;
    length = strlen(text);
    if (length == 0u || length > limit)
        return 0;
    cursor = (const unsigned char *)text;
    while (*cursor) {
        uint32_t code;
        unsigned continuation;
        unsigned char first = *cursor++;
        if (first < 0x80u) {
            if (first < 0x20u || first == 0x7fu)
                return 0;
            continue;
        }
        if (first >= 0xc2u && first <= 0xdfu) {
            code = first & 0x1fu;
            continuation = 1;
        } else if (first >= 0xe0u && first <= 0xefu) {
            code = first & 0x0fu;
            continuation = 2;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            code = first & 0x07u;
            continuation = 3;
        } else
            return 0;
        for (unsigned i = 0; i < continuation; ++i) {
            if ((*cursor & 0xc0u) != 0x80u)
                return 0;
            code = (code << 6u) | (*cursor++ & 0x3fu);
        }
        if ((continuation == 2 && code < 0x800u) ||
            (continuation == 3 && code < 0x10000u) ||
            (code >= 0xd800u && code <= 0xdfffu) || code > 0x10ffffu ||
            (code >= 0x80u && code <= 0x9fu))
            return 0;
    }
    return 1;
}

static char *trim_prefix(const char *text)
{
    const char *start = text;
    const char *end;
    size_t length;
    char *out;

    while (*start == ' ' || *start == '\t')
        start++;
    end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        end--;
    length = (size_t)(end - start);
    out = calloc(length + 1u, 1u);
    if (!out)
        return NULL;
    memcpy(out, start, length);
    return out;
}

int mhg_event_config_prepare(const char *data_root, char *path, size_t path_size)
{
    int written;

    if (!data_root || data_root[0] != '/' || !path || path_size == 0u) {
        errno = EINVAL;
        return -1;
    }
    if (strlen(data_root) + strlen("/events.json") >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    written = snprintf(path, path_size, "%s/events.json", data_root);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

void mhg_event_config_dispose(struct mhg_event_config *config)
{
    size_t index;

    if (!config)
        return;
    mhg_secret_buf_clear(&config->prefix);
    for (index = 0u; index < (MHG_PRESENCE_SLOT_COUNT * 2u); ++index)
        mhg_secret_buf_clear(&config->texts[index]);
    mhg_secure_clear(config, sizeof(*config));
}

int mhg_event_config_clone(struct mhg_event_config *destination,
                           const struct mhg_event_config *source)
{
    struct mhg_event_config copied = MHG_EVENT_CONFIG_INIT;
    size_t index;

    if (!destination || !source)
        return -1;
    copied.generation = source->generation;
    memcpy(copied.absent_seconds, source->absent_seconds,
           sizeof(copied.absent_seconds));
    if (source->prefix.data &&
        mhg_secret_buf_set(&copied.prefix, (const char *)source->prefix.data,
                           source->prefix.len) != 0)
        goto fail;
    for (index = 0u; index < (MHG_PRESENCE_SLOT_COUNT * 2u); ++index) {
        const struct mhg_secret_buf *text = &source->texts[index];

        if (text->data && mhg_secret_buf_set(&copied.texts[index],
                                             (const char *)text->data, text->len) != 0)
            goto fail;
    }
    mhg_event_config_dispose(destination);
    *destination = copied;
    return 0;

fail:
    mhg_event_config_dispose(&copied);
    return -1;
}

int mhg_event_config_load(const char *path, struct mhg_event_config *config)
{
    cJSON *root = NULL;
    const cJSON *generation;
    const cJSON *prefix;
    const cJSON *texts;
    struct mhg_event_config parsed = MHG_EVENT_CONFIG_INIT;
    struct stat info;

    memset(&info, 0, sizeof(info));
    char *data = NULL;
    size_t index;
    int descriptor = -1;
    int result = MHG_EVENT_CONFIG_ERROR;
    int needs_repair = 0;

    if (!path || !config)
        return MHG_EVENT_CONFIG_ERROR;
    mhg_event_config_dispose(config);
    descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        result = errno == ENOENT ? MHG_EVENT_CONFIG_ABSENT : MHG_EVENT_CONFIG_ERROR;
        return result;
    }
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
        (size_t)info.st_size > MHG_EVENT_CONFIG_LIMIT) {
        errno = EPROTO;
        goto done;
    }
    data = calloc((size_t)info.st_size + 1u, 1u);
    if (!data)
        goto done;
    {
        ssize_t got = read(descriptor, data, (size_t)info.st_size);

        if (got != (ssize_t)info.st_size) {
            errno = EIO;
            goto done;
        }
    }
    root = mhg_secret_json_parse_len((const unsigned char *)data, (size_t)info.st_size);
    if (!root || !cJSON_IsObject(root)) {
        errno = EPROTO;
        goto done;
    }
    generation = cJSON_GetObjectItemCaseSensitive(root, "generation");
    prefix = cJSON_GetObjectItemCaseSensitive(root, "prefix");
    texts = cJSON_GetObjectItemCaseSensitive(root, "texts");
    if (!cJSON_IsNumber(generation) || !isfinite(generation->valuedouble) ||
        generation->valuedouble < 0.0 || generation->valuedouble > 9007199254740991.0 ||
        (double)(uint64_t)generation->valuedouble != generation->valuedouble ||
        !cJSON_IsString(prefix) || !cJSON_IsArray(texts) ||
        cJSON_GetArraySize(texts) != (int)(MHG_PRESENCE_SLOT_COUNT * 2u)) {
        errno = EPROTO;
        goto done;
    }
    /* The prefix may be empty; every direction text must satisfy the bound. */
    if (prefix->valuestring[0] &&
        !mhg_event_config_text_is_valid(prefix->valuestring, MHG_EVENT_PREFIX_LIMIT)) {
        errno = EPROTO;
        goto done;
    }
    if (prefix->valuestring[0] != '\0' &&
        mhg_secret_buf_set(&parsed.prefix, prefix->valuestring,
                           strlen(prefix->valuestring)) != 0)
        goto done;
    for (index = 0u; index < (MHG_PRESENCE_SLOT_COUNT * 2u); ++index) {
        const cJSON *item = cJSON_GetArrayItem(texts, (int)index);

        if (!cJSON_IsString(item) ||
            !mhg_event_config_text_is_valid(item->valuestring, MHG_EVENT_TEXT_LIMIT)) {
            errno = EPROTO;
            goto done;
        }
        if (mhg_secret_buf_set(&parsed.texts[index], item->valuestring,
                               strlen(item->valuestring)) != 0)
            goto done;
    }
    {
        const cJSON *seconds = cJSON_GetObjectItemCaseSensitive(root, "absent_seconds");
        if (seconds && (!cJSON_IsArray(seconds) ||
                        cJSON_GetArraySize(seconds) != MHG_PRESENCE_SLOT_COUNT)) {
            errno = EPROTO;
            goto done;
        }
        for (index = 0; seconds && index < MHG_PRESENCE_SLOT_COUNT; ++index) {
            const cJSON *value = cJSON_GetArrayItem(seconds, (int)index);
            if (!cJSON_IsNumber(value)) {
                errno = EPROTO;
                goto done;
            }
            if (!mhg_event_config_seconds_valid(value->valuedouble)) {
                parsed.absent_seconds[index] = 1;
                needs_repair = 1;
            } else
                parsed.absent_seconds[index] = value->valuedouble;
        }
    }
    parsed.generation = (uint64_t)generation->valuedouble;
    *config = parsed;
    parsed = (struct mhg_event_config)MHG_EVENT_CONFIG_INIT;
    result = needs_repair ? MHG_EVENT_CONFIG_NEEDS_REPAIR : MHG_EVENT_CONFIG_PRESENT;

done:
    if (descriptor >= 0)
        close(descriptor);
    if (data) {
        mhg_secure_clear(data, (size_t)(info.st_size + 1));
        free(data);
    }
    mhg_secret_json_delete(root);
    mhg_event_config_dispose(&parsed);
    return result;
}

static char *render_config(const struct mhg_event_config *config)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *texts = cJSON_CreateArray();
    char *text = NULL;
    size_t index;

    if (!root || !texts || config->generation > 9007199254740991ull)
        goto fail;
    if (config->prefix.data && config->prefix.len &&
        !mhg_event_config_text_is_valid((const char *)config->prefix.data,
                                        MHG_EVENT_PREFIX_LIMIT))
        goto fail;
    for (index = 0; index < MHG_PRESENCE_SLOT_COUNT * 2u; ++index)
        if (!config->texts[index].data ||
            !mhg_event_config_text_is_valid((const char *)config->texts[index].data,
                                            MHG_EVENT_TEXT_LIMIT))
            goto fail;
    if (!cJSON_AddNumberToObject(root, "generation", (double)config->generation) ||
        !cJSON_AddStringToObject(root, "prefix",
                                 config->prefix.data ? (const char *)config->prefix.data
                                                     : "") ||
        !cJSON_AddItemToObject(root, "texts", texts))
        goto fail;
    texts = NULL; /* owned by root now */
    {
        cJSON *array = cJSON_GetObjectItemCaseSensitive(root, "texts");

        for (index = 0u; index < (MHG_PRESENCE_SLOT_COUNT * 2u); ++index) {
            const struct mhg_secret_buf *value = &config->texts[index];

            if (!cJSON_AddItemToArray(
                    array,
                    cJSON_CreateString(value->data ? (const char *)value->data : "")))
                goto fail;
        }
    }
    {
        cJSON *seconds = cJSON_AddArrayToObject(root, "absent_seconds");
        if (!seconds)
            goto fail;
        for (index = 0; index < MHG_PRESENCE_SLOT_COUNT; ++index) {
            if (!mhg_event_config_seconds_valid(config->absent_seconds[index]) ||
                !cJSON_AddItemToArray(
                    seconds, cJSON_CreateNumber(config->absent_seconds[index])))
                goto fail;
        }
    }
    text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return text;

fail:
    cJSON_Delete(texts);
    cJSON_Delete(root);
    return NULL;
}

int mhg_event_config_commit(const char *path, const struct mhg_event_config *config)
{
    struct mhg_event_config reloaded = MHG_EVENT_CONFIG_INIT;
    struct mhg_event_config trimmed = MHG_EVENT_CONFIG_INIT;
    char *prefix = NULL;
    char *text;
    int result;

    if (!path || !config)
        return MHG_EVENT_CONFIG_FAILED;
    /* The persisted prefix is always the trimmed one (§7.3). */
    trimmed = *config;
    prefix = trim_prefix(config->prefix.data ? (const char *)config->prefix.data : "");
    if (!prefix)
        return MHG_EVENT_CONFIG_FAILED;
    trimmed.prefix = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
    if (prefix[0] != '\0' &&
        mhg_secret_buf_set(&trimmed.prefix, prefix, strlen(prefix)) != 0) {
        free(prefix);
        return MHG_EVENT_CONFIG_FAILED;
    }
    text = render_config(&trimmed);
    if (!text) {
        mhg_secret_buf_clear(&trimmed.prefix);
        free(prefix);
        return MHG_EVENT_CONFIG_FAILED;
    }
    result = atomic_file_replace_text(path, text, 0600u, MHG_EVENT_CONFIG_LIMIT,
                                      &g_event_atomic_ops, NULL);
    cJSON_free(text);
    mhg_secret_buf_clear(&trimmed.prefix);
    free(prefix);
    if (!atomic_file_result_committed(result))
        return MHG_EVENT_CONFIG_FAILED;
    /* Committed and read back: the running process must never serve a config
     * it cannot re-read. */
    if (mhg_event_config_load(path, &reloaded) != MHG_EVENT_CONFIG_PRESENT ||
        reloaded.generation != config->generation) {
        mhg_event_config_dispose(&reloaded);
        return MHG_EVENT_CONFIG_FAILED;
    }
    mhg_event_config_dispose(&reloaded);
    return result == ATOMIC_FILE_COMMITTED_DURABLE
               ? MHG_EVENT_CONFIG_COMMITTED_DURABLE
               : MHG_EVENT_CONFIG_COMMITTED_NOT_DURABLE;
}

int mhg_event_config_clear(const char *path)
{
    char next[PATH_MAX];
    const char *slash;
    int result;

    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (unlink(path) != 0 && errno != ENOENT)
        return -1;
    slash = strrchr(path, '/');
    if (!slash || slash == path)
        return 0;
    if ((size_t)(slash - path) + strlen(MHG_EVENT_NEXT_LEAF) + 1u >= sizeof(next))
        return 0;
    snprintf(next, sizeof(next), "%.*s%s", (int)(slash - path), path,
             MHG_EVENT_NEXT_LEAF);
    (void)unlink(next);
    result = 0;
    {
        char directory[PATH_MAX];

        snprintf(directory, sizeof(directory), "%.*s", (int)(slash - path), path);
        if (directory[0] != '\0')
            (void)sync_directory(directory);
    }
    return result;
}

int mhg_event_config_final_texts(
    const struct mhg_event_config *config,
    char (*final)[MHG_EVENT_PREFIX_LIMIT + MHG_EVENT_TEXT_LIMIT + 1u],
    const char **pointers, size_t count)
{
    const char *prefix;
    size_t index;

    if (!config || !final || !pointers || count < (MHG_PRESENCE_SLOT_COUNT * 2u))
        return -1;
    prefix = config->prefix.data ? (const char *)config->prefix.data : "";
    for (index = 0u; index < (MHG_PRESENCE_SLOT_COUNT * 2u); ++index) {
        const char *text =
            config->texts[index].data ? (const char *)config->texts[index].data : "";
        int written =
            snprintf(final[index], MHG_EVENT_PREFIX_LIMIT + MHG_EVENT_TEXT_LIMIT + 1u,
                     "%s%s", prefix, text);

        if (written < 0 ||
            (size_t)written >= MHG_EVENT_PREFIX_LIMIT + MHG_EVENT_TEXT_LIMIT + 1u)
            return -1;
        pointers[index] = final[index];
    }
    return 0;
}
