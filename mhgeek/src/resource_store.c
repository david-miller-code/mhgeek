#define _GNU_SOURCE

#include "resource_store.h"

#include <cjson/cJSON.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_json.h"

#define MHG_RESOURCE_FILE_LIMIT 16384u
#define MHG_RESOURCE_ID_LIMIT 64u
struct resource_sidecars {
    char next[NAME_MAX + 1u];
};
static int safe_path(const char *path)
{
    const unsigned char *cursor;
    size_t length;

    if (!path || path[0] != '/' || strcmp(path, "/") == 0)
        return -1;
    length = strlen(path);
    if (length >= PATH_MAX || strstr(path, "/../") ||
        (length >= 3u && strcmp(path + length - 3u, "/..") == 0))
        return -1;
    for (cursor = (const unsigned char *)path; *cursor; ++cursor) {
        if ((*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
            (*cursor >= '0' && *cursor <= '9') || *cursor == '/' || *cursor == '.' ||
            *cursor == '_' || *cursor == '-')
            continue;
        return -1;
    }
    return 0;
}

static int split_path(const char *path, char directory[PATH_MAX], const char **leaf)
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

static int sidecars_for_leaf(const char *leaf, struct resource_sidecars *out)
{
    int n = snprintf(out->next, sizeof(out->next), ".%s.mhg-next", leaf);
    return n < 0 || (size_t)n >= sizeof(out->next) ? -1 : 0;
}
static int ensure_private_directory(const char *path)
{
    struct stat metadata;

    if (safe_path(path) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &metadata) != 0) {
        if (errno != ENOENT || mkdir(path, 0700) != 0 || lstat(path, &metadata) != 0)
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

    if (fd < 0)
        return -1;
    if (fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0777) != 0700) {
        int saved = errno ? errno : EPERM;

        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int text_valid(const struct mhg_secret_buf *value)
{
    size_t index;

    if (!value->data || value->len == 0u || value->len > MHG_RESOURCE_ID_LIMIT)
        return 0;
    for (index = 0u; index < value->len; ++index) {
        unsigned char byte = (unsigned char)value->data[index];

        if (byte <= 0x20u || byte == 0x7fu || byte >= 0x80u)
            return 0;
    }
    return 1;
}

const struct mhg_secret_buf *
mhg_resource_variable(const struct mhg_resource_record *record,
                      enum mhg_presence_slot slot, bool present)
{
    (void)present;
    return record && (unsigned)slot < MHG_PRESENCE_SLOT_COUNT
               ? &record->local_variables[slot]
               : NULL;
}
const struct mhg_secret_buf *
mhg_resource_global_variable(const struct mhg_resource_record *record,
                             enum mhg_presence_slot slot)
{
    return record && (unsigned)slot < MHG_PRESENCE_SLOT_COUNT
               ? &record->global_variables[slot]
               : NULL;
}
int mhg_resource_node_id(enum mhg_presence_slot slot, bool present, bool trigger,
                         char *out, size_t out_size)
{
    int written;

    if (!out || slot >= MHG_PRESENCE_SLOT_COUNT)
        return -1;
    written = snprintf(out, out_size, "slot%u%s%s", (unsigned)slot,
                       present ? "Present" : "Absent", trigger ? "Trigger" : "Action");
    if (written < 0 || (size_t)written >= out_size)
        return -1;
    return 0;
}

int mhg_resource_store_prepare(const char *data_root, char *path, size_t path_size)
{
    int written;

    if (!path || ensure_private_directory(data_root) != 0) {
        errno = EINVAL;
        return -1;
    }
    written = snprintf(path, path_size, "%s/resources.json", data_root);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int record_matches_target(const struct mhg_resource_record *record,
                                 const struct mhg_secret_buf *did,
                                 const struct mhg_secret_buf *model)
{
    return record->target_did.len == did->len &&
           record->target_model.len == model->len &&
           memcmp(record->target_did.data, did->data, did->len) == 0 &&
           memcmp(record->target_model.data, model->data, model->len) == 0;
}

static int hash_target_field(EVP_MD_CTX *context, const struct mhg_secret_buf *field)
{
    unsigned char length[8];
    uint64_t size = field->len;
    size_t index;

    for (index = 0u; index < sizeof(length); ++index) {
        length[sizeof(length) - 1u - index] = (unsigned char)(size & 0xffu);
        size >>= 8u;
    }
    return EVP_DigestUpdate(context, length, sizeof(length)) == 1 &&
                   EVP_DigestUpdate(context, field->data, field->len) == 1
               ? 0
               : -1;
}

int mhg_resource_store_select_path(const char *base_path,
                                   const struct mhg_secret_buf *target_did,
                                   const struct mhg_secret_buf *target_model,
                                   char *selected, size_t selected_size)
{
    static const char domain[] = "mhgateway-resource-target-v1";
    struct mhg_resource_record primary = MHG_RESOURCE_RECORD_INIT;
    struct mhg_resource_record candidate = MHG_RESOURCE_RECORD_INIT;
    char directory[PATH_MAX];
    const char *leaf = NULL;
    char alternate[PATH_MAX];
    char digest_hex[65];
    unsigned char digest[32];
    unsigned int digest_length = 0u;
    EVP_MD_CTX *hash = NULL;
    int primary_state;
    int alternate_state;
    int written;
    int result = -1;
    size_t index;

    if (selected && selected_size > 0u)
        selected[0] = '\0';
    if (!base_path || !target_did || !target_model || !target_did->data ||
        !target_model->data || target_did->len == 0u || target_model->len == 0u ||
        !selected || selected_size == 0u ||
        split_path(base_path, directory, &leaf) != 0 ||
        strcmp(leaf, "resources.json") != 0) {
        errno = EINVAL;
        return -1;
    }
    primary_state = mhg_resource_store_load(base_path, &primary);
    if (primary_state == MHG_RESOURCE_STORE_ERROR && errno != EPROTO) {
        errno = EPROTO;
        goto done;
    }
    if (primary_state == MHG_RESOURCE_STORE_PRESENT &&
        record_matches_target(&primary, target_did, target_model)) {
        written = snprintf(selected, selected_size, "%s", base_path);
        if (written < 0 || (size_t)written >= selected_size) {
            errno = ENAMETOOLONG;
            goto done;
        }
        result = 0;
        goto done;
    }
    hash = EVP_MD_CTX_new();
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, domain, sizeof(domain) - 1u) != 1 ||
        hash_target_field(hash, target_did) != 0 ||
        hash_target_field(hash, target_model) != 0 ||
        EVP_DigestFinal_ex(hash, digest, &digest_length) != 1 ||
        digest_length != sizeof(digest)) {
        errno = EIO;
        goto done;
    }
    for (index = 0u; index < sizeof(digest); ++index)
        snprintf(digest_hex + index * 2u, 3u, "%02x", digest[index]);
    digest_hex[64] = '\0';
    written = snprintf(alternate, sizeof(alternate), "%s/resources.%s.json", directory,
                       digest_hex);
    if (written < 0 || (size_t)written >= sizeof(alternate)) {
        errno = ENAMETOOLONG;
        goto done;
    }
    alternate_state = mhg_resource_store_load(alternate, &candidate);
    if ((alternate_state == MHG_RESOURCE_STORE_ERROR && errno != EPROTO) ||
        (alternate_state == MHG_RESOURCE_STORE_PRESENT &&
         !record_matches_target(&candidate, target_did, target_model))) {
        errno = EPROTO;
        goto done;
    }
    written = snprintf(selected, selected_size, "%s",
                       alternate_state == MHG_RESOURCE_STORE_PRESENT ||
                               primary_state == MHG_RESOURCE_STORE_PRESENT
                           ? alternate
                           : base_path);
    if (written < 0 || (size_t)written >= selected_size) {
        errno = ENAMETOOLONG;
        goto done;
    }
    result = 0;

done:
    EVP_MD_CTX_free(hash);
    mhg_resource_record_clear(&candidate);
    mhg_resource_record_clear(&primary);
    return result;
}

void mhg_resource_record_clear(struct mhg_resource_record *r)
{
    if (!r)
        return;
    mhg_secret_buf_clear(&r->digest);
    mhg_secret_buf_clear(&r->target_did);
    mhg_secret_buf_clear(&r->target_model);
    mhg_secret_buf_clear(&r->graph_id);
    mhg_secret_buf_clear(&r->scope);
    mhg_secret_buf_clear(&r->action_urn);
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; i++) {
        mhg_secret_buf_clear(&r->local_variables[i]);
        mhg_secret_buf_clear(&r->global_variables[i]);
    }
    memset(r, 0, sizeof(*r));
}
int mhg_resource_record_clone(struct mhg_resource_record *destination,
                              const struct mhg_resource_record *source)
{
    struct mhg_resource_record copy = MHG_RESOURCE_RECORD_INIT;
    if (!destination || !source)
        return -1;
    copy.version = source->version;
    copy.resource_generation = source->resource_generation;
    copy.spec_generation = source->spec_generation;
    copy.config_generation = source->config_generation;
    copy.stage = source->stage;
    copy.seed_state = source->seed_state;
    copy.global_seed_state = source->global_seed_state;
    copy.action_siid = source->action_siid;
    copy.action_aiid = source->action_aiid;
    copy.action_piid = source->action_piid;
    if (source->digest.data &&
        mhg_secret_buf_set(&copy.digest, source->digest.data, source->digest.len))
        goto fail;
    if (source->target_did.data &&
        mhg_secret_buf_set(&copy.target_did, source->target_did.data,
                           source->target_did.len))
        goto fail;
    if (source->target_model.data &&
        mhg_secret_buf_set(&copy.target_model, source->target_model.data,
                           source->target_model.len))
        goto fail;
    if (source->graph_id.data &&
        mhg_secret_buf_set(&copy.graph_id, source->graph_id.data, source->graph_id.len))
        goto fail;
    if (source->scope.data &&
        mhg_secret_buf_set(&copy.scope, source->scope.data, source->scope.len))
        goto fail;
    if (source->action_urn.data &&
        mhg_secret_buf_set(&copy.action_urn, source->action_urn.data,
                           source->action_urn.len))
        goto fail;
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; i++) {
        if ((source->local_variables[i].data &&
             mhg_secret_buf_set(&copy.local_variables[i],
                                source->local_variables[i].data,
                                source->local_variables[i].len)) ||
            (source->global_variables[i].data &&
             mhg_secret_buf_set(&copy.global_variables[i],
                                source->global_variables[i].data,
                                source->global_variables[i].len)))
            goto fail;
    }
    mhg_resource_record_clear(destination);
    *destination = copy;
    return 0;
fail:
    mhg_resource_record_clear(&copy);
    return -1;
}
static int read_file(const char *path, char **text_out, size_t *length_out)
{
    struct stat metadata;
    char *text;
    size_t offset = 0u;
    int fd;

    if (lstat(path, &metadata) != 0)
        return errno == ENOENT ? 1 : -1;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0777) != 0600) {
        errno = EPERM;
        return -1;
    }
    if (metadata.st_size <= 0 ||
        (unsigned long long)metadata.st_size > MHG_RESOURCE_FILE_LIMIT) {
        errno = EPROTO;
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    text = calloc(1u, (size_t)metadata.st_size + 1u);
    if (!text) {
        close(fd);
        return -1;
    }
    while (offset < (size_t)metadata.st_size) {
        ssize_t got = read(fd, text + offset, (size_t)metadata.st_size - offset);

        if (got > 0)
            offset += (size_t)got;
        else if (got < 0 && errno == EINTR)
            continue;
        else {
            free(text);
            close(fd);
            return -1;
        }
    }
    close(fd);
    if (memchr(text, '\0', offset)) {
        free(text);
        errno = EPROTO;
        return -1;
    }
    *text_out = text;
    *length_out = offset;
    return 0;
}

static int text_from_json(const cJSON *item, struct mhg_secret_buf *out)
{
    if (!cJSON_IsString(item) || !item->valuestring[0])
        return -1;
    return mhg_secret_buf_set(out, item->valuestring, strlen(item->valuestring));
}

static int integer_from_json(const cJSON *item, uint64_t *out)
{
    double value;

    if (!cJSON_IsNumber(item) || !out)
        return -1;
    value = item->valuedouble;
    /* cJSON stores numbers as doubles. Restrict record counters to exact
     * integers rather than silently rounding a future generation or timeout. */
    if (!isfinite(value) || value < 0.0 || value > 9007199254740991.0 ||
        (double)(uint64_t)value != value)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static int exact_keys(const cJSON *object, const char *const *keys, size_t count)
{
    const cJSON *item;
    size_t index;
    size_t seen = 0u;

    if (!cJSON_IsObject(object))
        return -1;
    cJSON_ArrayForEach(item, object)
    {
        bool known = false;

        if (!item->string)
            return -1;
        for (index = 0u; index < count; ++index)
            if (strcmp(item->string, keys[index]) == 0) {
                known = true;
                break;
            }
        if (!known)
            return -1;
        seen += 1u;
    }
    if (seen != count)
        return -1;
    for (index = 0u; index < count; ++index) {
        size_t matches = 0u;

        cJSON_ArrayForEach(item, object) if (strcmp(item->string, keys[index]) == 0)
            matches += 1u;
        if (matches != 1u)
            return -1;
    }
    return 0;
}

static int parse_ids(const cJSON *array, struct mhg_secret_buf *ids, size_t count)
{
    size_t index;

    if (!cJSON_IsArray(array) || cJSON_GetArraySize(array) != (int)count)
        return -1;
    for (index = 0u; index < count; ++index)
        if (text_from_json(cJSON_GetArrayItem(array, (int)index), &ids[index]) ||
            !text_valid(&ids[index]))
            return -1;
    return 0;
}

static int parse_record(const cJSON *root, struct mhg_resource_record *r)
{
    static const char *const keys[] = {"version",
                                       "resource_generation",
                                       "spec_generation",
                                       "config_generation",
                                       "stage",
                                       "seed_state",
                                       "global_seed_state",
                                       "action_siid",
                                       "action_aiid",
                                       "action_piid",
                                       "digest",
                                       "target_did",
                                       "target_model",
                                       "graph_id",
                                       "scope",
                                       "action_urn",
                                       "local_variables",
                                       "global_variables"};
    uint64_t n;
    if (exact_keys(root, keys, sizeof(keys) / sizeof(keys[0])))
        return -1;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "version"), &n))
        return -1;
    r->version = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "resource_generation"),
                          &n))
        return -1;
    r->resource_generation = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "spec_generation"),
                          &n))
        return -1;
    r->spec_generation = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "config_generation"),
                          &n))
        return -1;
    r->config_generation = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "stage"), &n))
        return -1;
    if (n > MHG_RESOURCE_STAGE_READY)
        return -1;
    r->stage = (enum mhg_resource_stage)n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "seed_state"), &n))
        return -1;
    if (n > MHG_RESOURCE_SEED_VERIFIED)
        return -1;
    r->seed_state = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "global_seed_state"),
                          &n))
        return -1;
    if (n > MHG_RESOURCE_SEED_VERIFIED)
        return -1;
    r->global_seed_state = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "action_siid"), &n))
        return -1;
    if (!n || n > INT_MAX)
        return -1;
    r->action_siid = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "action_aiid"), &n))
        return -1;
    if (!n || n > INT_MAX)
        return -1;
    r->action_aiid = n;
    if (integer_from_json(cJSON_GetObjectItemCaseSensitive(root, "action_piid"), &n))
        return -1;
    if (!n || n > INT_MAX)
        return -1;
    r->action_piid = n;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "digest"), &r->digest) ||
        !text_valid(&r->digest))
        return -1;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "target_did"),
                       &r->target_did) ||
        !text_valid(&r->target_did))
        return -1;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "target_model"),
                       &r->target_model) ||
        !text_valid(&r->target_model))
        return -1;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "graph_id"),
                       &r->graph_id) ||
        !text_valid(&r->graph_id))
        return -1;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "scope"), &r->scope) ||
        !text_valid(&r->scope))
        return -1;
    if (text_from_json(cJSON_GetObjectItemCaseSensitive(root, "action_urn"),
                       &r->action_urn) ||
        !text_valid(&r->action_urn))
        return -1;
    if (r->version != MHG_RESOURCE_VERSION || !r->resource_generation ||
        !r->spec_generation || r->stage > MHG_RESOURCE_STAGE_READY)
        return -1;
    if (r->stage == MHG_RESOURCE_STAGE_READY &&
        (r->seed_state != MHG_RESOURCE_SEED_VERIFIED ||
         r->global_seed_state != MHG_RESOURCE_SEED_VERIFIED))
        return -1;
    return parse_ids(cJSON_GetObjectItemCaseSensitive(root, "local_variables"),
                     r->local_variables, MHG_PRESENCE_SLOT_COUNT) ||
                   parse_ids(cJSON_GetObjectItemCaseSensitive(root, "global_variables"),
                             r->global_variables, MHG_PRESENCE_SLOT_COUNT)
               ? -1
               : 0;
}
static int parse_record_bytes(const char *text, size_t length,
                              struct mhg_resource_record *record)
{
    cJSON *root;
    int status;

    root = mhg_secret_json_parse_len((const unsigned char *)text, length);
    status = root ? parse_record(root, record) : -1;
    mhg_secret_json_delete(root);
    return status;
}

int mhg_resource_store_load(const char *path, struct mhg_resource_record *record)
{
    struct mhg_resource_record parsed = MHG_RESOURCE_RECORD_INIT;
    char *text = NULL;
    size_t length = 0u;
    int status;
    int result = MHG_RESOURCE_STORE_ERROR;

    if (record)
        mhg_resource_record_clear(record);
    if (!path || !record) {
        errno = EINVAL;
        return MHG_RESOURCE_STORE_ERROR;
    }
    status = read_file(path, &text, &length);
    if (status != 0)
        return status == 1 ? MHG_RESOURCE_STORE_ABSENT : MHG_RESOURCE_STORE_ERROR;
    if (parse_record_bytes(text, length, &parsed) != 0) {
        errno = EPROTO;
        goto done;
    }
    *record = parsed;
    parsed = (struct mhg_resource_record)MHG_RESOURCE_RECORD_INIT;
    result = MHG_RESOURCE_STORE_PRESENT;

done:
    if (text) {
        mhg_secure_clear(text, length);
        free(text);
    }
    mhg_resource_record_clear(&parsed);
    return result;
}

static int install_record(const char *path, const char *json,
                          const struct mhg_resource_record *record)
{
    char directory[PATH_MAX];
    const char *leaf = NULL;
    struct resource_sidecars sidecars;
    struct mhg_resource_record readback = MHG_RESOURCE_RECORD_INIT;
    char *readback_text = NULL;
    size_t length = strlen(json);
    size_t readback_length = 0u;
    size_t offset = 0u;
    int dir_fd = -1;
    int file_fd = -1;
    int result = MHG_RESOURCE_STORE_FAILED;

    if (split_path(path, directory, &leaf) != 0 ||
        sidecars_for_leaf(leaf, &sidecars) != 0)
        return MHG_RESOURCE_STORE_FAILED;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0)
        return MHG_RESOURCE_STORE_FAILED;
    file_fd = openat(dir_fd, sidecars.next,
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file_fd < 0)
        goto done;
    while (offset < length) {
        ssize_t wrote = write(file_fd, json + offset, length - offset);

        if (wrote > 0)
            offset += (size_t)wrote;
        else if (wrote < 0 && errno == EINTR)
            continue;
        else
            goto done;
    }
    if (fsync(file_fd) != 0)
        goto done;
    if (close(file_fd) != 0) {
        file_fd = -1;
        goto done;
    }
    file_fd = -1;
    if (renameat(dir_fd, sidecars.next, dir_fd, leaf) != 0)
        goto done;
    if (read_file(path, &readback_text, &readback_length) != 0 ||
        readback_length != length || memcmp(readback_text, json, length) != 0 ||
        mhg_resource_store_load(path, &readback) != MHG_RESOURCE_STORE_PRESENT ||
        readback.version != record->version ||
        readback.resource_generation != record->resource_generation ||
        readback.stage != record->stage) {
        goto done;
    }
    result = fsync(dir_fd) != 0 ? MHG_RESOURCE_STORE_COMMITTED_NOT_DURABLE
                                : MHG_RESOURCE_STORE_COMMITTED_DURABLE;

done:
    if (readback_text) {
        mhg_secure_clear(readback_text, readback_length);
        free(readback_text);
    }
    mhg_resource_record_clear(&readback);
    if (file_fd >= 0)
        close(file_fd);
    if (result == MHG_RESOURCE_STORE_FAILED)
        (void)unlinkat(dir_fd, sidecars.next, 0);
    if (dir_fd >= 0)
        close(dir_fd);
    return result;
}

static int append_ids(cJSON *array, const struct mhg_secret_buf *ids, size_t count)
{
    size_t index;

    for (index = 0u; index < count; ++index) {
        cJSON *value;

        if (!text_valid(&ids[index]))
            return -1;
        value = cJSON_CreateString((const char *)ids[index].data);
        if (!value)
            return -1;
        if (!cJSON_AddItemToArray(array, value)) {
            cJSON_Delete(value);
            return -1;
        }
    }
    return 0;
}

static cJSON *render_record(const struct mhg_resource_record *r)
{
    cJSON *root = cJSON_CreateObject();
    if (!r || !root)
        goto fail;
    if (!cJSON_AddNumberToObject(root, "version", (double)r->version))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "resource_generation",
                                 (double)r->resource_generation))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "spec_generation", (double)r->spec_generation))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "config_generation",
                                 (double)r->config_generation))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "stage", (double)r->stage))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "seed_state", (double)r->seed_state))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "global_seed_state",
                                 (double)r->global_seed_state))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "action_siid", (double)r->action_siid))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "action_aiid", (double)r->action_aiid))
        goto fail;
    if (!cJSON_AddNumberToObject(root, "action_piid", (double)r->action_piid))
        goto fail;
    if (!text_valid(&r->digest) ||
        !cJSON_AddStringToObject(root, "digest", (const char *)r->digest.data))
        goto fail;
    if (!text_valid(&r->target_did) ||
        !cJSON_AddStringToObject(root, "target_did", (const char *)r->target_did.data))
        goto fail;
    if (!text_valid(&r->target_model) ||
        !cJSON_AddStringToObject(root, "target_model",
                                 (const char *)r->target_model.data))
        goto fail;
    if (!text_valid(&r->graph_id) ||
        !cJSON_AddStringToObject(root, "graph_id", (const char *)r->graph_id.data))
        goto fail;
    if (!text_valid(&r->scope) ||
        !cJSON_AddStringToObject(root, "scope", (const char *)r->scope.data))
        goto fail;
    if (!text_valid(&r->action_urn) ||
        !cJSON_AddStringToObject(root, "action_urn", (const char *)r->action_urn.data))
        goto fail;
    if (append_ids(cJSON_AddArrayToObject(root, "local_variables"), r->local_variables,
                   MHG_PRESENCE_SLOT_COUNT) ||
        append_ids(cJSON_AddArrayToObject(root, "global_variables"),
                   r->global_variables, MHG_PRESENCE_SLOT_COUNT))
        goto fail;
    return root;
fail:
    cJSON_Delete(root);
    return NULL;
}
int mhg_resource_store_commit(const char *path,
                              const struct mhg_resource_record *record)
{
    cJSON *root = NULL;
    char *json = NULL;
    struct mhg_resource_record validated = MHG_RESOURCE_RECORD_INIT;
    int result = MHG_RESOURCE_STORE_FAILED;

    if (!path || !record) {
        errno = EINVAL;
        return MHG_RESOURCE_STORE_FAILED;
    }
    root = render_record(record);
    if (!root || parse_record(root, &validated) != 0 ||
        validated.version != record->version)
        goto done;
    json = cJSON_PrintUnformatted(root);
    if (!json || strlen(json) > MHG_RESOURCE_FILE_LIMIT)
        goto done;
    result = install_record(path, json, record);

done:
    mhg_resource_record_clear(&validated);
    if (json) {
        mhg_secure_clear(json, strlen(json));
        cJSON_free(json);
    }
    cJSON_Delete(root);
    return result;
}

int mhg_resource_store_confirm_durable(const char *path,
                                       const struct mhg_resource_record *expected)
{
    struct mhg_resource_record current = MHG_RESOURCE_RECORD_INIT;
    char directory[PATH_MAX];
    const char *leaf = NULL;
    cJSON *expected_json = NULL;
    cJSON *current_json = NULL;
    int dir_fd = -1;
    int file_fd = -1;
    int status = -1;

    if (!expected || split_path(path, directory, &leaf) != 0)
        return -1;
    expected_json = render_record(expected);
    if (!expected_json)
        goto done;
    dir_fd = open_private_directory(directory);
    if (dir_fd < 0)
        goto done;
    file_fd = openat(dir_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0 || fsync(file_fd) != 0 || fsync(dir_fd) != 0 ||
        mhg_resource_store_load(path, &current) != MHG_RESOURCE_STORE_PRESENT)
        goto done;
    current_json = render_record(&current);
    if (current_json && cJSON_Compare(expected_json, current_json, 1))
        status = 0;
done:
    if (file_fd >= 0)
        close(file_fd);
    if (dir_fd >= 0)
        close(dir_fd);
    cJSON_Delete(current_json);
    cJSON_Delete(expected_json);
    mhg_resource_record_clear(&current);
    return status;
}

int mhg_resource_store_clear(const char *path)
{
    char directory[PATH_MAX];
    const char *leaf = NULL;
    struct resource_sidecars sidecars;
    if (split_path(path, directory, &leaf) || sidecars_for_leaf(leaf, &sidecars))
        return -1;
    int fd = open_private_directory(directory);
    if (fd < 0)
        return -1;
    int result = 0;
    if ((unlinkat(fd, leaf, 0) && errno != ENOENT) ||
        (unlinkat(fd, sidecars.next, 0) && errno != ENOENT) || fsync(fd))
        result = -1;
    close(fd);
    return result;
}
