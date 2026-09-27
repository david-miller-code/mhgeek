#include "xiaomiio_catalog.h"
#include "https_client.h"

#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct mhg_catalog {
    struct mhg_cloud_http *http;
    struct mhg_catalog_config config;
    pthread_mutex_t lock;
    struct mhg_catalog_snapshot snapshot;
    struct mhg_catalog_device *devices;
    size_t device_capacity;
    bool published;
    struct mhg_catalog_stats stats;
};

static void devices_clear(struct mhg_catalog_device *devices, size_t count,
                          size_t capacity)
{
    size_t index;
    if (!devices) return;
    for (index = 0u; index < count; ++index) {
        mhg_secret_buf_clear(&devices[index].did);
        mhg_secret_buf_clear(&devices[index].model);
        mhg_secret_buf_clear(&devices[index].local_ip);
        mhg_secret_buf_clear(&devices[index].token);
    }
    OPENSSL_clear_free(devices, capacity * sizeof(*devices));
}

static void snapshot_clear(struct mhg_catalog *owner)
{
    devices_clear(owner->devices, owner->snapshot.device_count,
                  owner->device_capacity);
    owner->devices = NULL;
    owner->device_capacity = 0u;
    owner->snapshot.directory_generation = owner->stats.directory_generation;
    owner->snapshot.device_count = 0u;
    owner->snapshot.devices_skipped = 0u;
    owner->snapshot.devices = NULL;
    owner->published = false;
}

int mhg_catalog_create(struct mhg_catalog **owner_out,
                       const struct mhg_catalog_config *config)
{
    struct mhg_catalog *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || config->refresh_timeout_ms == 0u) return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->config = *config;
    owner->stats.last_error = MHG_CLOUD_OK;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return -1;
    }
    if (mhg_cloud_http_create(&owner->http, MHG_XIAOMI_SID_XIAOMIIO,
                              &config->http) != 0) {
        pthread_mutex_destroy(&owner->lock);
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_catalog_destroy(struct mhg_catalog *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    snapshot_clear(owner);
    mhg_cloud_http_destroy(owner->http);
    pthread_mutex_unlock(&owner->lock);
    pthread_mutex_destroy(&owner->lock);
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

static bool buf_equal(const struct mhg_secret_buf *left,
                      const struct mhg_secret_buf *right)
{
    if (left->len != right->len) return false;
    if (left->len == 0u) return true;
    if (!left->data || !right->data) return false;
    return memcmp(left->data, right->data, left->len) == 0;
}

/* Prefer a known model, then the more complete LAN record; ties use the
 * later observation. Every selection moves one whole record, never credentials
 * assembled from different observations. */
static unsigned completeness(const struct mhg_catalog_device *device)
{
    return (device->model.len ? 4u : 0u) +
           (device->local_ip.len ? 1u : 0u) + (device->token.len ? 1u : 0u);
}

static enum mhg_cloud_error append_page(
    struct mhg_catalog_device **devices, size_t *count, size_t *capacity,
    const struct mhg_catalog_page *page, size_t *duplicates,
    size_t **conflicts, size_t *conflict_count)
{
    size_t index;

    if (page->device_count == 0u) return MHG_CLOUD_OK;
    if (!devices || !count || !capacity ||
        page->device_count > SIZE_MAX - *count)
        return MHG_CLOUD_INTERNAL;
    if (*count + page->device_count > *capacity) {
        size_t wanted = *capacity ? *capacity : 8u;
        struct mhg_catalog_device *grown;
        while (wanted < *count + page->device_count) {
            if (wanted > SIZE_MAX / 2u) return MHG_CLOUD_INTERNAL;
            wanted *= 2u;
        }
        if (wanted > SIZE_MAX / sizeof(*grown)) return MHG_CLOUD_INTERNAL;
        grown = OPENSSL_realloc(*devices, wanted * sizeof(*grown));
        if (!grown) return MHG_CLOUD_INTERNAL;
        memset(grown + *capacity, 0,
               (wanted - *capacity) * sizeof(*grown));
        *devices = grown;
        *capacity = wanted;
    }
    for (index = 0u; index < page->device_count; ++index) {
        struct mhg_catalog_device *source =
            (struct mhg_catalog_device *)&page->devices[index];
        size_t seen;

        /* The DID is the device identity. A page boundary that shifts while
         * the account is being edited can repeat the same device; keep the
         * fresher record instead of publishing the same device twice. */
        for (seen = 0u; seen < *count; ++seen) {
            const struct mhg_secret_buf *known = &(*devices)[seen].did;

            if (known->len != 0u && known->len == source->did.len &&
                source->did.data && known->data &&
                memcmp(known->data, source->did.data, known->len) == 0)
                break;
        }
        if (seen < *count) {
            struct mhg_catalog_device *previous = &(*devices)[seen];

            size_t conflict;
            if (duplicates) *duplicates += 1u;
            for (conflict = 0u; conflict < *conflict_count; ++conflict)
                if ((*conflicts)[conflict] == seen) break;
            if (conflict < *conflict_count) continue;
            if (previous->model.len && source->model.len &&
                !buf_equal(&previous->model, &source->model)) {
                size_t *grown;
                if (*conflict_count == SIZE_MAX / sizeof(*grown))
                    return MHG_CLOUD_INTERNAL;
                grown = realloc(*conflicts, (*conflict_count + 1u) * sizeof(*grown));
                if (!grown) return MHG_CLOUD_INTERNAL;
                *conflicts = grown;
                (*conflicts)[(*conflict_count)++] = seen;
                continue;
            }
            if (completeness(source) < completeness(previous)) continue;
            mhg_secret_buf_clear(&previous->did);
            mhg_secret_buf_clear(&previous->model);
            mhg_secret_buf_clear(&previous->local_ip);
            mhg_secret_buf_clear(&previous->token);
            *previous = *source;
            *source = (struct mhg_catalog_device)MHG_CATALOG_DEVICE_INIT;
            continue;
        }
        (*devices)[*count] = *source;
        *source = (struct mhg_catalog_device)MHG_CATALOG_DEVICE_INIT;
        *count += 1u;
    }
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_catalog_refresh(
    struct mhg_catalog *owner, const struct mhg_service_session *session)
{
    struct mhg_cloud_http_result result_data = MHG_CLOUD_HTTP_RESULT_INIT;
    struct mhg_secret_buf params = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cursor = MHG_SECRET_BUF_INIT;
    struct mhg_catalog_device *devices = NULL;
    struct mhg_secret_buf *cursors = NULL;
    size_t cursor_count = 0u;
    size_t *conflicts = NULL;
    size_t conflict_count = 0u;
    uint64_t deadline;
    size_t device_count = 0u;
    size_t capacity = 0u;
    size_t pages = 0u;
    size_t skipped = 0u;
    size_t duplicates = 0u;
    bool more = true;
    enum mhg_cloud_error result;

    if (!owner) return MHG_CLOUD_INPUT;
    if (!session || session->sid != MHG_XIAOMI_SID_XIAOMIIO)
        return session ? MHG_CLOUD_SID_MISMATCH : MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    deadline = mhg_https_now_ms() + owner->config.refresh_timeout_ms;
    owner->stats.refreshes++;
    owner->stats.last_error = MHG_CLOUD_OK;
    while (more) {
        struct mhg_cloud_http_work work = MHG_CLOUD_HTTP_WORK_INIT;
        struct mhg_catalog_page page = MHG_CATALOG_PAGE_INIT;
        struct mhg_cloud_http_stats http_stats = MHG_CLOUD_HTTP_STATS_INIT;

        if (mhg_https_now_ms() >= deadline) {
            result = MHG_CLOUD_NETWORK;
            goto out;
        }
        if (pages == 0u) {
            result = mhg_secret_buf_set(&params, mhg_catalog_initial_params(),
                                        strlen(mhg_catalog_initial_params())) ==
                     0 ? MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
        } else {
            result = mhg_catalog_next_params((const char *)cursor.data,
                                             &params);
        }
        if (result != MHG_CLOUD_OK) goto out;
        result = mhg_cloud_http_work_catalog(
            &work, session, (const char *)params.data);
        if (result != MHG_CLOUD_OK) goto out;
        result = mhg_cloud_http_execute_deadline(owner->http, &work, &result_data, deadline);
        mhg_cloud_http_stats_get(owner->http, &http_stats);
        owner->stats.http_requests = http_stats.total_requests;
        owner->stats.last_http_status =
            http_stats.last_http_status < 0 ? 0u :
            (uint64_t)http_stats.last_http_status;
        mhg_cloud_http_work_clear(&work);
        if (result != MHG_CLOUD_OK) goto out;
        pages++;
        owner->stats.pages_fetched++;
        result = mhg_catalog_parse_page(
            session,
            MHG_BYTES_VIEW(result_data.envelope.result_json.data,
                           result_data.envelope.result_json.len),
            &page);
        if (result != MHG_CLOUD_OK) goto out;
        skipped += page.skipped;
        result = append_page(&devices, &device_count, &capacity, &page,
                             &duplicates, &conflicts, &conflict_count);
        more = page.has_more && result == MHG_CLOUD_OK;
        if (result == MHG_CLOUD_OK && more) {
            size_t seen;
            for (seen = 0u; seen < cursor_count; ++seen)
                if (buf_equal(&cursors[seen], &page.next_start_did)) break;
            if (seen != cursor_count) {
                result = MHG_CLOUD_MALFORMED;
            } else if (cursor_count == SIZE_MAX / sizeof(*cursors)) {
                result = MHG_CLOUD_INTERNAL;
            } else {
                struct mhg_secret_buf *grown = realloc(cursors,
                    (cursor_count + 1u) * sizeof(*cursors));
                if (!grown) result = MHG_CLOUD_INTERNAL;
                else {
                    cursors = grown;
                    cursors[cursor_count++] = page.next_start_did;
                    page.next_start_did = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
                    if (mhg_secret_buf_set(&cursor, cursors[cursor_count - 1u].data,
                                          cursors[cursor_count - 1u].len) != 0)
                        result = MHG_CLOUD_INTERNAL;
                }
            }
        }
        mhg_catalog_page_clear(&page);
        mhg_cloud_http_result_clear(&result_data);
        if (result != MHG_CLOUD_OK) goto out;
    }
    if (mhg_https_now_ms() >= deadline) {
        result = MHG_CLOUD_NETWORK;
        goto out;
    }
    /* Keep conflicting identities out of the published snapshot, including
     * later repetitions of the DID during this same walk. */
    size_t write_index = 0u;
    for (size_t read_index = 0u; read_index < device_count; ++read_index) {
        size_t conflict;
        for (conflict = 0u; conflict < conflict_count; ++conflict)
            if (conflicts[conflict] == read_index) break;
        if (conflict != conflict_count) {
            mhg_secret_buf_clear(&devices[read_index].did);
            mhg_secret_buf_clear(&devices[read_index].model);
            mhg_secret_buf_clear(&devices[read_index].local_ip);
            mhg_secret_buf_clear(&devices[read_index].token);
        } else {
            if (write_index != read_index) devices[write_index] = devices[read_index];
            ++write_index;
        }
    }
    device_count = write_index;
    skipped += conflict_count;
    snapshot_clear(owner);
    owner->stats.identity_conflicts += conflict_count;
    owner->stats.directory_generation++;
    owner->devices = devices;
    owner->device_capacity = capacity;
    owner->stats.entries_skipped += skipped;
    owner->stats.duplicates += duplicates;
    owner->snapshot.directory_generation = owner->stats.directory_generation;
    owner->snapshot.device_count = device_count;
    owner->snapshot.devices_skipped = skipped;
    owner->snapshot.devices = owner->devices;
    owner->published = true;
    devices = NULL;
    device_count = 0u;
    capacity = 0u;
    result = MHG_CLOUD_OK;

out:
    for (size_t index = 0u; index < cursor_count; ++index)
        mhg_secret_buf_clear(&cursors[index]);
    free(cursors);
    free(conflicts);
    devices_clear(devices, device_count, capacity);
    owner->stats.last_error = result;
    mhg_cloud_http_result_clear(&result_data);
    mhg_secret_buf_clear(&params);
    mhg_secret_buf_clear(&cursor);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

const struct mhg_catalog_snapshot *mhg_catalog_current(
    const struct mhg_catalog *owner)
{
    return owner && owner->published ? &owner->snapshot : NULL;
}

void mhg_catalog_invalidate(struct mhg_catalog *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    snapshot_clear(owner);
    pthread_mutex_unlock(&owner->lock);
}

enum mhg_catalog_match mhg_catalog_match_local_ip(
    const struct mhg_catalog_snapshot *snapshot, const char *local_ip,
    const struct mhg_catalog_device **unique_out)
{
    enum mhg_catalog_match match = MHG_CATALOG_MATCH_NONE;
    size_t index;

    if (unique_out) *unique_out = NULL;
    if (!snapshot || !local_ip || !local_ip[0]) return MHG_CATALOG_MATCH_NONE;
    for (index = 0u; index < snapshot->device_count; ++index) {
        const struct mhg_catalog_device *device = &snapshot->devices[index];
        if (!device->local_ip.data || !device->local_ip.len) continue;
        if (device->local_ip.len != strlen(local_ip) ||
            memcmp(device->local_ip.data, local_ip, device->local_ip.len) != 0)
            continue;
        if (match == MHG_CATALOG_MATCH_UNIQUE) {
            if (unique_out) *unique_out = NULL;
            return MHG_CATALOG_MATCH_MULTIPLE;
        }
        match = MHG_CATALOG_MATCH_UNIQUE;
        if (unique_out) *unique_out = device;
    }
    return match;
}

void mhg_catalog_stats_get(const struct mhg_catalog *owner,
                           struct mhg_catalog_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_catalog_stats)
        MHG_CATALOG_STATS_INIT;
}
