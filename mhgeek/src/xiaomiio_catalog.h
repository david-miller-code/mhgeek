#ifndef MHGEEK_XIAOMIIO_CATALOG_H
#define MHGEEK_XIAOMIIO_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cloud_http.h"
#include "xiaomi_service.h"

/* The encrypted account directory. One owner serves the xiaomiio side only: it
 * carries the xiaomiio session into the signed request, decrypts the response
 * and publishes an owned snapshot that keeps every `accessKey` in memory. */
struct mhg_catalog_config {
    struct mhg_cloud_http_config http;
    /* Total monotonic deadline for one complete directory refresh. */
    unsigned long refresh_timeout_ms;
};

#define MHG_CATALOG_CONFIG_INIT {MHG_CLOUD_HTTP_CONFIG_INIT, 120000ul}

enum mhg_catalog_match {
    MHG_CATALOG_MATCH_NONE = 0,
    MHG_CATALOG_MATCH_UNIQUE = 1,
    /* More than one owned device answered to the same address; the target is
     * ambiguous and the caller must stop instead of choosing one. */
    MHG_CATALOG_MATCH_MULTIPLE = 2,
};

struct mhg_catalog_snapshot {
    uint64_t directory_generation;
    size_t device_count;
    /* Entries the account answered with but this plugin could not use (missing
     * or mistyped did). They are counted, never guessed. */
    size_t devices_skipped;
    const struct mhg_catalog_device *devices;
};

struct mhg_catalog_stats {
    uint64_t refreshes;
    uint64_t pages_fetched;
    uint64_t directory_generation;
    uint64_t last_http_status;
    uint64_t http_requests;
    /* Unusable entries skipped across the published walk. */
    uint64_t entries_skipped;
    /* Repeated DIDs observed during a completed walk. */
    uint64_t duplicates;
    /* DIDs removed because two nonempty models disagreed. */
    uint64_t identity_conflicts;
    enum mhg_cloud_error last_error;
};

#define MHG_CATALOG_STATS_INIT {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, MHG_CLOUD_OK}

struct mhg_catalog;

int mhg_catalog_create(struct mhg_catalog **owner_out,
                       const struct mhg_catalog_config *config);
void mhg_catalog_destroy(struct mhg_catalog *owner);

/* Fetches every page of the xiaomiio directory and publishes the snapshot
 * only when all of them parsed. A failure leaves the previously published
 * snapshot in place and its generation unchanged. */
enum mhg_cloud_error mhg_catalog_refresh(
    struct mhg_catalog *owner, const struct mhg_service_session *session);

/* The published snapshot, or NULL when nothing is published. The pointer is
 * borrowed: it stays readable until the next refresh or invalidate of the same
 * owner, and every `accessKey` inside it lives only in memory. */
const struct mhg_catalog_snapshot *mhg_catalog_current(
    const struct mhg_catalog *owner);
/* Drops the snapshot and its accessKeys without touching the generation, the
 * account or the other SID's session. */
void mhg_catalog_invalidate(struct mhg_catalog *owner);

/* Byte-exact `localip` lookup over the published snapshot. */
enum mhg_catalog_match mhg_catalog_match_local_ip(
    const struct mhg_catalog_snapshot *snapshot, const char *local_ip,
    const struct mhg_catalog_device **unique_out);

void mhg_catalog_stats_get(const struct mhg_catalog *owner,
                           struct mhg_catalog_stats *stats);

#endif
