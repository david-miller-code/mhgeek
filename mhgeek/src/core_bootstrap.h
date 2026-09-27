#ifndef MHGEEK_CORE_BOOTSTRAP_H
#define MHGEEK_CORE_BOOTSTRAP_H

#include <stddef.h>
#include <stdint.h>

#include "cloud_http.h"
#include "mijia_core.h"
#include "xiaomi_service.h"

/* The cloud half of the capability probe. For one catalog-matched target it
 * runs both `mijia` core RPCs and returns their short-lived answers in memory:
 * the Web URL must address the configured LAN host byte-for-byte, and the
 * dynamic code is only handed to the caller that opens the LAN session. */
struct mhg_bootstrap_config {
    /* The `mijia` side of the cloud owner; the catalog owner holds its own. */
    struct mhg_cloud_http_config http;
};

#define MHG_BOOTSTRAP_CONFIG_INIT {MHG_CLOUD_HTTP_CONFIG_INIT}

struct mhg_bootstrap_target {
    /* Taken from the published catalog snapshot: DID, model and that entry's
     * `accessKey`. */
    const char *did;
    const char *model;
    const char *access_key;
    /* The LAN address the user configured for the target. */
    const char *expected_host;
};

struct mhg_bootstrap_evidence {
    /* Increments once per successful probe; the LAN stage binds its session to
     * this generation so an older URL or code can never be reused. */
    uint64_t bootstrap_generation;
    struct mhg_secret_buf url;
    struct mhg_secret_buf passcode;
};

#define MHG_BOOTSTRAP_EVIDENCE_INIT \
    {0u, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

struct mhg_bootstrap_stats {
    uint64_t runs;
    uint64_t http_requests;
    uint64_t last_http_status;
    uint64_t bootstrap_generation;
    /* How many runs were answered with the passcode of the previous run.
     * Nonsecret: only the equality is counted, never the value. A repeat means
     * the cloud is not rotating the code per call, which is what a hub that
     * refuses writes on a "consumed" code would need. */
    uint64_t passcode_repeats;
    enum mhg_cloud_error last_error;
    /* The fixed nonsecret provider code of the last run that a provider
     * rejection stopped (`MHG_CLOUD_SERVICE`), so a caller can tell a refused
     * `accessKey` from an offline device instead of only seeing "service".
     * Zero whenever the last run was not stopped that way. */
    int last_provider_code;
};

#define MHG_BOOTSTRAP_STATS_INIT {0u, 0u, 0u, 0u, 0u, MHG_CLOUD_OK, 0}

struct mhg_bootstrap;

int mhg_bootstrap_create(struct mhg_bootstrap **owner_out,
                         const struct mhg_bootstrap_config *config);
void mhg_bootstrap_destroy(struct mhg_bootstrap *owner);

/* Runs the two RPCs in order, each with its own request id. MHG_CLOUD_OK is
 * returned only when both answered, the Web URL host equals
 * `expected_host` and the passcode is six digits; every other return leaves
 * `evidence` empty and never asks for the passcode of a rejected target. */
enum mhg_cloud_error mhg_bootstrap_run(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target,
    struct mhg_bootstrap_evidence *evidence);
/* Candidate selection probes only the URL. Finish consumes the selected URL
 * and requests one passcode after uniqueness has been established. Deadline
 * is absolute monotonic milliseconds; zero uses the per-request timeout. */
enum mhg_cloud_error mhg_bootstrap_probe_url(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target, struct mhg_secret_buf *url,
    uint64_t deadline);
enum mhg_cloud_error mhg_bootstrap_finish(
    struct mhg_bootstrap *owner, const struct mhg_service_session *session,
    const struct mhg_bootstrap_target *target, struct mhg_secret_buf *url,
    struct mhg_bootstrap_evidence *evidence);
void mhg_bootstrap_evidence_clear(struct mhg_bootstrap_evidence *evidence);

/* True when `url` is an absolute http/https URL, without userinfo, fragment
 * or bracketed host, whose authority host is exactly `host`. */

void mhg_bootstrap_stats_get(const struct mhg_bootstrap *owner,
                             struct mhg_bootstrap_stats *stats);

#endif
