#ifndef MHGEEK_CLOUD_HTTP_H
#define MHGEEK_CLOUD_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cloud_crypto.h"
#include "mijia_core.h"
#include "xiaomi_service.h"

/* One owner instance serves exactly one SID and owns its libcurl handle, its
 * PassportDeviceId value and its request buffers. The catalog endpoint is a
 * xiaomiio request and the core endpoint is a mijia request; a work item whose
 * session SID does not match the owner is rejected before any I/O. */
struct mhg_cloud_http_config {
    /* NULL selects the production endpoints. Overrides must still use HTTPS
     * and are intended for a loopback test prefix on the same host. */
    const char *catalog_base_url;
    const char *core_base_url;
    const char *ca_info;
    unsigned long connect_timeout_ms;
    unsigned long total_timeout_ms;
    size_t response_limit;
    bool allow_system_proxy;
#ifdef MHG_CLOUD_HTTP_TESTING
    /* libcurl CONNECT_TO syntax. Test-only so production cannot redirect a
     * trusted cloud hostname to another peer. */
    const char *catalog_connect_to;
    const char *core_connect_to;
#endif
};

#define MHG_CLOUD_HTTP_CONFIG_INIT \
    {NULL, NULL, NULL, 10000ul, 30000ul, 262144u, true \
     MHG_CLOUD_HTTP_CONFIG_TEST_INIT}
#ifdef MHG_CLOUD_HTTP_TESTING
#define MHG_CLOUD_HTTP_CONFIG_TEST_INIT , NULL, NULL
#else
#define MHG_CLOUD_HTTP_CONFIG_TEST_INIT
#endif

enum mhg_cloud_http_kind {
    MHG_CLOUD_HTTP_CATALOG = 1,
    MHG_CLOUD_HTTP_CORE = 2,
};

struct mhg_cloud_http_work {
    enum mhg_cloud_http_kind kind;
    /* Owned copy of the exact session the request was built for. */
    struct mhg_service_session session;
    /* Owned request `data` JSON: catalog params or mijia core data. */
    struct mhg_secret_buf data_json;
    /* Core requests only: canonical path DID and MIOT-REQUEST-MODEL. */
    struct mhg_secret_buf did;
    struct mhg_secret_buf model;
};

#define MHG_CLOUD_HTTP_WORK_INIT \
    {MHG_CLOUD_HTTP_CATALOG, MHG_SERVICE_SESSION_INIT, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

struct mhg_cloud_http_result {
    struct mhg_cloud_envelope envelope;
    long http_status;
};

#define MHG_CLOUD_HTTP_RESULT_INIT {MHG_CLOUD_ENVELOPE_INIT, 0}

struct mhg_cloud_http_stats {
    uint64_t total_requests;
    long last_http_status;
    enum mhg_cloud_error last_error;
};

#define MHG_CLOUD_HTTP_STATS_INIT {0u, 0, MHG_CLOUD_OK}

struct mhg_cloud_http;

/* Struct and buffer outputs must start at the matching INIT value. Public
 * writers clear reusable outputs on entry and leave them empty on failure. */

int mhg_cloud_http_create(struct mhg_cloud_http **owner_out,
                          enum mhg_xiaomi_sid sid,
                          const struct mhg_cloud_http_config *config);
void mhg_cloud_http_destroy(struct mhg_cloud_http *owner);

/* Builds the two supported work shapes so callers cannot hand-assemble a data
 * blob, cookie set or header profile. */
enum mhg_cloud_error mhg_cloud_http_work_catalog(
    struct mhg_cloud_http_work *work, const struct mhg_service_session *session,
    const char *params_json);
enum mhg_cloud_error mhg_cloud_http_work_core(
    struct mhg_cloud_http_work *work, const struct mhg_service_session *session,
    enum mhg_core_method method, uint64_t id, const char *access_key,
    const char *did, const char *model);
void mhg_cloud_http_work_clear(struct mhg_cloud_http_work *work);

/* Executes one immutable typed work item synchronously. The result is written
 * only on MHG_CLOUD_OK; every other return leaves the envelope empty. */
enum mhg_cloud_error mhg_cloud_http_execute(
    struct mhg_cloud_http *owner, const struct mhg_cloud_http_work *work,
    struct mhg_cloud_http_result *result);
/* Absolute monotonic millisecond deadline; zero uses the request timeout. */
enum mhg_cloud_error mhg_cloud_http_execute_deadline(
    struct mhg_cloud_http *owner, const struct mhg_cloud_http_work *work,
    struct mhg_cloud_http_result *result, uint64_t deadline);
void mhg_cloud_http_result_clear(struct mhg_cloud_http_result *result);
void mhg_cloud_http_stats_get(const struct mhg_cloud_http *owner,
                              struct mhg_cloud_http_stats *stats);
const char *mhg_cloud_http_kind_name(enum mhg_cloud_http_kind kind);

#endif
