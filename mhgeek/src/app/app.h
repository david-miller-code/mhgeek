#ifndef MHGEEK_APP_H
#define MHGEEK_APP_H

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stddef.h>

#include "ainice/bridge.h"
#include "auth_sms.h"
#include "operations.h"
#include "event_config_store.h"
#include "presence_delivery.h"
#include "presence_source.h"
#include "resource_store.h"
#include "resource_sync.h"
#include "runtime.h"
#include "target_resolver.h"
#include "target_store.h"
#include "xiaomiio_catalog.h"

/* The mhgeek plugin process :
 *
 *   mhgeek.app
 *     - one 30ms scheduler lane owning the runtime: gate, cloud, LAN,
 *       resources, presence hand-off and event delivery;
 *     - one blocking SUBSYS presence subscription thread (the SDK never
 *       reconnects on its own, so the thread resubscribes until stop);
 *     - one Bridge module `mhgeek` serving the routes.
 *
 * The routes only render state and queue actions; they never touch the LAN
 * session or the delivery owner directly. */

#define MHG_APP_MODULE "mhgeek"
#define MHG_APP_ROOT_DEFAULT "/plugins/mhgeek"
#define MHG_APP_DATA_DEFAULT "/data/plugins/mhgeek"
#define MHG_APP_RESPONSE_MAX (256u * 1024u)
#define MHG_APP_BRIDGE_JSON_TIMEOUT_MS 1000u

/* One frontend action, executed by the scheduler thread (the Bridge never
 * blocks on the cloud or the LAN session). */
/* Published configuration and explicit repair progress. */
enum mhg_app_maintenance_state {
    MHG_APP_MAINTENANCE_NONE = 0,
    MHG_APP_MAINTENANCE_PENDING = 1,
    MHG_APP_MAINTENANCE_DONE = 2,
    MHG_APP_MAINTENANCE_FAILED = 3,
};

struct mhg_app_maintenance {
    enum mhg_app_maintenance_state repair;
    enum mhg_app_maintenance_state config;
    enum mhg_cloud_error last_error;
    uint64_t config_generation;
};

/* What the frontend may learn about authorization: the state machine
 * plus stable names, the toast key and a masked account identifier. Never the
 * phone number, code, unmasked account identity or provider payload. */
struct mhg_app_auth_state {
    enum mhg_auth_sms_state state;
    enum mhg_auth_sms_phase phase;
    enum mhg_auth_sms_error error;
    bool has_account;
    uint64_t account_generation;
    uint64_t challenge_generation;
    uint64_t operation_id;
    unsigned int code_length;
    unsigned int retry_after_seconds;
    enum mhg_auth_sms_provider_scope provider_scope;
    enum mhg_auth_sms_provider_class provider_class;
    int provider_code;
    enum mhg_auth_sms_pending_store_outcome pending_store_outcome;
    char state_name[32];
    char phase_name[32];
    char error_name[40];
    char provider_scope_name[24];
    char provider_class_name[40];
    char masked_account_id[32];
    /* Stable toast key: a provider class name, or sms_retry_later for the
     * local throttle; empty when the state carries no dedicated key. */
    char message_key[40];
};

/* Target detail for the local management page. The exact selected DID is
 * exposed only by GET /gateway/target; status snapshots retain masked IDs. */
struct mhg_app_target_state {
    bool configured;
    bool locked;
    enum mhg_target_state state;
    enum mhg_target_outcome outcome;
    enum mhg_cloud_error last_error;
    char ip[MHG_TARGET_IP_LIMIT];
    char did[MHG_TARGET_DID_LIMIT];
    char did_masked[32];
    char model_masked[32];
};

struct mhg_bridge_context {
    /* Immutable request-local views. The application copies its published
     * snapshot under a short lock before calling the route renderer. */
    const struct mhg_runtime_status *status;
    const struct mhg_catalog_stats *catalog;
    const struct mhg_app_target_state *target_view;
    const struct mhg_app_auth_state *auth_view;
    const struct mhg_app_maintenance *maintenance_view;
    size_t catalog_device_count;
    enum mhg_resource_state resource_state;
    /* Bounded, non-secret text of the last LAN attempt failure, so the page can
     * tell "hub unreachable" apart from "wrong passcode". */
    const char *lan_error;
    const char *resource_error;
    const char *config_error;
    const char *const *texts;      /* index slot * 2 + (present ? 0 : 1) */
    const char *prefix;
    const double *absent_seconds;
    uint64_t config_generation;
    uint64_t synced_config_generation;
    /* Queues one action for the scheduler; false means "busy, retry". */
    bool (*enqueue)(void *userdata, struct mhg_app_request *request);
    bool (*operation)(void *userdata, uint64_t id, struct mhg_app_operation *out);
    void (*maintenance_state)(void *userdata,
                              struct mhg_app_maintenance *state);
    void (*auth_state)(void *userdata, struct mhg_app_auth_state *state);
    void *userdata;
};

/* One Bridge request: `{module, method, params}`. Only `route` and `health`
 * exist; everything else is a stable error. */
int mhg_app_bridge_request(const char *request_json,
                           ainice_bridge_response_t *response, void *userdata);

/* Shared helpers for the routes (stable error envelope). */
cJSON *mhg_app_error(int code, const char *message);
int mhg_app_set_json(ainice_bridge_response_t *response, cJSON *root);

/* Route table; returns NULL for an unknown path. */
cJSON *mhg_app_route(struct mhg_bridge_context *context, const char *method,
                     const char *path, cJSON *query, cJSON *body);

#endif
