/* mhgeek plugin process: one 30ms scheduler lane, one
 * SUBSYS presence subscription thread and the Bridge module. */
#define _POSIX_C_SOURCE 200809L

#include "app.h"
#include "bridge_snapshot.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

#include "account_store.h"
#include "auth_sms_executor.h"
#include "auth_sms_file_store.h"
#include "event_config_store.h"
#include "common.h"
#include "emit_lan.h"
#include "lan_owner.h"
#include "resource_lan.h"
#include "resource_sync.h"
#include "spec_action.h"
#include "target_resolver.h"
#include "xiaomi_session.h"

#ifndef MHG_APP_CA_INFO
#define MHG_APP_CA_INFO "/etc/ssl/certs/ca-certificates.crt"
#endif

/* One RPC path for the resource phase: the live LAN session. */
struct app_rpc {
    struct mhg_lan_owner *owner;
    uint64_t generation;
};

struct app {
    const char *data_root;
    const char *ca_info;
    char account_path[4096];
    char target_path[4096];
    char resource_base_path[4096];
    char resource_path[4096];
    struct mhg_account_record account;
    struct mhg_target_record target;
    struct mhg_resource_record record;
    struct mhg_xiaomi_session *io_session;
    struct mhg_xiaomi_session *mijia_session;
    struct mhg_target_resolver *resolver;
    struct mhg_lan_owner *lan;
    struct mhg_resource_lan *resources;
    struct mhg_resource_sync *sync;
    struct mhg_emit_lan *emit;
    struct mhg_delivery *delivery;
    struct mhg_presence_source *presence;
    struct mhg_runtime *runtime;
    struct mhg_bridge_context bridge;
    struct app_rpc rpc;
    bool has_account;
    bool has_target;
    bool spec_ready;
    bool resources_ready;
    int siid;
    int aiid;
    int piid;
    char urn[192];
    struct mhg_app_bridge_publisher published;
    char lan_error[160];
    char resource_error[200];
    char config_error[200];
    /* Hub-side session rejections already consumed by a cloud refresh. */
    uint64_t lan_auth_failures_seen;
    struct mhg_event_config event_config;
    char final_texts[MHG_RESOURCE_VARIABLE_COUNT][MHG_EVENT_PREFIX_LIMIT +
                                               MHG_EVENT_TEXT_LIMIT + 1u];
    const char *final_texts_ptr[MHG_RESOURCE_VARIABLE_COUNT];
    char event_path[4096];
    bool event_config_persisted;
    bool config_recovery_pending;
    uint64_t pending_config_generation;
    uint64_t next_config_recovery_ms;
    struct mhg_auth_sms_file_store auth_file_store;
    struct mhg_auth_sms_store auth_store;
    struct mhg_auth_sms_executor *auth;
    struct mhg_auth_sms_work auth_work;
    struct mhg_app_auth_state auth_state;
    struct mhg_app_maintenance maintenance;
    struct mhg_app_operations operations;
    pthread_t presence_thread;
    pthread_t scheduler_thread;
    bool presence_thread_started;
    bool scheduler_thread_started;
};

static struct app g_app;
static volatile sig_atomic_t g_stop;

static uint64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0u;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)(now.tv_nsec / 1000000L);
}

static uint64_t app_clock(void *userdata)
{
    (void)userdata;
    return monotonic_ms();
}

static void sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
    (void)nanosleep(&delay, NULL);
}

static void on_signal(int number)
{
    (void)number;
    g_stop = 1;
}

/* Same masking rule as the routes: first and last three characters only. */
static void mask_identity(const char *text, char *out, size_t out_size)
{
    size_t length = text ? strlen(text) : 0u;

    if (out_size == 0u) return;
    if (length <= 6u) {
        snprintf(out, out_size, "***");
        return;
    }
    snprintf(out, out_size, "%.3s***%.3s", text, text + length - 3u);
}

static int app_should_stop(void *userdata)
{
    (void)userdata;
    return g_stop != 0;
}

static bool app_resource_path_current(struct app *app)
{
    char selected[sizeof(app->resource_path)];

    return app->resources != NULL &&
           app->target.action_state == MHG_TARGET_ACTION_VERIFIED &&
           mhg_lan_owner_resources_open(app->lan) &&
           mhg_resource_store_select_path(
               app->resource_base_path, &app->target.did, &app->target.model,
               selected, sizeof(selected)) == 0 &&
           strcmp(selected, app->resource_path) == 0;
}

static int lan_call(void *userdata, const char *method, const cJSON *params,
                    cJSON **reply, struct mhg_error *error)
{
    struct app_rpc *rpc = userdata;

    return mhg_lan_owner_call(rpc->owner, rpc->generation, method, params,
                              reply, monotonic_ms(), error);
}

static int lan_end_seed_generation(void *userdata, struct mhg_error *error)
{
    struct app_rpc *rpc = userdata;

    if (!rpc || !rpc->owner)
        return mhg_errorf(error, EINVAL, "seed LAN owner is unavailable");
    /* An old probe must never close a newer connection or authorize a retry
     * marker for that connection. A -10004 may already have ended precisely
     * this captured generation; that is an isolated success. */
    if (mhg_lan_owner_generation(rpc->owner) != rpc->generation)
        return mhg_errorf(error, ESTALE, "seed LAN generation changed");
    if (mhg_lan_owner_state(rpc->owner) == MHG_LAN_ONLINE)
        mhg_lan_owner_end(rpc->owner, rpc->generation,
                          MHG_LAN_END_CANCELLED, monotonic_ms());
    return mhg_lan_owner_state(rpc->owner) == MHG_LAN_ONLINE ?
        mhg_errorf(error, EIO, "seed LAN generation remained online") : 0;
}

static void record_resource_error(struct app *app, const char *stage,
                                  const struct mhg_error *error);

/* Resource and emit owners are bound to one verified LAN generation. A new
 * generation must replay the latest state instead of trusting old ACKs. */
static void app_drop_resource_owners(struct app *app)
{
    mhg_delivery_rebind(app->delivery);
    mhg_emit_lan_destroy(app->emit);
    app->emit = NULL;
    mhg_resource_sync_destroy(app->sync);
    app->sync = NULL;
    mhg_resource_lan_destroy(app->resources);
    app->resources = NULL;
    mhg_resource_record_clear(&app->record);
    app->resources_ready = false;
}

/* --- runtime ops ------------------------------------------------------- */

static int app_gate(void *userdata, enum mhg_runtime_gate *gate,
                    struct mhg_error *error)
{
    struct app *app = userdata;
    struct mhg_target_record fresh = MHG_TARGET_RECORD_INIT;
    int loaded;

    if (!app->has_account) {
        *gate = MHG_RUNTIME_GATE_CREDENTIALS;
        return 0;
    }
    if (mhg_target_resolver_outcome(app->resolver) ==
        MHG_TARGET_OUTCOME_STORE) {
        if (mhg_target_resolver_recover_store(app->resolver) != MHG_CLOUD_OK) {
            *gate = MHG_RUNTIME_GATE_TARGET;
            app->resources_ready = false;
            mhg_errorf(error, EIO, "target store authority is uncertain");
            return 0;
        }
        mhg_runtime_request_recheck(app->runtime);
    }
    /* The target record is re-read on the slow lane, so a frontend save or
     * clear takes effect without restarting the plugin. */
    loaded = mhg_target_store_load(app->target_path, &fresh);
    if (loaded == MHG_TARGET_STORE_PRESENT) {
        mhg_target_record_clear(&app->target);
        app->target = fresh;
        app->has_target = true;
    } else if (loaded == MHG_TARGET_STORE_ABSENT) {
        mhg_target_record_clear(&app->target);
        app->target = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
        app->has_target = false;
    } else {
        mhg_target_record_clear(&fresh);
        mhg_target_record_clear(&app->target);
        app->has_target = false;
        mhg_errorf(error, EIO, "target record is unreadable");
    }
    if (!app->has_target) app->resources_ready = false;
    *gate = app->has_target ? MHG_RUNTIME_GATE_OPEN :
                              MHG_RUNTIME_GATE_TARGET;
    return 0;
}

static void app_lan_service_idle(void *userdata, uint64_t now_ms)
{
    struct app *app = userdata;
    struct mhg_error error = {0};
    cJSON *reply = NULL;
    int ready = 0;

    if (mhg_lan_owner_state(app->lan) != MHG_LAN_ONLINE ||
        mhg_lan_owner_pending(app->lan))
        return;
    /* service() closes a failed generation; the driver then schedules its
     * recovery. Pending replies belong to their caller and must not be read. */
    (void)mhg_lan_owner_service(app->lan, now_ms, &reply, &ready, &error);
    cJSON_Delete(reply);
}

static bool app_lan_connected(void *userdata)
{
    struct app *app = userdata;

    return mhg_lan_owner_resources_open(app->lan) != 0;
}

static uint64_t app_lan_next_attempt(void *userdata, uint64_t now_ms)
{
    struct app *app = userdata;

    (void)now_ms;
    return mhg_lan_owner_next_attempt_ms(app->lan);
}

static void app_lan_snapshot(void *userdata, uint64_t *generation,
                             enum mhg_lan_state *state,
                             enum mhg_lan_binding *binding)
{
    struct app *app = userdata;

    *generation = mhg_lan_owner_generation(app->lan);
    *state = mhg_lan_owner_state(app->lan);
    *binding = mhg_lan_owner_binding(app->lan);
}

/* Both service legs must exist before any cloud work. Establishment is itself
 * a network step, so this only runs on the scheduler thread. */
static int app_ensure_sessions(struct app *app, struct mhg_error *error)
{
    if (mhg_xiaomi_session_current(app->io_session) == NULL &&
        mhg_xiaomi_session_establish(app->io_session,
                                     (const char *)app->account.user_id.data,
                                     (const char *)app->account.pass_token.data) !=
            MHG_CLOUD_OK) {
        mhg_errorf(error, EIO, "xiaomiio session failed");
        return -1;
    }
    if (mhg_xiaomi_session_current(app->mijia_session) == NULL &&
        mhg_xiaomi_session_establish(app->mijia_session,
                                     (const char *)app->account.user_id.data,
                                     (const char *)app->account.pass_token.data) !=
            MHG_CLOUD_OK) {
        mhg_errorf(error, EIO, "mijia session failed");
        return -1;
    }
    return 0;
}

/* An authenticated HTTP rejection invalidates only the service leg that
 * failed. The next normal attempt rebuilds it from the saved account; no SMS
 * or mutation is retried here. */
static void app_cloud_rejected(struct app *app, enum mhg_target_outcome outcome,
                                enum mhg_cloud_error result)
{
    if (result != MHG_CLOUD_AUTH_REJECTED) return;
    if (outcome == MHG_TARGET_OUTCOME_CATALOG)
        mhg_xiaomi_session_invalidate(app->io_session);
    else if (outcome == MHG_TARGET_OUTCOME_PROBE)
        mhg_xiaomi_session_invalidate(app->mijia_session);
}

static int app_cloud_refresh(void *userdata, struct mhg_lan_bootstrap *out,
                             struct mhg_error *error)
{
    struct app *app = userdata;
    const struct mhg_bootstrap_evidence *evidence;
    struct mhg_lan_stats stats = MHG_LAN_STATS_INIT;

    /* A hub -10004 ends the LAN generation. Consume that fact at the refresh
     * boundary, before ensure_sessions(), so scheduler timing cannot reuse
     * the rejected Mijia session or its old bootstrap material. */
    mhg_lan_owner_stats_get(app->lan, &stats);
    if (stats.auth_failures > app->lan_auth_failures_seen) {
        app->lan_auth_failures_seen = stats.auth_failures;
        mhg_xiaomi_session_invalidate(app->mijia_session);
    }
    if (app_ensure_sessions(app, error)) return -1;
    if (mhg_target_resolver_refresh_catalog(
            app->resolver, mhg_xiaomi_session_current(app->io_session)) !=
            MHG_CLOUD_OK ||
        mhg_target_resolver_verify(app->resolver,
                                   mhg_target_resolver_snapshot(app->resolver),
                                   NULL) != MHG_CLOUD_OK ||
        mhg_target_resolver_refresh_bootstrap(
            app->resolver, mhg_target_resolver_snapshot(app->resolver),
            mhg_xiaomi_session_current(app->mijia_session)) != MHG_CLOUD_OK) {
        app_cloud_rejected(app, mhg_target_resolver_outcome(app->resolver),
                            mhg_target_resolver_last_error(app->resolver));
        mhg_errorf(error, EIO, "cloud bootstrap failed (%s)",
                   mhg_cloud_error_name(
                       mhg_target_resolver_last_error(app->resolver)));
        return -1;
    }
    if (mhg_target_record_clone(&app->target,
                                mhg_target_resolver_record(app->resolver)) != 0) {
        mhg_errorf(error, ENOMEM, "target snapshot allocation failed");
        return -1;
    }
    evidence = mhg_target_resolver_evidence(app->resolver);
    if (!evidence || !evidence->url.data || !evidence->passcode.data) {
        mhg_errorf(error, EPROTO, "bootstrap evidence missing");
        return -1;
    }
    out->url = (const char *)evidence->url.data;
    out->passcode = (const char *)evidence->passcode.data;
    out->target_ip = (const char *)app->target.ip.data;
    out->target_did = (const char *)app->target.did.data;
    out->target_model = (const char *)app->target.model.data;
    out->generation += 1u;
    return 0;
}

/* Bounded, non-secret diagnostic: the hub URL's host (the user typed the
 * address in the page anyway), the recorded target address and our own error
 * text. Control bytes are replaced so a message cannot break the status JSON. */
static void record_lan_error(struct app *app, const char *url,
                             const char *target_ip,
                             const struct mhg_error *error)
{
    char host[64] = "";
    char text[200];
    const char *begin = url ? strstr(url, "://") : NULL;
    const char *cursor;
    size_t index = 0u;

    if (begin) {
        size_t length = 0u;

        begin += 3u;
        cursor = begin;
        while (*cursor && *cursor != '/' && *cursor != ':' &&
               length + 1u < sizeof(host)) {
            host[length++] = *cursor++;
        }
        host[length] = '\0';
    }
    snprintf(text, sizeof(text), "errno=%d state=%s url_host=%s target=%s: ",
             error ? error->code : 0,
             mhg_lan_state_name(mhg_lan_owner_state(app->lan)), host,
             target_ip ? target_ip : "");
    while (error && error->message[index] &&
           strlen(text) + 1u < sizeof(text)) {
        unsigned char byte = (unsigned char)error->message[index];
        size_t used = strlen(text);

        text[used] = (byte >= 0x20u && byte < 0x7fu) ? (char)byte : '?';
        text[used + 1u] = '\0';
        index += 1u;
    }
    snprintf(app->lan_error, sizeof(app->lan_error), "%s", text);
}

static int app_lan_attempt(void *userdata,
                           const struct mhg_lan_bootstrap *bootstrap,
                           size_t *device_count, struct mhg_error *error)
{
    struct app *app = userdata;
    uint64_t generation;

    if (mhg_lan_owner_attempt(app->lan, bootstrap->url, bootstrap->passcode,
                              bootstrap->target_ip, bootstrap->target_did,
                              bootstrap->target_model, monotonic_ms(),
                              device_count, error)) {
        record_lan_error(app, bootstrap->url, bootstrap->target_ip, error);
        return -1;
    }
    app->lan_error[0] = '\0';
    generation = mhg_lan_owner_generation(app->lan);
    app_drop_resource_owners(app);
    /* A new generation revalidates the target URN against this LAN device
     * list; a persisted verified tuple may then be reused after graph
     * readback even when online Spec is unavailable. */
    app->spec_ready = false;
    app->rpc.owner = app->lan;
    app->rpc.generation = generation;
    /* mhg_lan_owner_attempt() already confirmed the binding for this attempt
     * (URL host + membership), so a second verification would only see the
     * VERIFIED state and fail; the generation is captured for the RPC phase. */
    return 0;
}

/* Derives the virtual-event Action parameters from the live target's own Spec
 *; only the target's own device list entry may supply the URN. */
static int app_derive_spec(struct app *app, struct mhg_error *error)
{
    struct mhg_spec_action spec_action = {0, 0, 0};
    cJSON *reply = NULL;
    const cJSON *list;
    const cJSON *item;
    bool found = false;

    if (mhg_lan_owner_call(app->lan, app->rpc.generation, "/api/getDevList",
                           NULL, &reply, monotonic_ms(), error))
        return -1;
    list = cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(reply, "result"), "devList");
    cJSON_ArrayForEach(item, list) {
        const cJSON *urn = cJSON_GetObjectItemCaseSensitive(item, "urn");

        if (!cJSON_IsString(urn) || !item->string) continue;
        if (strcmp(item->string, (const char *)app->target.did.data) != 0)
            continue;
        if (strlen(urn->valuestring) >= sizeof(app->urn)) break;
        snprintf(app->urn, sizeof(app->urn), "%s", urn->valuestring);
        found = true;
        break;
    }
    cJSON_Delete(reply);
    if (!found) {
        mhg_errorf(error, EPROTO, "target urn is absent from the device list");
        return -1;
    }
    {
        int binding = mhg_target_record_action_for_urn(
            &app->target, app->urn, &app->siid, &app->aiid, &app->piid);

        if (binding < 0) {
            mhg_errorf(error, EPROTO, "target urn changed from the verified action");
            return -1;
        }
        if (binding == 0) {
            app->spec_ready = true;
            return 0;
        }
    }
    if (mhg_spec_action_derive(app->urn, app->ca_info, &spec_action, error))
        return -1;
    if (mhg_target_resolver_commit_action(
            app->resolver, (const char *)app->target.did.data,
            (const char *)app->target.model.data, app->urn,
            spec_action.siid, spec_action.aiid, spec_action.piid) !=
        MHG_CLOUD_OK) {
        mhg_errorf(error, EIO, "verified action persistence failed");
        return -1;
    }
    if (mhg_target_record_clone(&app->target,
                                mhg_target_resolver_record(app->resolver)) != 0) {
        mhg_errorf(error, ENOMEM, "verified action snapshot failed");
        return -1;
    }
    app->siid = spec_action.siid;
    app->aiid = spec_action.aiid;
    app->piid = spec_action.piid;
    app->spec_ready = true;
    return 0;
}

static int app_resources_sync(void *userdata, struct mhg_error *error)
{
    struct app *app = userdata;
    struct mhg_resource_lan_config config = MHG_RESOURCE_LAN_CONFIG_INIT;
    struct mhg_resource_sync_config sync_config = MHG_RESOURCE_SYNC_CONFIG_INIT;
    struct mhg_emit_lan_config emit_config = MHG_EMIT_LAN_CONFIG_INIT;
    char selected_path[sizeof(app->resource_path)];

    /* Every pass must earn readiness again. A failed recheck cannot leave the
     * prior pass's ready flag authorizing a configuration save or delivery. */
    app->resources_ready = false;
    if (app->config_recovery_pending) {
        mhg_errorf(error, EAGAIN, "event configuration authority uncertain");
        return -1;
    }

    if (!app->spec_ready && app_derive_spec(app, error)) {
        record_resource_error(app, "spec", error);
        return -1;
    }
    if (app->target.action_state != MHG_TARGET_ACTION_VERIFIED ||
        mhg_resource_store_select_path(
            app->resource_base_path, &app->target.did, &app->target.model,
            selected_path, sizeof(selected_path)) != 0) {
        mhg_errorf(error, EPROTO, "target resource authority is unreadable");
        record_resource_error(app, "authority", error);
        return -1;
    }
    if (strcmp(app->resource_path, selected_path) != 0) {
        app_drop_resource_owners(app);
        snprintf(app->resource_path, sizeof(app->resource_path), "%s",
                 selected_path);
    }
    if (!app->resources) {
        struct mhg_resource_record existing = MHG_RESOURCE_RECORD_INIT;

        /* Field-level check with lengths only: the status must never carry the
         * exact target identity. */
        if (!app->target.did.data || !app->target.model.data ||
            app->target.did.len == 0u || app->target.model.len == 0u ||
            app->urn[0] == '\0' || app->siid <= 0 || app->aiid <= 0 ||
            app->piid <= 0 || !app->final_texts_ptr[0]) {
            char detail[160];

            snprintf(detail, sizeof(detail),
                     "did_len=%zu model_len=%zu urn_len=%zu siid=%d aiid=%d "
                     "piid=%d text0_len=%zu",
                     app->target.did.len, app->target.model.len,
                     strlen(app->urn), app->siid, app->aiid, app->piid,
                     app->final_texts_ptr[0] ?
                         strlen(app->final_texts_ptr[0]) : 0u);
            mhg_errorf(error, EINVAL, "resource config: %s", detail);
            record_resource_error(app, "config", error);
            return -1;
        }
        config.ops.call = lan_call;
        config.ops.end_generation = lan_end_seed_generation;
        config.userdata = &app->rpc;
        config.target_did = (const char *)app->target.did.data;
        config.target_model = (const char *)app->target.model.data;
        config.urn = app->urn;
        config.spec_generation = 1u;
        config.texts = app->final_texts_ptr;
        config.absent_seconds = app->event_config.absent_seconds;
        config.config_generation = app->event_config.generation;
        config.siid = app->siid;
        config.aiid = app->aiid;
        config.piid = app->piid;
        config.resource_generation = 1u;
        if (mhg_resource_store_load(app->resource_path, &existing) ==
            MHG_RESOURCE_STORE_PRESENT)
            config.resource_generation = existing.resource_generation + 1u;
        mhg_resource_record_clear(&existing);
        if (mhg_resource_lan_create(&app->resources, &config) != 0) {
            char detail[200];

            snprintf(detail, sizeof(detail),
                     "call=%d did=%d model=%d urn=%d texts=%d siid=%d aiid=%d "
                     "piid=%d",
                     config.ops.call != NULL, config.target_did != NULL,
                     config.target_model != NULL, config.urn != NULL,
                     config.texts != NULL, config.siid, config.aiid,
                     config.piid);
            mhg_errorf(error, EINVAL, "resource owner: %s", detail);
            record_resource_error(app, "owner", error);
            return -1;
        }
    }
    if (!app->sync) {
        sync_config.ops.plan = mhg_resource_lan_plan;
        sync_config.ops.seed_guard = mhg_resource_lan_seed_guard;
        sync_config.ops.seed_create = mhg_resource_lan_seed_create;
        sync_config.ops.seed_probe = mhg_resource_lan_seed_probe;
        sync_config.ops.global_seed_create =
            mhg_resource_lan_global_seed_create;
        sync_config.ops.global_seed_probe =
            mhg_resource_lan_global_seed_probe;
        sync_config.ops.seed_end_generation =
            mhg_resource_lan_seed_end_generation;
        sync_config.ops.create_disabled = mhg_resource_lan_create_disabled;
        sync_config.ops.readback = mhg_resource_lan_readback;
        sync_config.ops.enable = mhg_resource_lan_enable;
        sync_config.ops.reconcile_config = mhg_resource_lan_reconcile_config;
        sync_config.userdata = app->resources;
        sync_config.path = app->resource_path;
        sync_config.stop = &g_stop;
        if (mhg_resource_sync_create(&app->sync, &sync_config) != 0) {
            mhg_errorf(error, ENOMEM, "resource sync allocation failed");
            record_resource_error(app, "sync-alloc", error);
            return -1;
        }
    }
    enum mhg_resource_state synchronized = mhg_resource_sync_run(app->sync, error);
    if (synchronized != MHG_RESOURCE_READY && synchronized != MHG_RESOURCE_PRESENTATION_PENDING) {
        record_resource_error(app, "sync", error);
        if (app->maintenance.repair == MHG_APP_MAINTENANCE_PENDING) {
            app->maintenance.repair = MHG_APP_MAINTENANCE_FAILED;
            app->maintenance.last_error = (int)MHG_CLOUD_SERVICE;
        }
        return -1;
    }
    if (mhg_resource_store_load(app->resource_path, &app->record) !=
        MHG_RESOURCE_STORE_PRESENT) {
        mhg_errorf(error, EPROTO, "resource record missing after sync");
        record_resource_error(app, "record", error);
        return -1;
    }
    if (app->emit && mhg_emit_lan_replace_record(app->emit, &app->record) != 0) {
        mhg_errorf(error, ENOMEM, "emitter record refresh failed");
        record_resource_error(app, "emit-refresh", error);
        return -1;
    }
    if (!app->emit) {
        emit_config.ops.call = lan_call;
        emit_config.userdata = &app->rpc;
        emit_config.record = &app->record;
        if (mhg_emit_lan_create(&app->emit, &emit_config) != 0) {
            mhg_errorf(error, ENOMEM, "emit allocation failed");
            record_resource_error(app, "emit", error);
            return -1;
        }
    }
    app->resources_ready = true;
    if (synchronized == MHG_RESOURCE_PRESENTATION_PENDING) {
        record_resource_error(app, "presentation", error);
        return 1;
    }
    app->resource_error[0] = '\0';
    if (app->maintenance.repair == MHG_APP_MAINTENANCE_PENDING)
        app->maintenance.repair = MHG_APP_MAINTENANCE_DONE;
    if (app->maintenance.config == MHG_APP_MAINTENANCE_PENDING) {
        app->maintenance.config = MHG_APP_MAINTENANCE_DONE;
        app->maintenance.last_error = (int)MHG_CLOUD_OK;
    }
    return 0;
}

/* Same bounded, non-secret treatment as the LAN diagnostic: a stage name, our
 * own errno and our own text, control bytes replaced so the status JSON cannot
 * be broken from inside. */
static void record_error_text(char *out, size_t out_size, const char *stage,
                              const struct mhg_error *error)
{
    char text[200];
    size_t index = 0u;

    if (!out || out_size == 0u) return;
    snprintf(text, sizeof(text), "stage=%s errno=%d: ", stage,
             error ? error->code : 0);
    while (error && error->message[index] &&
           strlen(text) + 1u < sizeof(text)) {
        unsigned char byte = (unsigned char)error->message[index];
        size_t used = strlen(text);

        text[used] = (byte >= 0x20u && byte < 0x7fu) ? (char)byte : '?';
        text[used + 1u] = '\0';
        index += 1u;
    }
    snprintf(out, out_size, "%s", text);
}

static void record_resource_error(struct app *app, const char *stage,
                                  const struct mhg_error *error)
{
    record_error_text(app->resource_error, sizeof(app->resource_error), stage,
                      error);
}

/* --- delivery ops ------------------------------------------------------ */

static int app_event_send(void *userdata, enum mhg_presence_slot slot,
                          bool present, struct mhg_error *error)
{
    struct app *app = userdata;

    if (!app->emit) {
        mhg_errorf(error, ENOTCONN, "event emitter is not ready");
        return -1;
    }
    return mhg_emit_lan_send(app->emit, slot, present, error);
}

/* --- bridge-facing helpers -------------------------------------------- */


/* --- event configuration ----------------------------------------------- */

/* Product defaults used until the frontend writes its own texts. */
static const char *const default_direction_texts[MHG_RESOURCE_VARIABLE_COUNT] = {
    "全局有人", "全局无人",
    "A区有人", "A区无人",
    "B区有人", "B区无人",
    "C区有人", "C区无人",
    "D区有人", "D区无人",
    "E区有人", "E区无人",
    "F区有人", "F区无人",
    "G区有人", "G区无人",
    "H区有人", "H区无人",
};

static int config_defaults(struct mhg_event_config *config)
{
    size_t index;

    *config = (struct mhg_event_config)MHG_EVENT_CONFIG_INIT;
    config->generation = 1u;
    for (index = 0u; index < MHG_PRESENCE_SLOT_COUNT; ++index)
        config->absent_seconds[index] = 1.0;
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index) {
        if (mhg_secret_buf_set(&config->texts[index],
                               default_direction_texts[index],
                               strlen(default_direction_texts[index])) != 0) {
            mhg_event_config_dispose(config);
            return -1;
        }
    }
    return 0;
}

/* The graph and the emitter always read the final `prefix + text` strings. */
static void config_publish(struct app *app)
{
    if (mhg_event_config_final_texts(&app->event_config, app->final_texts,
                                     app->final_texts_ptr,
                                     MHG_RESOURCE_VARIABLE_COUNT) != 0)
        fprintf(stderr, "mhgeek-backend: event text assembly failed\n");
}

static int config_apply(struct mhg_event_config *config,
                        const struct mhg_app_request *request)
{
    size_t index;
    bool changed = false;

    if (request->has_prefix) {
        /* An empty prefix is legal and means "no prefix at all". */
        mhg_secret_buf_clear(&config->prefix);
        if (request->prefix[0] != '\0' &&
            mhg_secret_buf_set(&config->prefix, request->prefix,
                               strlen(request->prefix)) != 0)
            return -1;
        changed = true;
    }
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index) {
        if (!request->set_texts[index]) continue;
        mhg_secret_buf_clear(&config->texts[index]);
        if (mhg_secret_buf_set(&config->texts[index],
                               request->texts[index],
                               strlen(request->texts[index])) != 0)
            return -1;
        changed = true;
    }
    for (index = 0; index < MHG_PRESENCE_SLOT_COUNT; ++index) {
        if (!request->set_absent_seconds[index]) continue;
        config->absent_seconds[index] = request->absent_seconds[index];
        changed = true;
    }
    if (changed) config->generation += 1u;
    return 0;
}

/* A committed-but-not-durable or post-rename readback failure cannot be
 * treated as an ordinary rollback: events.json may already contain either
 * generation. Freeze delivery until a readable file is durably re-committed,
 * then let resource sync converge the graph to that sole local authority. */
static void app_config_recovery(struct app *app, uint64_t now_ms)
{
    struct mhg_event_config loaded = MHG_EVENT_CONFIG_INIT;
    int state;

    if (!app->config_recovery_pending || now_ms < app->next_config_recovery_ms)
        return;
    app->next_config_recovery_ms = now_ms + 1000u;
    state = mhg_event_config_load(app->event_path, &loaded);
    if (state == MHG_EVENT_CONFIG_ABSENT && !app->event_config_persisted) {
        app->config_recovery_pending = false;
        app->maintenance.config = MHG_APP_MAINTENANCE_FAILED;
        app->maintenance.last_error = (int)MHG_CLOUD_SERVICE;
        mhg_runtime_request_recheck(app->runtime);
    } else if (state == MHG_EVENT_CONFIG_PRESENT &&
               mhg_event_config_commit(app->event_path, &loaded) ==
                   MHG_EVENT_CONFIG_COMMITTED_DURABLE) {
        bool requested = loaded.generation == app->pending_config_generation;

        mhg_event_config_dispose(&app->event_config);
        app->event_config = loaded;
        loaded = (struct mhg_event_config)MHG_EVENT_CONFIG_INIT;
        app->event_config_persisted = true;
        config_publish(app);
        app_drop_resource_owners(app);
        app->config_recovery_pending = false;
        app->maintenance.config = requested ? MHG_APP_MAINTENANCE_PENDING :
                                              MHG_APP_MAINTENANCE_FAILED;
        app->maintenance.last_error = requested ? (int)MHG_CLOUD_OK :
                                                  (int)MHG_CLOUD_SERVICE;
        app->maintenance.config_generation = app->event_config.generation;
        mhg_runtime_request_recheck(app->runtime);
    }
    mhg_event_config_dispose(&loaded);
}

/* Configuration transaction: events.json is the durable local authority.
 * The resource sync derives the expected graph digest from it and converges
 * the same IDs after this request or after a crash at any later point. */
static void config_transaction(struct app *app, const struct mhg_app_request *request,
                               uint64_t now_ms)
{
    struct mhg_event_config working = MHG_EVENT_CONFIG_INIT;
    struct mhg_event_config canonical = MHG_EVENT_CONFIG_INIT;
    struct mhg_resource_record record = MHG_RESOURCE_RECORD_INIT;
    struct mhg_error error = {0};
    char texts[MHG_RESOURCE_VARIABLE_COUNT][MHG_EVENT_PREFIX_LIMIT +
                                            MHG_EVENT_TEXT_LIMIT + 1u];
    const char *texts_ptr[MHG_RESOURCE_VARIABLE_COUNT];
    enum mhg_event_config_commit_result committed;

    app->maintenance.config = MHG_APP_MAINTENANCE_PENDING;
    app->config_error[0] = '\0';
    /* A request only carries the fields the frontend sent, so the transaction
     * works on a copy of the running configuration: a partial save must keep
     * the other 17 texts (an empty one is rejected by the store read-back and
     * would also send an empty Action text to the hub). */
    if (mhg_event_config_clone(&working, &app->event_config) != 0 ||
        config_apply(&working, request) != 0 ||
        mhg_event_config_final_texts(&working, texts, texts_ptr,
                                     MHG_RESOURCE_VARIABLE_COUNT) != 0) {
        mhg_errorf(&error, ENOMEM, "event configuration build failed");
        goto failed;
    }
    committed = mhg_event_config_commit(app->event_path, &working);
    if (committed == MHG_EVENT_CONFIG_FAILED) {
        mhg_errorf(&error, EIO, "event configuration persistence failed");
        goto failed;
    }
    if (committed != MHG_EVENT_CONFIG_COMMITTED_DURABLE ||
        mhg_event_config_load(app->event_path, &canonical) !=
            MHG_EVENT_CONFIG_PRESENT ||
        canonical.generation != working.generation) {
        app->pending_config_generation = working.generation;
        app->config_recovery_pending = true;
        app->next_config_recovery_ms = now_ms;
        app->resources_ready = false;
        mhg_delivery_rebind(app->delivery);
        mhg_runtime_request_recheck(app->runtime);
        record_error_text(app->config_error, sizeof(app->config_error),
                          "authority-uncertain", NULL);
        goto done;
    }
    mhg_event_config_dispose(&app->event_config);
    app->event_config = canonical;
    canonical = (struct mhg_event_config)MHG_EVENT_CONFIG_INIT;
    app->event_config_persisted = true;
    config_publish(app);
    app_drop_resource_owners(app);
    app->resources_ready = false;
    mhg_delivery_rebind(app->delivery);
    mhg_runtime_request_recheck(app->runtime);
    /* It remains PENDING until the new graph is read back and its record is
     * committed durably; the slow lane performs that work without a second
     * frontend submission. */
    goto done;

failed:
    record_error_text(app->config_error, sizeof(app->config_error),
                      "commit", &error);
    app->maintenance.config = MHG_APP_MAINTENANCE_FAILED;
    app->maintenance.last_error = (int)MHG_CLOUD_SERVICE;

done:
    app->maintenance.config_generation = app->event_config.generation;
    mhg_resource_record_clear(&record);
    mhg_event_config_dispose(&working);
    mhg_event_config_dispose(&canonical);
}

/* --- authorization ----------------------------------------------------- */

static void auth_mask_account_id(const struct mhg_secret_buf *user_id,
                                 char output[32])
{
    output[0] = '\0';
    if (!user_id || !user_id->data || user_id->len == 0u) return;
    if (user_id->len <= 4u) {
        snprintf(output, 32u, "****");
        return;
    }
    snprintf(output, 32u, "%.2s******%s", (const char *)user_id->data,
             (const char *)user_id->data + user_id->len - 2u);
}

/* Runtime owners never retain a revoked account/target association. The
 * file-store transaction owns disk cleanup; this path performs no remote I/O. */
static void app_forget_binding(struct app *app, bool authorization, uint64_t now_ms)
{
    mhg_lan_owner_end(app->lan, mhg_lan_owner_generation(app->lan),
                      MHG_LAN_END_CANCELLED, now_ms);
    app_drop_resource_owners(app);
    mhg_target_record_clear(&app->target);
    app->has_target = false;
    app->spec_ready = false;
    app->siid = app->aiid = app->piid = 0;
    app->urn[0] = '\0';
    app->lan_error[0] = app->resource_error[0] = '\0';
    memcpy(app->resource_path, app->resource_base_path, sizeof(app->resource_path));
    if (authorization) {
        mhg_account_record_clear(&app->account);
        app->has_account = false;
        mhg_xiaomi_session_invalidate(app->io_session);
        mhg_xiaomi_session_invalidate(app->mijia_session);
        mhg_target_resolver_forget_authorization(app->resolver);
    }
    mhg_runtime_request_recheck(app->runtime);
}

static void auth_snapshot(struct app *app, uint64_t now_ms)
{
    struct mhg_auth_sms_status status;

    memset(&status, 0, sizeof(status));
    mhg_auth_sms_executor_status(app->auth, now_ms, &status);
    app->auth_state.state = status.state;
    app->auth_state.phase = status.phase;
    app->auth_state.error = status.error;
    app->auth_state.has_account = status.has_account;
    app->auth_state.masked_account_id[0] = '\0';
    app->auth_state.account_generation = status.account_generation;
    app->auth_state.challenge_generation = status.challenge_generation;
    app->auth_state.operation_id = status.operation_id;
    app->auth_state.code_length = status.code_length;
    app->auth_state.retry_after_seconds = status.retry_after_seconds;
    app->auth_state.provider_scope = status.provider_scope;
    app->auth_state.provider_class = status.provider_class;
    app->auth_state.provider_code = status.provider_code;
    app->auth_state.pending_store_outcome = status.pending_store_outcome;
    snprintf(app->auth_state.state_name, sizeof(app->auth_state.state_name),
             "%s", mhg_auth_sms_state_name(status.state));
    snprintf(app->auth_state.phase_name, sizeof(app->auth_state.phase_name),
             "%s", mhg_auth_sms_phase_name(status.phase));
    snprintf(app->auth_state.error_name, sizeof(app->auth_state.error_name),
             "%s", mhg_auth_sms_error_name(status.error));
    snprintf(app->auth_state.provider_scope_name,
             sizeof(app->auth_state.provider_scope_name), "%s",
             mhg_auth_sms_provider_scope_name(status.provider_scope));
    snprintf(app->auth_state.provider_class_name,
             sizeof(app->auth_state.provider_class_name), "%s",
             mhg_auth_sms_provider_class_name(status.provider_class));
    snprintf(app->auth_state.message_key, sizeof(app->auth_state.message_key),
             "%s", mhg_auth_sms_status_message_key(&status));
    if (app->auth_file_store.binding_invalidated) {
        app_forget_binding(app, true, now_ms);
        app->auth_file_store.binding_invalidated = false;
    }
    if (!status.has_account) {
        mhg_account_record_clear(&app->account);
        app->has_account = false;
    } else if (!app->has_account ||
               app->account.generation != status.account_generation) {
        struct mhg_account_record fresh = MHG_ACCOUNT_RECORD_INIT;

        app->has_account = false;
        if (mhg_auth_sms_executor_copy_account(app->auth, &fresh) == 0) {
            mhg_account_record_clear(&app->account);
            app->account = fresh;
            app->has_account = true;
        } else {
            mhg_account_record_clear(&fresh);
        }
    }
    if (app->has_account)
        auth_mask_account_id(&app->account.user_id,
                             app->auth_state.masked_account_id);
}

/* One blocking executor step per scheduler tick while a chain is open; the
 * executor owns its own serialization and deadlines. */
static void auth_service(struct app *app, uint64_t now_ms)
{
    struct mhg_auth_sms_work next = MHG_AUTH_SMS_WORK_INIT;
    enum mhg_cloud_error cloud = MHG_CLOUD_INTERNAL;
    enum mhg_auth_sms_result result;

    if (app->auth_work.kind == MHG_AUTH_SMS_WORK_NONE) return;
    result = mhg_auth_sms_executor_run(app->auth, &app->auth_work, now_ms,
                                       &next, &cloud);
    mhg_auth_sms_work_clear(&app->auth_work);
    app->auth_work = next;
    next = (struct mhg_auth_sms_work)MHG_AUTH_SMS_WORK_INIT;
    auth_snapshot(app, now_ms);
    if (result != MHG_AUTH_SMS_ACCEPTED) {
        fprintf(stderr, "mhgeek-backend: auth step stopped state=%s cloud=%s\n",
                app->auth_state.state_name, mhg_cloud_error_name(cloud));
    }
}

static void operation_finish(struct app *, uint64_t,
                             enum mhg_app_operation_state,
                             enum mhg_app_operation_error, const char *);

static void auth_dispatch(struct app *app, const struct mhg_app_request *request,
                          uint64_t now_ms)
{
    struct mhg_auth_sms_request auth_request = {0};
    struct mhg_auth_sms_reply reply = MHG_AUTH_SMS_REPLY_INIT;

    switch (request->kind) {
    case MHG_APP_REQUEST_AUTH_START:
        auth_request.action = MHG_AUTH_SMS_ACTION_START;
        auth_request.calling_code = request->calling_code;
        auth_request.national_number = request->national_number;
        break;
    case MHG_APP_REQUEST_AUTH_VERIFY:
        auth_request.action = MHG_AUTH_SMS_ACTION_VERIFY;
        auth_request.code = request->code;
        break;
    case MHG_APP_REQUEST_AUTH_RESEND:
        auth_request.action = MHG_AUTH_SMS_ACTION_RESEND;
        auth_request.now_ms = now_ms;
        break;
    case MHG_APP_REQUEST_AUTH_CANCEL:
        auth_request.action = MHG_AUTH_SMS_ACTION_CANCEL;
        break;
    case MHG_APP_REQUEST_AUTH_CLEAR:
        auth_request.action = MHG_AUTH_SMS_ACTION_CLEAR;
        break;
    default:
        auth_request.action = request->retry_persist ?
            MHG_AUTH_SMS_ACTION_RETRY_PERSIST : MHG_AUTH_SMS_ACTION_RETRY;
        auth_request.challenge_generation = request->challenge_generation;
        break;
    }
    auth_request.operation_id = request->operation_id;
    if (request->kind == MHG_APP_REQUEST_AUTH_RETRY && request->retry_persist) {
        struct mhg_auth_sms_status pending;

        /* The queue operation tracks this button press; persistence belongs
         * to the original accepted authorization transaction. */
        mhg_auth_sms_executor_status(app->auth, now_ms, &pending);
        auth_request.challenge_generation = pending.challenge_generation;
        auth_request.operation_id = pending.operation_id;
    }
    if (mhg_auth_sms_executor_dispatch(app->auth, &auth_request, &reply) != 0 ||
        reply.result != MHG_AUTH_SMS_ACCEPTED) {
        fprintf(stderr,
                "mhgeek-backend: auth action rejected result=%d state=%s\n",
                (int)reply.result, app->auth_state.state_name);
        mhg_auth_sms_reply_clear(&reply);
        if (app->auth_file_store.binding_invalidated) {
            mhg_app_operations_cancel_auth_before(&app->operations, request->operation_id);
            mhg_auth_sms_work_clear(&app->auth_work);
        }
        auth_snapshot(app, now_ms);
        operation_finish(app, request->operation_id, MHG_OP_FAILED,
                         MHG_OP_AUTH_FAILED, app->auth_state.error_name);
        return;
    }
    if (request->kind == MHG_APP_REQUEST_AUTH_CANCEL || request->kind == MHG_APP_REQUEST_AUTH_CLEAR)
        mhg_app_operations_cancel_auth_before(&app->operations, request->operation_id);
    mhg_auth_sms_work_clear(&app->auth_work);
    app->auth_work = reply.work;
    reply.work = (struct mhg_auth_sms_work)MHG_AUTH_SMS_WORK_INIT;
    mhg_auth_sms_reply_clear(&reply);
    auth_snapshot(app, now_ms);
    if (request->kind == MHG_APP_REQUEST_AUTH_CLEAR ||
        request->kind == MHG_APP_REQUEST_AUTH_START ||
        request->kind == MHG_APP_REQUEST_AUTH_VERIFY ||
        request->kind == MHG_APP_REQUEST_AUTH_RESEND)
        auth_service(app, now_ms);
    if (request->kind == MHG_APP_REQUEST_AUTH_START ||
        request->kind == MHG_APP_REQUEST_AUTH_VERIFY)
        mhg_runtime_request_recheck(app->runtime);
}

static void app_target_state(void *userdata, struct mhg_app_target_state *state);

/* The Bridge thread renders these snapshots only: the scheduler thread owns
 * every lock that network I/O may hold for seconds. */
static void app_refresh_snapshots(struct app *app)
{
    struct mhg_app_bridge_snapshot next = {0};
    size_t index;

    /* Countdown is a live projection, independent of authorization writes. */
    auth_snapshot(app, monotonic_ms());
    mhg_runtime_status_get(app->runtime, &next.status);
    mhg_target_resolver_catalog_stats_get(app->resolver, &next.catalog);
    const struct mhg_catalog_snapshot *catalog =
        mhg_target_resolver_snapshot(app->resolver);
    next.catalog_device_count = catalog ? catalog->device_count : 0u;
    app_target_state(app, &next.target);
    next.auth = app->auth_state;
    next.maintenance = app->maintenance;
    next.maintenance.config_generation = app->event_config.generation;
    next.resource_state = app->sync ? mhg_resource_sync_state(app->sync) : MHG_RESOURCE_NONE;
    next.synced_config_generation = app->resources_ready && next.resource_state == MHG_RESOURCE_READY ? app->record.config_generation : 0;
    snprintf(next.lan_error, sizeof(next.lan_error), "%s", app->lan_error);
    snprintf(next.resource_error, sizeof(next.resource_error), "%s",
             app->resource_error);
    snprintf(next.config_error, sizeof(next.config_error), "%s",
             app->config_error);
    snprintf(next.prefix, sizeof(next.prefix), "%s",
             app->event_config.prefix.data ?
                 (const char *)app->event_config.prefix.data : "");
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index)
        snprintf(next.texts[index], sizeof(next.texts[index]), "%s",
                 app->event_config.texts[index].data ?
                     (const char *)app->event_config.texts[index].data : "");
    memcpy(next.absent_seconds, app->event_config.absent_seconds,
           sizeof(next.absent_seconds));
    mhg_app_bridge_publish(&app->published, &next);
}

static int app_bridge_request(const char *request_json,
                              ainice_bridge_response_t *response,
                              void *userdata)
{
    struct app *app = userdata;
    struct mhg_app_bridge_snapshot snapshot;
    struct mhg_bridge_context context = app->bridge;
    const char *texts[MHG_RESOURCE_VARIABLE_COUNT];
    size_t index;

    mhg_app_bridge_take(&app->published, &snapshot);
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index)
        texts[index] = snapshot.texts[index];
    context.status = &snapshot.status;
    context.catalog = &snapshot.catalog;
    context.catalog_device_count = snapshot.catalog_device_count;
    context.target_view = &snapshot.target;
    context.auth_view = &snapshot.auth;
    context.maintenance_view = &snapshot.maintenance;
    context.resource_state = snapshot.resource_state;
    context.lan_error = snapshot.lan_error;
    context.resource_error = snapshot.resource_error;
    context.config_error = snapshot.config_error;
    context.prefix = snapshot.prefix;
    context.texts = texts;
    context.absent_seconds = snapshot.absent_seconds;
    context.config_generation = snapshot.maintenance.config_generation;
    context.synced_config_generation = snapshot.synced_config_generation;
    return mhg_app_bridge_request(request_json, response, &context);
}

/* --- frontend action queue -------------------------------------------- */

static bool app_operation(void *userdata, uint64_t id, struct mhg_app_operation *out)
{
    return mhg_app_operations_get(&((struct app *)userdata)->operations, id, out);
}
static void operation_finish(struct app *app, uint64_t id,
                             enum mhg_app_operation_state state,
                             enum mhg_app_operation_error error,
                             const char *diagnostic)
{
    mhg_app_operations_finish(&app->operations, id, state, error,
        app->config_recovery_pending ? app->pending_config_generation : app->event_config.generation, diagnostic,
        error == MHG_OP_AUTH_FAILED ? app->auth_state.message_key : "");
}
static enum mhg_app_operation_error target_operation_error(
    enum mhg_target_outcome outcome)
{
    switch (outcome) {
    case MHG_TARGET_OUTCOME_CATALOG: return MHG_OP_TARGET_CATALOG_FAILED;
    case MHG_TARGET_OUTCOME_NOT_FOUND: return MHG_OP_TARGET_NOT_FOUND;
    case MHG_TARGET_OUTCOME_AMBIGUOUS: return MHG_OP_TARGET_AMBIGUOUS;
    case MHG_TARGET_OUTCOME_CONFLICT:
    case MHG_TARGET_OUTCOME_DRIFTED: return MHG_OP_TARGET_CONFLICT;
    case MHG_TARGET_OUTCOME_PROBE: return MHG_OP_TARGET_PROBE_FAILED;
    case MHG_TARGET_OUTCOME_STORE: return MHG_OP_STORE_FAILED;
    default: return MHG_OP_TARGET_FAILED;
    }
}

static bool app_enqueue(void *userdata, struct mhg_app_request *request)
{
    return mhg_app_operations_enqueue(&((struct app *)userdata)->operations, request);
}
static bool app_take_request(struct app *app, struct mhg_app_request *out)
{
    return mhg_app_operations_take(&app->operations, out, !app->config_recovery_pending);
}

static void app_target_state(void *userdata, struct mhg_app_target_state *state)
{
    struct app *app = userdata;

    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->configured = app->has_target;
    state->state = (int)mhg_target_resolver_state(app->resolver);
    state->outcome = (int)mhg_target_resolver_outcome(app->resolver);
    state->last_error = (int)mhg_target_resolver_last_error(app->resolver);
    state->locked = state->state == MHG_TARGET_STATE_LOCKED;
    if (app->has_target) {
        snprintf(state->ip, sizeof(state->ip), "%s",
                 app->target.ip.data ? (const char *)app->target.ip.data : "");
        snprintf(state->did, sizeof(state->did), "%s",
                 app->target.did.data ? (const char *)app->target.did.data : "");
        mask_identity(app->target.did.data ?
                          (const char *)app->target.did.data : "",
                      state->did_masked, sizeof(state->did_masked));
        mask_identity(app->target.model.data ?
                          (const char *)app->target.model.data : "",
                      state->model_masked, sizeof(state->model_masked));
    }
}

/* Applies one queued frontend action on the scheduler thread. */
static void app_run_request(struct app *app, const struct mhg_app_request *request,
                            uint64_t now_ms)
{
    struct mhg_error error = {0};

    /* Authorization may change after the Bridge snapshot admitted a request.
     * Never requeue a target/config operation while credentials are absent. */
    if (!mhg_app_request_is_auth(request->kind) &&
        (!app->auth_state.has_account ||
         app->auth_state.state != MHG_AUTH_SMS_AUTHENTICATED)) {
        operation_finish(app, request->operation_id, MHG_OP_FAILED,
                         MHG_OP_UNAUTHORIZED, "authorization changed");
        return;
    }

    switch (request->kind) {
    case MHG_APP_REQUEST_REPLAY:
        mhg_delivery_request_replay(app->delivery);
        break;
    case MHG_APP_REQUEST_RECONNECT:
        mhg_lan_owner_end(app->lan, mhg_lan_owner_generation(app->lan),
                          MHG_LAN_END_CANCELLED, now_ms);
        mhg_runtime_request_recheck(app->runtime);
        break;
    case MHG_APP_REQUEST_TARGET_SET:
        /* One bounded cloud attempt produces a terminal result; authorization
         * stays independently schedulable after a provider failure. */
        if (app_ensure_sessions(app, &error)) {
            operation_finish(app, request->operation_id, MHG_OP_FAILED,
                             MHG_OP_CLOUD_FAILED, error.message);
            return;
        }
        if (mhg_target_resolver_submit(
                app->resolver, mhg_xiaomi_session_current(app->io_session),
                mhg_xiaomi_session_current(app->mijia_session), request->ip,
                request->has_did ? request->did : NULL) == MHG_CLOUD_OK) {
            /* The binding is locked now: drop any previous session. */
            mhg_lan_owner_end(app->lan, mhg_lan_owner_generation(app->lan),
                              MHG_LAN_END_CANCELLED, now_ms);
            mhg_runtime_request_recheck(app->runtime);
        } else {
            enum mhg_target_outcome outcome = mhg_target_resolver_outcome(app->resolver);
            app_cloud_rejected(app, outcome,
                                mhg_target_resolver_last_error(app->resolver));
            char diagnostic[96];
            snprintf(diagnostic, sizeof(diagnostic), "%s: %d",
                     mhg_target_outcome_name(outcome),
                     mhg_target_resolver_last_error(app->resolver));
            operation_finish(app, request->operation_id, MHG_OP_FAILED,
                             target_operation_error(outcome), diagnostic);
            return;
        }
        break;
    case MHG_APP_REQUEST_TARGET_CLEAR:
        mhg_lan_owner_end(app->lan, mhg_lan_owner_generation(app->lan),
                          MHG_LAN_END_CANCELLED, now_ms);
        if (mhg_target_resolver_clear(app->resolver) == MHG_CLOUD_OK) {
            app_forget_binding(app, false, now_ms);
        } else {
            fprintf(stderr, "mhgeek-backend: target clear failed: %s\n",
                    error.message[0] ? error.message : "store");
            operation_finish(app, request->operation_id, MHG_OP_FAILED,
                             MHG_OP_STORE_FAILED, "target clear failed");
            return;
        }
        break;
    case MHG_APP_REQUEST_AUTH_START:
    case MHG_APP_REQUEST_AUTH_VERIFY:
    case MHG_APP_REQUEST_AUTH_RESEND:
    case MHG_APP_REQUEST_AUTH_CANCEL:
    case MHG_APP_REQUEST_AUTH_CLEAR:
    case MHG_APP_REQUEST_AUTH_RETRY:
        auth_dispatch(app, request, now_ms);
        break;
    case MHG_APP_REQUEST_CONFIG_SET:
        config_transaction(app, request, now_ms);
        operation_finish(app, request->operation_id,
                         app->maintenance.config == MHG_APP_MAINTENANCE_FAILED ? MHG_OP_FAILED : MHG_OP_WAITING_SYNC,
                         app->maintenance.config == MHG_APP_MAINTENANCE_FAILED ? MHG_OP_STORE_FAILED : MHG_OP_OK,
                         app->config_error);
        break;
    case MHG_APP_REQUEST_RESYNC:
        app->maintenance.repair = MHG_APP_MAINTENANCE_PENDING;
        app->resources_ready = false;
        if (!app_resource_path_current(app)) {
            app->maintenance.repair = MHG_APP_MAINTENANCE_FAILED;
            app->maintenance.last_error = (int)MHG_CLOUD_SERVICE;
            break;
        }
        if (app->maintenance.repair == MHG_APP_MAINTENANCE_PENDING)
            mhg_runtime_request_recheck(app->runtime);
        break;
    default:
        break;
    }
}

/* Resolve durable configuration and network work independently of admission.
 * No operation is reinserted into the request queue. */
static void app_operations_progress(struct app *app)
{
    struct mhg_app_operation records[MHG_APP_OPERATION_CAPACITY];
    mhg_app_operations_sync(&app->operations, app->event_config.generation,
        app->record.config_generation, !app->config_recovery_pending,
        app->resources_ready && mhg_resource_sync_state(app->sync) == MHG_RESOURCE_READY);
    mhg_app_operations_snapshot(&app->operations, records);
    for (size_t i = 0; i < MHG_APP_OPERATION_CAPACITY; ++i) {
        struct mhg_app_operation op = records[i];
        if (!op.operation_id || op.state == MHG_OP_QUEUED || mhg_app_operation_terminal(op.state))
            continue;
        enum mhg_app_operation_state state = MHG_OP_SUCCEEDED;
        enum mhg_app_operation_error error = MHG_OP_OK;
        const char *diagnostic = "";
        if (mhg_app_request_is_auth(op.kind)) {
            if (app->auth_work.kind != MHG_AUTH_SMS_WORK_NONE) continue;
            if ((app->auth_state.error != MHG_AUTH_SMS_ERROR_NONE &&
                 !(op.kind == MHG_APP_REQUEST_AUTH_CANCEL &&
                   app->auth_state.error == MHG_AUTH_SMS_ERROR_CANCELED)) ||
                (op.kind == MHG_APP_REQUEST_AUTH_VERIFY &&
                 app->auth_state.state != MHG_AUTH_SMS_AUTHENTICATED)) {
                state = MHG_OP_FAILED; error = MHG_OP_AUTH_FAILED;
                diagnostic = app->auth_state.error_name;
            }
        } else if (op.kind == MHG_APP_REQUEST_CONFIG_SET) {
            continue; /* The operation owner correlates persisted generations. */
        } else if (op.kind == MHG_APP_REQUEST_RESYNC) {
            if (app->maintenance.repair == MHG_APP_MAINTENANCE_PENDING)
                state = MHG_OP_WAITING_SYNC;
            else if (app->maintenance.repair == MHG_APP_MAINTENANCE_FAILED) {
                state = MHG_OP_FAILED; error = MHG_OP_SYNC_FAILED;
                diagnostic = app->resource_error;
            }
        }
        operation_finish(app, op.operation_id, state, error, diagnostic);
    }
}

/* --- workers ----------------------------------------------------------- */

static int app_subscribe(ainice_presence_handler_t handler, void *userdata,
                         ainice_event_should_stop_t should_stop,
                         void *stop_userdata)
{
    return ainice_presence_subscribe_until(handler, userdata, should_stop,
                                           stop_userdata);
}

static void *presence_main(void *arg)
{
    struct app *app = arg;

    while (!g_stop) {
        struct mhg_error error = {0};

        if (mhg_presence_source_run(app->presence, &error) != 0 && !g_stop) {
            /* The SDK never reconnects on its own; the caller decides. */
            sleep_ms(2000u);
        }
    }
    return NULL;
}

static void *scheduler_main(void *arg)
{
    struct app *app = arg;

    while (!g_stop) {
        struct mhg_app_request request;
        uint64_t now = monotonic_ms();

        if (app_take_request(app, &request))
            app_run_request(app, &request, now);
        app_config_recovery(app, monotonic_ms());
        auth_service(app, monotonic_ms());
        (void)mhg_runtime_service(app->runtime, monotonic_ms());
        app_operations_progress(app);
        app_refresh_snapshots(app);
        sleep_ms(30u);   /* the product scheduler granularity */
    }
    return NULL;
}

/* --- lifecycle --------------------------------------------------------- */

static void init_paths(struct app *app)
{
    const char *root = getenv("AINICE_PLUGIN_DIR");
    const char *data = getenv("AINICE_PLUGIN_DATA");

    if (!root || !root[0]) root = MHG_APP_ROOT_DEFAULT;
    if (!data || !data[0]) data = MHG_APP_DATA_DEFAULT;
    app->data_root = data;
    (void)root;
}

static void app_shutdown(struct app *app)
{
    g_stop = 1;
    mhg_presence_source_request_stop(app->presence);
    if (app->presence_thread_started)
        (void)pthread_join(app->presence_thread, NULL);
    if (app->scheduler_thread_started)
        (void)pthread_join(app->scheduler_thread, NULL);
    mhg_runtime_destroy(app->runtime);
    mhg_presence_source_destroy(app->presence);
    mhg_delivery_destroy(app->delivery);
    mhg_emit_lan_destroy(app->emit);
    mhg_resource_sync_destroy(app->sync);
    mhg_resource_lan_destroy(app->resources);
    mhg_lan_owner_destroy(app->lan);
    mhg_target_resolver_destroy(app->resolver);
    mhg_xiaomi_session_destroy(app->mijia_session);
    mhg_xiaomi_session_destroy(app->io_session);
    mhg_auth_sms_work_clear(&app->auth_work);
    mhg_auth_sms_executor_destroy(app->auth);
    mhg_event_config_dispose(&app->event_config);
    mhg_resource_record_clear(&app->record);
    mhg_target_record_clear(&app->target);
    mhg_account_record_clear(&app->account);
    mhg_app_bridge_publisher_destroy(&app->published);
    mhg_app_operations_destroy(&app->operations);
    curl_global_cleanup();
}

int main(void)
{
    struct app *app = &g_app;
    struct mhg_xiaomi_session_config session_config =
        MHG_XIAOMI_SESSION_CONFIG_INIT;
    struct mhg_target_resolver_config resolver_config =
        MHG_TARGET_RESOLVER_CONFIG_INIT;
    struct mhg_lan_config lan_config = MHG_LAN_CONFIG_DEFAULT;
    struct mhg_delivery_config delivery_config = MHG_DELIVERY_CONFIG_INIT;
    struct mhg_presence_source_config presence_config =
        MHG_PRESENCE_SOURCE_CONFIG_INIT;
    struct mhg_runtime_config runtime_config = MHG_RUNTIME_CONFIG_INIT;
    struct sigaction action = {0};
    int bridge_result;

    init_paths(app);
    app->ca_info = getenv("AINICE_CA_INFO");
    if (!app->ca_info || !app->ca_info[0]) app->ca_info = MHG_APP_CA_INFO;
    if (mhg_app_operations_init(&app->operations) != 0) {
        fputs("mhgeek-backend: request lock failed\n", stderr);
        return 1;
    }
    if (mhg_app_bridge_publisher_init(&app->published) != 0) {
        mhg_app_operations_destroy(&app->operations);
        fputs("mhgeek-backend: bridge lock failed\n", stderr);
        return 1;
    }
    if (geteuid() == 0) {
        fputs("mhgeek-backend: refusing to run as root\n", stderr);
        return 1;
    }
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) {
        fputs("mhgeek-backend: cannot install stop handlers\n", stderr);
        return 1;
    }
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL)) {
        fputs("mhgeek-backend: cannot ignore SIGPIPE\n", stderr);
        return 1;
    }
    if (mhg_account_store_prepare(app->data_root, app->account_path,
                                  sizeof(app->account_path)) != 0 ||
        mhg_target_store_prepare(app->data_root, app->target_path,
                                 sizeof(app->target_path)) != 0 ||
        mhg_resource_store_prepare(app->data_root, app->resource_base_path,
                                   sizeof(app->resource_base_path)) != 0) {
        fputs("mhgeek-backend: data root unavailable\n", stderr);
        return 1;
    }
    memcpy(app->resource_path, app->resource_base_path,
           sizeof(app->resource_path));
    if (mhg_auth_sms_file_store_init(&app->auth_file_store, app->data_root,
                                     &app->auth_store) != 0) {
        fputs("mhgeek-backend: authorization store unavailable\n", stderr);
        return 1;
    }
    {
        struct mhg_auth_sms_http_config auth_http = MHG_AUTH_SMS_HTTP_CONFIG_INIT;

        auth_http.ca_info = app->ca_info;
        if (mhg_auth_sms_executor_create(&app->auth, &app->auth_store,
                                         &auth_http) != 0) {
            fputs("mhgeek-backend: authorization owner failed\n", stderr);
            return 1;
        }
    }
    if (mhg_event_config_prepare(app->data_root, app->event_path,
                                 sizeof(app->event_path)) != 0) {
        fputs("mhgeek-backend: event configuration path failed\n", stderr);
        return 1;
    }
    switch (mhg_event_config_load(app->event_path, &app->event_config)) {
    case MHG_EVENT_CONFIG_NEEDS_REPAIR:
        if (app->event_config.generation >= 9007199254740991ull) {
            fputs("mhgeek-backend: event duration repair generation exhausted\n", stderr);
            return 1;
        }
        app->event_config.generation++;
        if (mhg_event_config_commit(app->event_path, &app->event_config) !=
            MHG_EVENT_CONFIG_COMMITTED_DURABLE) {
            fputs("mhgeek-backend: corrected event durations could not be persisted\n",
                  stderr);
            return 1;
        }
        /* Continue only after the corrected durations are durable. */
        /* fall through */
    case MHG_EVENT_CONFIG_PRESENT:
        app->event_config_persisted = true;
        break;
    case MHG_EVENT_CONFIG_ABSENT:
        if (config_defaults(&app->event_config)) {
            fputs("mhgeek-backend: event defaults allocation failed\n", stderr);
            app_shutdown(app);
            return 1;
        }
        break;
    default:
        fputs("mhgeek-backend: event configuration is unreadable; "
              "refusing to replace it with defaults\n", stderr);
        app_shutdown(app);
        return 1;
    }
    config_publish(app);
    app->maintenance.config_generation = app->event_config.generation;
    app->auth_work = (struct mhg_auth_sms_work)MHG_AUTH_SMS_WORK_INIT;
    auth_snapshot(app, monotonic_ms());
    if (app->has_account) {
        struct mhg_target_record fresh = MHG_TARGET_RECORD_INIT;

        if (mhg_target_store_load(app->target_path, &fresh) ==
            MHG_TARGET_STORE_PRESENT) {
            mhg_target_record_clear(&app->target);
            app->target = fresh;
            app->has_target = true;
        } else {
            mhg_target_record_clear(&fresh);
        }
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fputs("mhgeek-backend: curl init failed\n", stderr);
        return 1;
    }
    session_config.ca_info = app->ca_info;
    session_config.allow_system_proxy = 0;
    if (mhg_xiaomi_session_create(&app->io_session, MHG_XIAOMI_SID_XIAOMIIO,
                                  &session_config) != 0 ||
        mhg_xiaomi_session_create(&app->mijia_session, MHG_XIAOMI_SID_MIJIA,
                                  &session_config) != 0) {
        fputs("mhgeek-backend: session allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    resolver_config.target_path = app->target_path;
    resolver_config.catalog.http.ca_info = app->ca_info;
    resolver_config.catalog.http.allow_system_proxy = false;
    resolver_config.bootstrap.http.ca_info = app->ca_info;
    resolver_config.bootstrap.http.allow_system_proxy = false;
    if (mhg_target_resolver_create(&app->resolver, &resolver_config) != 0 ||
        mhg_target_resolver_begin(app->resolver) != MHG_CLOUD_OK) {
        fputs("mhgeek-backend: resolver allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    lan_config.stop = &g_stop;
    lan_config.now_ms = app_clock;
    lan_config.clock_userdata = app;
    if (mhg_lan_owner_create(&app->lan, &lan_config) != 0) {
        fputs("mhgeek-backend: lan owner allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    delivery_config.ops.now_ms = app_clock;
    delivery_config.ops.send = app_event_send;
    delivery_config.userdata = app;
    delivery_config.stop = &g_stop;
    if (mhg_delivery_create(&app->delivery, &delivery_config) != 0) {
        fputs("mhgeek-backend: delivery allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    presence_config.ops.subscribe = app_subscribe;
    presence_config.should_stop = app_should_stop;
    presence_config.stop_userdata = app;
    if (mhg_presence_source_create(&app->presence, &presence_config) != 0) {
        fputs("mhgeek-backend: presence allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    runtime_config.ops.now_ms = app_clock;
    runtime_config.ops.gate = app_gate;
    runtime_config.ops.lan_service_idle = app_lan_service_idle;
    runtime_config.ops.lan_connected = app_lan_connected;
    runtime_config.ops.lan_next_attempt_ms = app_lan_next_attempt;
    runtime_config.ops.lan_snapshot = app_lan_snapshot;
    runtime_config.ops.cloud_refresh = app_cloud_refresh;
    runtime_config.ops.lan_attempt = app_lan_attempt;
    runtime_config.ops.resources_sync = app_resources_sync;
    runtime_config.userdata = app;
    runtime_config.presence = app->presence;
    runtime_config.delivery = app->delivery;
    runtime_config.backoff_initial_ms = 1000u;
    runtime_config.backoff_max_ms = 30000u;
    runtime_config.cloud_retry_ms = 30000u;
    runtime_config.slow_ms = 1000u;
    runtime_config.stop = &g_stop;
    if (mhg_runtime_create(&app->runtime, &runtime_config) != 0) {
        fputs("mhgeek-backend: runtime allocation failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    app->bridge.enqueue = app_enqueue;
    app->bridge.operation = app_operation;
    app->bridge.userdata = app;
    app_refresh_snapshots(app);
    if (pthread_create(&app->presence_thread, NULL, presence_main, app) != 0) {
        fputs("mhgeek-backend: presence worker start failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    app->presence_thread_started = true;
    if (pthread_create(&app->scheduler_thread, NULL, scheduler_main, app) != 0) {
        fputs("mhgeek-backend: scheduler worker start failed\n", stderr);
        app_shutdown(app);
        return 1;
    }
    app->scheduler_thread_started = true;
    fprintf(stderr, "mhgeek-backend: serving module=%s account=%s target=%s\n",
            MHG_APP_MODULE, app->has_account ? "present" : "absent",
            app->has_target ? "present" : "absent");
    bridge_result = ainice_bridge_serve_until(MHG_APP_MODULE,
                                              app_bridge_request,
                                              app, app_should_stop,
                                              NULL);
    if (bridge_result != 0)
        fprintf(stderr, "mhgeek-backend: bridge failed result=%d\n",
                bridge_result);
    app_shutdown(app);
    return bridge_result == 0 ? 0 : 1;
}
