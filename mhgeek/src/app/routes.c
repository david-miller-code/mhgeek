#include "app.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ainice/protocol_error_codes.h"
#include "checked_json.h"
#include "target_resolver.h"
#include "target_store.h"

/* Identities of the nine slots; the display text is not an identity. */
static const char *const slot_identities[MHG_PRESENCE_SLOT_COUNT] = {
    "global", "zoneA", "zoneB", "zoneC", "zoneD",
    "zoneE", "zoneF", "zoneG", "zoneH",
};

static cJSON *health_get(void)
{
    cJSON *root = cJSON_CreateObject();

    if (!root ||
        subsys_json_add_string(root, "status", "ok") != 0 ||
        subsys_json_add_string(root, "module", MHG_APP_MODULE) != 0) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

static cJSON *presence_json(const struct mhg_bridge_context *context,
                            const struct mhg_runtime_status *status)
{
    cJSON *presence = cJSON_CreateObject();
    cJSON *zones = cJSON_CreateArray();
    struct mhg_presence_state state = status->presence;
    bool known = status->presence_known;
    int slot;

    (void)context;
    if (!presence || !zones ||
        subsys_json_add_bool(presence, "known", known) != 0 ||
        subsys_json_add_bool(presence, "global",
                             state.on[MHG_PRESENCE_GLOBAL]) != 0 ||
        subsys_json_add_number(presence, "snapshots",
                               (double)status->presence_snapshots) != 0 ||
        subsys_json_add_number(presence, "applied_ms",
                               (double)status->presence_ms) != 0) {
        cJSON_Delete(zones);
        cJSON_Delete(presence);
        return NULL;
    }
    for (slot = MHG_PRESENCE_ZONE_A; slot <= MHG_PRESENCE_ZONE_H; ++slot) {
        if (!cJSON_AddItemToArray(zones, cJSON_CreateBool(state.on[slot]))) {
            cJSON_Delete(zones);
            cJSON_Delete(presence);
            return NULL;
        }
    }
    if (subsys_json_attach_object(presence, "zones", &zones) != 0) {
        cJSON_Delete(zones);
        cJSON_Delete(presence);
        return NULL;
    }
    return presence;
}

static cJSON *target_json(const struct mhg_app_target_state *target)
{
    cJSON *entry = cJSON_CreateObject();

    if (!entry) return NULL;
    if (subsys_json_add_bool(entry, "configured",
                             target && target->configured) != 0 ||
        subsys_json_add_string(entry, "ip", target ? target->ip : "") != 0) {
        cJSON_Delete(entry);
        return NULL;
    }
    if (target && target->configured) {
        if (subsys_json_add_string(entry, "did_masked",
                                   target->did_masked) != 0 ||
            subsys_json_add_string(entry, "model_masked",
                                   target->model_masked) != 0) {
            cJSON_Delete(entry);
            return NULL;
        }
    }
    return entry;
}

static cJSON *status_get(struct mhg_bridge_context *context)
{
    struct mhg_runtime_status status;
    struct mhg_catalog_stats catalog = MHG_CATALOG_STATS_INIT;
    struct mhg_app_maintenance maintenance = {0};
    cJSON *root = cJSON_CreateObject();
    cJSON *cloud = cJSON_CreateObject();
    cJSON *lan = cJSON_CreateObject();
    cJSON *resources = cJSON_CreateObject();
    cJSON *delivery = cJSON_CreateObject();
    cJSON *presence = NULL;
    cJSON *target = NULL;

    if (!root || !cloud || !lan || !resources || !delivery) goto fail;
    memset(&status, 0, sizeof(status));
    if (context && context->status) status = *context->status;
    if (context && context->catalog) catalog = *context->catalog;
    if (context && context->maintenance_view)
        maintenance = *context->maintenance_view;
    else if (context && context->maintenance_state)
        context->maintenance_state(context->userdata, &maintenance);
    presence = presence_json(context, &status);
    target = target_json(context ? context->target_view : NULL);
    if (!presence || !target) goto fail;

    if (subsys_json_add_number(root, "state", status.state) != 0 ||
        subsys_json_add_string(root, "state_name",
                               mhg_runtime_state_name(status.state)) != 0 ||
        subsys_json_add_number(cloud, "driver", status.driver) != 0 ||
        subsys_json_add_string(cloud, "driver_name",
                               mhg_lan_driver_state_name(status.driver)) != 0 ||
        subsys_json_add_number(cloud, "last_error", status.last_error) != 0 ||
        subsys_json_add_string(cloud, "error_message",
                               context && context->lan_error ?
                                   context->lan_error : "") != 0 ||
        subsys_json_add_number(cloud, "refreshes",
                               (double)status.driver_stats.refreshes) != 0 ||
        subsys_json_add_number(cloud, "attempts",
                               (double)status.driver_stats.attempts) != 0 ||
        subsys_json_add_number(cloud, "cloud_failures",
                               (double)status.driver_stats.cloud_failures) != 0 ||
        subsys_json_add_number(cloud, "lan_failures",
                               (double)status.driver_stats.lan_failures) != 0 ||
        subsys_json_add_number(cloud, "reconnects",
                               (double)status.driver_stats.reconnects) != 0 ||
        subsys_json_add_number(cloud, "backoff_ms",
                               (double)status.driver_stats.backoff_ms) != 0 ||
        subsys_json_attach_object(root, "cloud", &cloud) != 0 ||
        subsys_json_add_number(lan, "state", status.lan) != 0 ||
        subsys_json_add_string(lan, "state_name",
                               mhg_lan_state_name(status.lan)) != 0 ||
        subsys_json_add_number(lan, "binding", status.binding) != 0 ||
        subsys_json_add_string(lan, "binding_name",
                               mhg_lan_binding_name(status.binding)) != 0 ||
        subsys_json_add_number(lan, "generation",
                               (double)status.lan_generation) != 0 ||
        subsys_json_add_number(lan, "devices",
                               (double)status.device_count) != 0 ||
        subsys_json_attach_object(root, "lan", &lan) != 0 ||
        subsys_json_add_bool(resources, "ready",
                             status.resources_ready) != 0 ||
        subsys_json_add_number(resources, "state",
                               context ? context->resource_state :
                                         MHG_RESOURCE_NONE) != 0 ||
        subsys_json_add_string(resources, "state_name",
                               mhg_resource_state_name(
                                   context ? context->resource_state :
                                             MHG_RESOURCE_NONE)) != 0 ||
        subsys_json_add_number(resources, "generation",
                               (double)catalog.directory_generation) != 0 ||
        subsys_json_add_number(resources, "devices_total",
                               context ? (double)context->catalog_device_count : 0) != 0 ||
        subsys_json_add_number(resources, "devices_skipped",
                               (double)catalog.entries_skipped) != 0 ||
        subsys_json_add_number(resources, "duplicates",
                               (double)catalog.duplicates) != 0 ||
        subsys_json_add_number(resources, "identity_conflicts",
                               (double)catalog.identity_conflicts) != 0 ||
        subsys_json_add_number(resources, "repair", maintenance.repair) != 0 ||
        subsys_json_add_number(resources, "config", maintenance.config) != 0 ||
        subsys_json_add_number(resources, "config_generation",
                               (double)maintenance.config_generation) != 0 ||
        subsys_json_add_number(resources, "maintenance_error",
                               maintenance.last_error) != 0 ||
        subsys_json_add_string(resources, "error_message",
                               context && context->resource_error ?
                                   context->resource_error : "") != 0 ||
        subsys_json_add_string(resources, "config_error_message",
                               context && context->config_error ?
                                   context->config_error : "") != 0 ||
        subsys_json_attach_object(root, "resources", &resources) != 0 ||
        subsys_json_add_number(delivery, "state", status.delivery) != 0 ||
        subsys_json_add_string(delivery, "state_name",
                               mhg_delivery_state_name(status.delivery)) != 0 ||
        subsys_json_add_number(delivery, "batches",
                               (double)status.delivery_stats.batches) != 0 ||
        subsys_json_add_number(delivery, "replays",
                               (double)status.delivery_stats.replays) != 0 ||
        subsys_json_add_number(delivery, "attempted",
                               (double)status.delivery_stats.events_attempted) != 0 ||
        subsys_json_add_number(delivery, "accepted",
                               (double)status.delivery_stats.events_accepted) != 0 ||
        subsys_json_add_number(delivery, "failed",
                               (double)status.delivery_stats.events_failed) != 0 ||
        subsys_json_add_number(delivery, "skipped",
                               (double)status.delivery_stats.events_skipped) != 0 ||
        subsys_json_add_number(delivery, "pauses",
                               (double)status.delivery_stats.pauses) != 0 ||
        subsys_json_add_number(delivery, "retries",
                               (double)status.delivery_stats.retries) != 0 ||
        subsys_json_add_number(delivery, "superseded",
                               (double)status.delivery_stats.superseded) != 0 ||
        subsys_json_add_string(delivery, "error_message",
                               status.delivery_stats.error_message) != 0 ||
        subsys_json_attach_object(root, "delivery", &delivery) != 0 ||
        subsys_json_attach_object(root, "presence", &presence) != 0 ||
        subsys_json_attach_object(root, "target", &target) != 0)
        goto fail;
    return root;

fail:
    cJSON_Delete(presence);
    cJSON_Delete(target);
    cJSON_Delete(delivery);
    cJSON_Delete(resources);
    cJSON_Delete(lan);
    cJSON_Delete(cloud);
    cJSON_Delete(root);
    return NULL;
}

static cJSON *virtual_events_get(struct mhg_bridge_context *context)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *slots = cJSON_CreateArray();
    int slot;

    if (!root || !slots ||
        subsys_json_add_number(root, "config_generation", context ? (double)context->config_generation : 0) ||
        subsys_json_add_number(root, "synced_config_generation", context ? (double)context->synced_config_generation : 0) ||
        subsys_json_add_bool(root, "sync_pending", !context || !context->status || !context->status->resources_ready || context->resource_state != MHG_RESOURCE_READY) ||
        subsys_json_add_string(root, "prefix",
                               context && context->prefix ?
                                   context->prefix : "") != 0)
        goto fail;
    for (slot = 0; slot < MHG_PRESENCE_SLOT_COUNT; ++slot) {
        cJSON *entry = cJSON_CreateObject();
        const char *present_text =
            context && context->texts ? context->texts[slot * 2] : NULL;
        const char *absent_text =
            context && context->texts ? context->texts[slot * 2 + 1] : NULL;

        if (!entry ||
            subsys_json_add_number(entry, "slot", slot) != 0 ||
            subsys_json_add_number(entry, "absent_seconds",
                context && context->absent_seconds ? context->absent_seconds[slot] : 1) != 0 ||
            subsys_json_add_string(entry, "id", slot_identities[slot]) != 0 ||
            subsys_json_add_string(entry, "present_text",
                                   present_text ? present_text : "") != 0 ||
            subsys_json_add_string(entry, "absent_text",
                                   absent_text ? absent_text : "") != 0 ||
            !cJSON_AddItemToArray(slots, entry)) {
            cJSON_Delete(entry);
            goto fail;
        }
    }
    if (subsys_json_attach_object(root, "slots", &slots) != 0) goto fail;
    return root;

fail:
    cJSON_Delete(slots);
    cJSON_Delete(root);
    return NULL;
}

static cJSON *submit_request(struct mhg_bridge_context *context,
                             struct mhg_app_request *request,
                             const char *operation);

/* Authorization routes: the frontend sends an operation id and polls
 * /auth/status; the scheduler thread performs the single network step. */
static cJSON *auth_status_get(struct mhg_bridge_context *context)
{
    struct mhg_app_auth_state state;
    cJSON *root = cJSON_CreateObject();
    cJSON *account = NULL;

    memset(&state, 0, sizeof(state));
    if (context && context->auth_view)
        state = *context->auth_view;
    else if (context && context->auth_state)
        context->auth_state(context->userdata, &state);
    account = state.has_account ? cJSON_CreateObject() : cJSON_CreateNull();
    if (!root || !account ||
        subsys_json_add_number(root, "state", state.state) != 0 ||
        subsys_json_add_string(root, "state_name", state.state_name) != 0 ||
        subsys_json_add_number(root, "phase", state.phase) != 0 ||
        subsys_json_add_string(root, "phase_name", state.phase_name) != 0 ||
        subsys_json_add_number(root, "error", state.error) != 0 ||
        subsys_json_add_string(root, "error_name", state.error_name) != 0 ||
        subsys_json_add_bool(root, "has_account", state.has_account) != 0 ||
        subsys_json_add_number(root, "account_generation",
                               (double)state.account_generation) != 0 ||
        subsys_json_add_number(root, "challenge_generation",
                               (double)state.challenge_generation) != 0 ||
        subsys_json_add_number(root, "operation_id",
                               (double)state.operation_id) != 0 ||
        subsys_json_add_number(root, "code_length", state.code_length) != 0 ||
        subsys_json_add_number(root, "retry_after_seconds",
                               state.retry_after_seconds) != 0 ||
        subsys_json_add_number(root, "provider_scope",
                               state.provider_scope) != 0 ||
        subsys_json_add_string(root, "provider_scope_name",
                               state.provider_scope_name) != 0 ||
        subsys_json_add_number(root, "provider_class",
                               state.provider_class) != 0 ||
        subsys_json_add_string(root, "provider_class_name",
                               state.provider_class_name) != 0 ||
        subsys_json_add_number(root, "provider_code",
                               state.provider_code) != 0 ||
        subsys_json_add_number(root, "pending_store_outcome",
                               state.pending_store_outcome) != 0 ||
        subsys_json_add_string(root, "message_key",
                               state.message_key) != 0) {
        cJSON_Delete(root);
        cJSON_Delete(account);
        return NULL;
    }
    if (state.has_account &&
        subsys_json_add_string(account, "masked_id",
                               state.masked_account_id) != 0) {
        cJSON_Delete(root);
        cJSON_Delete(account);
        return NULL;
    }
    if (subsys_json_attach_object(root, "account", &account) != 0) {
        cJSON_Delete(root);
        cJSON_Delete(account);
        return NULL;
    }
    return root;
}

static cJSON *auth_submit(struct mhg_bridge_context *context, cJSON *body,
                          const char *operation, enum mhg_app_request_kind kind,
                          const char *const *required)
{
    struct mhg_app_request request = {0};
    size_t index;

    request.kind = kind;
    if (required) {
        for (index = 0u; required[index]; ++index) {
            const char *value = body ? cJSON_GetStringValue(
                cJSON_GetObjectItemCaseSensitive(body, required[index])) : NULL;

            if (!value || !value[0])
                return mhg_app_error(AINICE_PROTOCOL_ERROR_MISSING_REQUIRED,
                                     required[index]);
            if (strcmp(required[index], "calling_code") == 0)
                snprintf(request.calling_code, sizeof(request.calling_code),
                         "%s", value);
            else if (strcmp(required[index], "national_number") == 0)
                snprintf(request.national_number,
                         sizeof(request.national_number), "%s", value);
            else if (strcmp(required[index], "code") == 0)
                snprintf(request.code, sizeof(request.code), "%s", value);
        }
    }
    if (body) {
        const cJSON *persist =
            cJSON_GetObjectItemCaseSensitive(body, "retry_persist");
        const cJSON *generation =
            cJSON_GetObjectItemCaseSensitive(body, "challenge_generation");

        request.retry_persist = cJSON_IsTrue(persist);
        if (generation) {
            if (!cJSON_IsNumber(generation) || !(generation->valuedouble >= 0) ||
                generation->valuedouble > 9007199254740991.0 ||
                (double)(uint64_t)generation->valuedouble != generation->valuedouble)
                return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST, "invalid challenge generation");
            request.challenge_generation = (uint64_t)generation->valuedouble;
        }
    }
    return submit_request(context, &request, operation);
}

/* The scheduler commits a partial local configuration, then independently
 * synchronizes the generated graph to its durable generation. */
static cJSON *virtual_events_put(struct mhg_bridge_context *context, cJSON *body)
{
    struct mhg_app_request request = {0};
    const cJSON *prefix = body ?
        cJSON_GetObjectItemCaseSensitive(body, "prefix") : NULL;
    const cJSON *slots = body ?
        cJSON_GetObjectItemCaseSensitive(body, "slots") : NULL;
    const cJSON *entry;

    if (!body || (!prefix && !slots))
        return mhg_app_error(AINICE_PROTOCOL_ERROR_MISSING_REQUIRED,
                             "prefix or slots is required");
    if (prefix) {
        const char *text = cJSON_GetStringValue(prefix);

        if (text && (strlen(text) > MHG_EVENT_PREFIX_LIMIT ||
                     (text[0] != '\0' && !mhg_event_config_text_is_valid(
                          text, MHG_EVENT_PREFIX_LIMIT)))) {
            if (text[0] != '\0')
                return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                                     "prefix is not printable or is too long");
        }
        if (!text ||
            (text[0] != '\0' &&
             !mhg_event_config_text_is_valid(text, MHG_EVENT_PREFIX_LIMIT)))
            return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                                 "prefix is not printable or is too long");
        request.has_prefix = true;
        snprintf(request.prefix, sizeof(request.prefix), "%s", text);
    }
    if (slots) {
        if (!cJSON_IsArray(slots))
            return mhg_app_error(AINICE_PROTOCOL_ERROR_ROUTE_BODY_INVALID,
                                 "slots must be an array");
        cJSON_ArrayForEach(entry, slots) {
            const cJSON *slot_item =
                cJSON_GetObjectItemCaseSensitive(entry, "slot");
            const cJSON *present_text =
                cJSON_GetObjectItemCaseSensitive(entry, "present_text");
            const cJSON *absent_text =
                cJSON_GetObjectItemCaseSensitive(entry, "absent_text");
            const cJSON *seconds = cJSON_GetObjectItemCaseSensitive(entry, "absent_seconds");
            int slot;

            if (!cJSON_IsObject(entry) || !cJSON_IsNumber(slot_item))
                return mhg_app_error(AINICE_PROTOCOL_ERROR_ROUTE_BODY_INVALID,
                                     "each slot needs a numeric slot");
            if (!(slot_item->valuedouble >= 0) || slot_item->valuedouble >= MHG_PRESENCE_SLOT_COUNT)
                return mhg_app_error(AINICE_PROTOCOL_ERROR_ROUTE_BODY_INVALID, "slot is out of range");
            slot = (int)slot_item->valuedouble;
            if (slot < 0 || slot >= MHG_PRESENCE_SLOT_COUNT)
                return mhg_app_error(AINICE_PROTOCOL_ERROR_ROUTE_BODY_INVALID,
                                     "slot is out of range");
            if (slot_item->valuedouble != slot)
                return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST, "slot must be an integer");
            if (seconds) {
                if (!cJSON_IsNumber(seconds) ||
                    !mhg_event_config_seconds_valid(seconds->valuedouble))
                    return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST, "absent_seconds is invalid");
                request.set_absent_seconds[slot] = true;
                request.absent_seconds[slot] = seconds->valuedouble;
            }
            if (present_text) {
                const char *text = cJSON_GetStringValue(present_text);

                if (!mhg_event_config_text_is_valid(text,
                                                    MHG_EVENT_TEXT_LIMIT))
                    return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                                         "present_text is invalid");
                request.set_texts[slot * 2] = true;
                snprintf(request.texts[slot * 2],
                         sizeof(request.texts[slot * 2]), "%s", text);
            }
            if (absent_text) {
                const char *text = cJSON_GetStringValue(absent_text);

                if (!mhg_event_config_text_is_valid(text,
                                                    MHG_EVENT_TEXT_LIMIT))
                    return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                                         "absent_text is invalid");
                request.set_texts[slot * 2 + 1] = true;
                snprintf(request.texts[slot * 2 + 1],
                         sizeof(request.texts[slot * 2 + 1]), "%s", text);
            }
        }
    }
    request.kind = MHG_APP_REQUEST_CONFIG_SET;
    return submit_request(context, &request, "virtual_events_put");
}

static cJSON *accepted(const char *operation, const struct mhg_app_request *request)
{
    cJSON *root = cJSON_CreateObject();

    if (!root ||
        subsys_json_add_bool(root, "accepted", true) != 0 ||
        subsys_json_add_number(root, "operation_id", (double)request->operation_id) != 0 ||
        subsys_json_add_string(root, "instance_id", request->instance_id) != 0 ||
        subsys_json_add_string(root, "operation_state", "queued") != 0 ||
        subsys_json_add_string(root, "operation", operation) != 0) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

/* Queue one scheduler action; a full queue is "busy", not a silent drop. */
static cJSON *submit_request(struct mhg_bridge_context *context,
                             struct mhg_app_request *request,
                             const char *operation)
{
    if (!context || !context->enqueue)
        return mhg_app_error(AINICE_PROTOCOL_ERROR_NOT_AVAILABLE,
                             "plugin is not started");
    if (!mhg_app_request_is_auth(request->kind)) {
        struct mhg_app_auth_state state = {0};
        if (context->auth_view) state = *context->auth_view;
        else if (context->auth_state)
            context->auth_state(context->userdata, &state);
        if (!state.has_account || state.state != MHG_AUTH_SMS_AUTHENTICATED)
            return mhg_app_error(AINICE_PROTOCOL_ERROR_UNAUTHORIZED,
                                 "please authorize the account first");
    }
    if (!context->enqueue(context->userdata, request))
        return mhg_app_error(AINICE_PROTOCOL_ERROR_BUSY,
                             "another operation is still pending");
    return accepted(operation, request);
}

static cJSON *target_get(struct mhg_bridge_context *context)
{
    struct mhg_app_target_state state;
    cJSON *root = cJSON_CreateObject();
    char ip[MHG_TARGET_IP_LIMIT];

    memset(&state, 0, sizeof(state));
    if (context && context->target_view) state = *context->target_view;
    snprintf(ip, sizeof(ip), "%s", state.ip);
    if (!root ||
        subsys_json_add_bool(root, "configured", state.configured) != 0 ||
        subsys_json_add_bool(root, "locked", state.locked) != 0 ||
        subsys_json_add_number(root, "state", state.state) != 0 ||
        subsys_json_add_string(root, "state_name",
                               mhg_target_state_name((enum mhg_target_state)
                                                         state.state)) != 0 ||
        subsys_json_add_number(root, "last_outcome", state.outcome) != 0 ||
        subsys_json_add_string(root, "last_outcome_name",
                               mhg_target_outcome_name(
                                   (enum mhg_target_outcome)state.outcome)) != 0 ||
        subsys_json_add_number(root, "last_error", state.last_error) != 0 ||
        subsys_json_add_string(root, "ip", ip) != 0 ||
        subsys_json_add_string(root, "model_masked",
                               state.model_masked) != 0) {
        cJSON_Delete(root);
        return NULL;
    }
    if (state.configured &&
        subsys_json_add_string(root, "did", state.did) != 0) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

static cJSON *target_put(struct mhg_bridge_context *context, cJSON *body)
{
    struct mhg_app_request request = {0};
    const char *ip = body ?
        cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(body, "ip")) : NULL;
    const char *did = body ?
        cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(body, "did")) : NULL;
    struct mhg_app_target_state state;

    memset(&state, 0, sizeof(state));
    if (context && context->target_view) state = *context->target_view;
    /* Saving locks the binding; changing it starts with an explicit clear. */
    if (state.locked)
        return mhg_app_error(AINICE_PROTOCOL_ERROR_CONFLICT,
                             "target is locked; clear it before changing it");
    if (!mhg_target_field_is_valid(ip, MHG_TARGET_IP_LIMIT))
        return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                             "ip must be a bounded printable address");
    if (did && did[0] && !mhg_target_field_is_valid(did, MHG_TARGET_DID_LIMIT))
        return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                             "did must be bounded printable text");
    request.kind = MHG_APP_REQUEST_TARGET_SET;
    snprintf(request.ip, sizeof(request.ip), "%s", ip);
    if (did && did[0]) {
        snprintf(request.did, sizeof(request.did), "%s", did);
        request.has_did = true;
    }
    return submit_request(context, &request, "target_set");
}

static cJSON *operation_get(struct mhg_bridge_context *context, cJSON *query)
{
    const cJSON *value = query ? cJSON_GetObjectItemCaseSensitive(query, "id") : NULL;
    uint64_t id = 0;
    if (cJSON_IsString(value)) {
        char *end = NULL;
        errno = 0;
        id = strtoull(value->valuestring, &end, 10);
        if (errno || !end || end == value->valuestring || *end || value->valuestring[0] == '-') id = 0;
    } else if (cJSON_IsNumber(value) && value->valuedouble >= 1 &&
               value->valuedouble <= 9007199254740991.0) {
        id = (uint64_t)value->valuedouble;
        if ((double)id != value->valuedouble) id = 0;
    }
    if (!id || id > 9007199254740991ULL)
        return mhg_app_error(AINICE_PROTOCOL_ERROR_BAD_REQUEST, "invalid operation id");
    const char *instance = query ? cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(query, "instance_id")) : NULL;
    struct mhg_app_operation op;
    static const char *const states[] = {"queued", "running", "waiting_sync", "succeeded", "failed", "superseded"};
    static const char *const errors[] = {
        [MHG_OP_OK] = "", [MHG_OP_UNAUTHORIZED] = "unauthorized",
        [MHG_OP_CLOUD_FAILED] = "cloud_failed", [MHG_OP_TARGET_FAILED] = "target_failed",
        [MHG_OP_STORE_FAILED] = "store_failed", [MHG_OP_SYNC_FAILED] = "sync_failed",
        [MHG_OP_AUTH_FAILED] = "auth_failed", [MHG_OP_CANCELLED] = "cancelled",
        [MHG_OP_TARGET_CATALOG_FAILED] = "target_catalog_failed",
        [MHG_OP_TARGET_NOT_FOUND] = "target_not_found",
        [MHG_OP_TARGET_AMBIGUOUS] = "target_ambiguous",
        [MHG_OP_TARGET_CONFLICT] = "target_conflict",
        [MHG_OP_TARGET_PROBE_FAILED] = "target_probe_failed"
    };
    if (!context || !context->operation || !context->operation(context->userdata, id, &op) ||
        !instance || strcmp(instance, op.instance_id) != 0)
        return mhg_app_error(AINICE_PROTOCOL_ERROR_NOT_AVAILABLE, "operation not found");
    cJSON *root = cJSON_CreateObject();
    if (!root || subsys_json_add_number(root, "operation_id", (double)op.operation_id) ||
        subsys_json_add_string(root, "instance_id", op.instance_id) ||
        subsys_json_add_number(root, "kind", op.kind) ||
        subsys_json_add_string(root, "state", states[op.state]) ||
        subsys_json_add_string(root, "error_code", errors[op.error]) ||
        subsys_json_add_string(root, "diagnostic", op.diagnostic) ||
        subsys_json_add_string(root, "message_key", op.message_key) ||
        subsys_json_add_number(root, "config_generation", (double)op.config_generation)) {
        cJSON_Delete(root); return NULL;
    }
    return root;
}

cJSON *mhg_app_route(struct mhg_bridge_context *context, const char *method,
                     const char *path, cJSON *query, cJSON *body)
{
    if (strcmp(path, "/operations") == 0 && strcmp(method, "GET") == 0)
        return operation_get(context, query);
    if (strcmp(path, "/auth/status") == 0 && strcmp(method, "GET") == 0)
        return auth_status_get(context);
    if (strcmp(path, "/auth/sms/start") == 0 && strcmp(method, "POST") == 0) {
        static const char *const required[] = {"calling_code",
                                               "national_number", NULL};

        return auth_submit(context, body, "auth_start",
                           MHG_APP_REQUEST_AUTH_START, required);
    }
    if (strcmp(path, "/auth/sms/verify") == 0 && strcmp(method, "POST") == 0) {
        static const char *const required[] = {"code", NULL};

        return auth_submit(context, body, "auth_verify",
                           MHG_APP_REQUEST_AUTH_VERIFY, required);
    }
    if (strcmp(path, "/auth/sms/resend") == 0 && strcmp(method, "POST") == 0)
        return auth_submit(context, body, "auth_resend",
                           MHG_APP_REQUEST_AUTH_RESEND, NULL);
    if (strcmp(path, "/auth/retry") == 0 && strcmp(method, "POST") == 0)
        return auth_submit(context, body, "auth_retry",
                           MHG_APP_REQUEST_AUTH_RETRY, NULL);
    if (strcmp(path, "/auth/cancel") == 0 && strcmp(method, "POST") == 0)
        return auth_submit(context, body, "auth_cancel",
                           MHG_APP_REQUEST_AUTH_CANCEL, NULL);
    if (strcmp(path, "/auth/clear") == 0 && strcmp(method, "POST") == 0)
        return auth_submit(context, body, "auth_clear",
                           MHG_APP_REQUEST_AUTH_CLEAR, NULL);
    if (strcmp(path, "/health") == 0 && strcmp(method, "GET") == 0)
        return health_get();
    if (strcmp(path, "/gateway/status") == 0 && strcmp(method, "GET") == 0)
        return status_get(context);
    if (strcmp(path, "/gateway/virtual-events") == 0 &&
        strcmp(method, "GET") == 0)
        return virtual_events_get(context);
    if (strcmp(path, "/gateway/target") == 0 && strcmp(method, "GET") == 0)
        return target_get(context);
    if (strcmp(path, "/gateway/virtual-events") == 0 &&
        strcmp(method, "PUT") == 0)
        return virtual_events_put(context, body);
    if (strcmp(path, "/gateway/target") == 0 && strcmp(method, "PUT") == 0)
        return target_put(context, body);
    if (strcmp(path, "/gateway/target/clear") == 0 &&
        strcmp(method, "POST") == 0) {
        struct mhg_app_request request = {0};

        request.kind = MHG_APP_REQUEST_TARGET_CLEAR;
        return submit_request(context, &request, "target_clear");
    }
    if (strcmp(path, "/gateway/replay") == 0 && strcmp(method, "POST") == 0) {
        struct mhg_app_request request = {0};

        request.kind = MHG_APP_REQUEST_REPLAY;
        return submit_request(context, &request, "replay");
    }
    if (strcmp(path, "/gateway/resources/repair") == 0 &&
        strcmp(method, "POST") == 0) {
        struct mhg_app_request request = {0};

        request.kind = MHG_APP_REQUEST_RESYNC;
        return submit_request(context, &request, "resources_repair");
    }
    if (strcmp(path, "/gateway/reconnect") == 0 &&
        strcmp(method, "POST") == 0) {
        struct mhg_app_request request = {0};

        request.kind = MHG_APP_REQUEST_RECONNECT;
        return submit_request(context, &request, "reconnect");
    }
    /* Unknown routes are handled by the Bridge error envelope. */
    return NULL;
}
