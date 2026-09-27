#include "resource_lan.h"

#include "board_identity.h"
#include "event_config_store.h"
#include "resource_graph.h"
#include "secret_json.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mhg_resource_lan {
    struct mhg_resource_lan_config config;
    /* The owner outlives the caller's buffers: the app reloads the target
     * record on every slow step (which frees the old one) and the harness
     * loads it into a stack record, so the identity is copied in here. */
    struct mhg_secret_buf target_did;
    struct mhg_secret_buf target_model;
    struct mhg_secret_buf urn;
    struct mhg_secret_buf texts[MHG_RESOURCE_VARIABLE_COUNT];
    const char *text_pointers[MHG_RESOURCE_VARIABLE_COUNT];
    double absent_seconds[MHG_PRESENCE_SLOT_COUNT];
};

static const char *const state_variable_labels[MHG_RESOURCE_STATE_VARIABLE_COUNT] = {
    "全局状态", "A区状态", "B区状态", "C区状态", "D区状态",
    "E区状态",  "F区状态", "G区状态", "H区状态"};

static const char
    *const local_state_variable_labels[MHG_RESOURCE_STATE_VARIABLE_COUNT] = {
        "全局状态变更", "A区状态变更", "B区状态变更", "C区状态变更", "D区状态变更",
        "E区状态变更",  "F区状态变更", "G区状态变更", "H区状态变更"};

int mhg_resource_lan_create(struct mhg_resource_lan **owner_out,
                            const struct mhg_resource_lan_config *config)
{
    struct mhg_resource_lan *owner;

    if (owner_out)
        *owner_out = NULL;
    if (!owner_out || !config || !config->ops.call || !config->target_did ||
        !config->target_model || !config->urn || !config->texts ||
        !config->absent_seconds || config->siid <= 0 || config->aiid <= 0 ||
        config->piid <= 0)
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner)
        return -1;
    owner->config = *config;
    if (mhg_secret_buf_set(&owner->target_did, config->target_did,
                           strlen(config->target_did)) != 0 ||
        mhg_secret_buf_set(&owner->target_model, config->target_model,
                           strlen(config->target_model)) != 0 ||
        mhg_secret_buf_set(&owner->urn, config->urn, strlen(config->urn)) != 0) {
        mhg_resource_lan_destroy(owner);
        return -1;
    }
    owner->config.target_did = (const char *)owner->target_did.data;
    owner->config.target_model = (const char *)owner->target_model.data;
    owner->config.urn = (const char *)owner->urn.data;
    for (size_t i = 0; i < MHG_RESOURCE_VARIABLE_COUNT; ++i) {
        if (!config->texts[i] || mhg_secret_buf_set(&owner->texts[i], config->texts[i],
                                                    strlen(config->texts[i]))) {
            mhg_resource_lan_destroy(owner);
            return -1;
        }
        owner->text_pointers[i] = (const char *)owner->texts[i].data;
    }
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; ++i) {
        if (!mhg_event_config_seconds_valid(config->absent_seconds[i])) {
            mhg_resource_lan_destroy(owner);
            return -1;
        }
        owner->absent_seconds[i] = config->absent_seconds[i];
    }
    owner->config.texts = owner->text_pointers;
    owner->config.absent_seconds = owner->absent_seconds;
    *owner_out = owner;
    return 0;
}

void mhg_resource_lan_destroy(struct mhg_resource_lan *owner)
{
    if (!owner)
        return;
    mhg_secret_buf_clear(&owner->target_did);
    mhg_secret_buf_clear(&owner->target_model);
    mhg_secret_buf_clear(&owner->urn);
    for (size_t i = 0; i < MHG_RESOURCE_VARIABLE_COUNT; ++i)
        mhg_secret_buf_clear(&owner->texts[i]);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

static struct mhg_resource_lan *lan(void *userdata)
{
    return userdata;
}

/* A JSON-RPC error payload is a rejection, not a success: the session layer
 * reports the exchange as fine because the channel itself worked. */
static int jsonrpc_error(const char *method, cJSON **reply, struct mhg_error *error)
{
    const cJSON *item;
    const cJSON *code;
    const cJSON *message;

    if (!reply || !*reply)
        return 0;
    item = cJSON_GetObjectItemCaseSensitive(*reply, "error");
    if (!item)
        return 0;
    code = cJSON_GetObjectItemCaseSensitive(item, "code");
    message = cJSON_GetObjectItemCaseSensitive(item, "message");
    mhg_errorf(error, EREMOTEIO, "%s rejected by the gateway: code=%d %s", method,
               cJSON_IsNumber(code) ? (int)code->valuedouble : 0,
               cJSON_IsString(message) ? message->valuestring : "");
    cJSON_Delete(*reply);
    *reply = NULL;
    return -1;
}

static int call(struct mhg_resource_lan *owner, const char *method, const cJSON *params,
                cJSON **reply, struct mhg_error *error)
{
    if (owner->config.ops.call(owner->config.userdata, method, params, reply, error))
        return -1;
    return jsonrpc_error(method, reply, error);
}

static const cJSON *result_of(const cJSON *reply)
{
    return reply ? cJSON_GetObjectItemCaseSensitive(reply, "result") : NULL;
}

static int attach_object(cJSON *parent, const char *key, cJSON **child)
{
    if (!child || !*child || !cJSON_AddItemToObject(parent, key, *child))
        return 0;
    *child = NULL;
    return 1;
}

static const char *identity_slot(size_t index)
{
    static const char *const names[MHG_PRESENCE_SLOT_COUNT] = {
        "global", "zoneA", "zoneB", "zoneC", "zoneD",
        "zoneE",  "zoneF", "zoneG", "zoneH",
    };

    return names[(index / 2u) % MHG_PRESENCE_SLOT_COUNT];
}

static int fill_identity(const struct mhg_resource_lan *owner, const char *identity,
                         struct mhg_resource_record *record)
{
    char id[64];
    size_t index;

    snprintf(id, sizeof(id), "mhg%sV3", identity);
    if (mhg_secret_buf_set(&record->graph_id, id, strlen(id)) != 0)
        return -1;
    snprintf(id, sizeof(id), "Rmhg%sV3", identity);
    if (mhg_secret_buf_set(&record->scope, id, strlen(id)) != 0 ||
        mhg_secret_buf_set(&record->target_did, owner->config.target_did,
                           strlen(owner->config.target_did)) != 0 ||
        mhg_secret_buf_set(&record->target_model, owner->config.target_model,
                           strlen(owner->config.target_model)) != 0 ||
        mhg_secret_buf_set(&record->action_urn, owner->config.urn,
                           strlen(owner->config.urn)) != 0)
        return -1;
    record->action_siid = owner->config.siid;
    record->action_aiid = owner->config.aiid;
    record->action_piid = owner->config.piid;
    for (index = 0u; index < MHG_RESOURCE_STATE_VARIABLE_COUNT; ++index) {
        const char *slot = identity_slot(index * 2u);

        snprintf(id, sizeof(id), "%sState", slot);
        if (mhg_secret_buf_set(&record->local_variables[index], id, strlen(id)) != 0)
            return -1;
        snprintf(id, sizeof(id), "mhg%s%sState", identity, slot);
        if (mhg_secret_buf_set(&record->global_variables[index], id, strlen(id)) != 0)
            return -1;
    }
    return 0;
}

int mhg_resource_lan_plan(void *userdata, struct mhg_resource_record *record,
                          struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    struct mhg_resource_record next = MHG_RESOURCE_RECORD_INIT;
    char identity[32], digest[33];
    cJSON *graph = NULL;
    int result = -1;
    if (!owner || !record || mhg_board_identity_hex(identity, sizeof(identity)))
        return mhg_errorf(error, ENODEV, "board identity unavailable");
    next.version = MHG_RESOURCE_VERSION;
    next.resource_generation = owner->config.resource_generation;
    next.spec_generation = owner->config.spec_generation;
    next.config_generation = owner->config.config_generation;
    if (fill_identity(owner, identity, &next))
        goto done;
    graph = mhg_resource_graph_build(&owner->config, &next, false, error);
    if (!graph ||
        mhg_resource_graph_digest(cJSON_GetObjectItemCaseSensitive(graph, "nodes"),
                                  digest) ||
        mhg_secret_buf_set(&next.digest, digest, strlen(digest)))
        goto done;
    mhg_resource_record_clear(record);
    *record = next;
    next = (struct mhg_resource_record)MHG_RESOURCE_RECORD_INIT;
    result = 0;
done:
    cJSON_Delete(graph);
    mhg_resource_record_clear(&next);
    return result;
}
static int find_variable(const cJSON *list, const char *id, int *found, int *type_ok)
{
    const cJSON *item;

    *found = 0;
    *type_ok = 0;
    if (cJSON_IsObject(list)) {
        item = cJSON_GetObjectItemCaseSensitive(list, id);
        if (!item)
            return 0;
        {
            const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");

            *found = 1;
            *type_ok = cJSON_IsString(type) && strcmp(type->valuestring, "number") == 0;
        }
        return 0;
    }
    if (cJSON_IsArray(list)) {
        cJSON_ArrayForEach(item, list)
        {
            const cJSON *entry_id = cJSON_GetObjectItemCaseSensitive(item, "id");
            const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");

            if (!cJSON_IsString(entry_id) || strcmp(entry_id->valuestring, id) != 0)
                continue;
            *found = 1;
            *type_ok = cJSON_IsString(type) && strcmp(type->valuestring, "number") == 0;
            return 0;
        }
        return 0;
    }
    return -1;
}

static bool variable_list_rejected(const cJSON *list)
{
    const cJSON *code =
        cJSON_IsObject(list) ? cJSON_GetObjectItemCaseSensitive(list, "code") : NULL;

    return cJSON_IsNumber(code) && code->valuedouble < 0.0;
}

static const cJSON *variable_entry_for_id(const cJSON *list, const char *id)
{
    const cJSON *item;
    const cJSON *match = NULL;

    if (cJSON_IsObject(list))
        return cJSON_GetObjectItemCaseSensitive(list, id);
    if (!cJSON_IsArray(list))
        return NULL;
    cJSON_ArrayForEach(item, list)
    {
        const cJSON *entry_id = cJSON_GetObjectItemCaseSensitive(item, "id");

        if (!cJSON_IsString(entry_id) || strcmp(entry_id->valuestring, id) != 0)
            continue;
        if (match)
            return NULL;
        match = item;
    }
    return match;
}

static int global_variable_name(size_t index, char *out, size_t size)
{
    char identity[32];
    if (mhg_board_identity_text(identity, sizeof(identity)))
        return -1;
    int n = snprintf(out, size, "%s - AInice视觉空间 (%s)",
                     state_variable_labels[index], identity);
    return n < 0 || (size_t)n >= size ? -1 : 0;
}
static bool binding_matches(const struct mhg_resource_lan *owner,
                            const struct mhg_resource_record *record)
{
    return owner && record && record->version == MHG_RESOURCE_VERSION &&
           record->graph_id.data && record->scope.data &&
           record->local_variables[0].data && record->global_variables[0].data &&
           record->target_did.data && record->target_model.data &&
           record->action_urn.data &&
           strcmp((const char *)record->target_did.data, owner->config.target_did) ==
               0 &&
           strcmp((const char *)record->target_model.data,
                  owner->config.target_model) == 0 &&
           strcmp((const char *)record->action_urn.data, owner->config.urn) == 0 &&
           record->action_siid == owner->config.siid &&
           record->action_aiid == owner->config.aiid &&
           record->action_piid == owner->config.piid;
}

static bool identity_matches(const struct mhg_resource_record *record,
                             const char *identity)
{
    char expected[80];
    size_t index;

    if (!record || !identity)
        return false;
    snprintf(expected, sizeof(expected), "mhg%sV3", identity);
    if (!record->graph_id.data ||
        strcmp((const char *)record->graph_id.data, expected) != 0)
        return false;
    snprintf(expected, sizeof(expected), "Rmhg%sV3", identity);
    if (!record->scope.data || strcmp((const char *)record->scope.data, expected) != 0)
        return false;
    for (index = 0u; index < MHG_RESOURCE_STATE_VARIABLE_COUNT; ++index) {
        const char *slot = identity_slot(index * 2u);

        snprintf(expected, sizeof(expected), "%sState", slot);
        if (!record->local_variables[index].data ||
            strcmp((const char *)record->local_variables[index].data, expected) != 0)
            return false;
        snprintf(expected, sizeof(expected), "mhg%s%sState", identity, slot);
        if (!record->global_variables[index].data ||
            strcmp((const char *)record->global_variables[index].data, expected) != 0)
            return false;
    }
    return true;
}

static bool owned_identity(const struct mhg_resource_lan *owner,
                           const struct mhg_resource_record *record)
{
    char identity[32];
    return binding_matches(owner, record) &&
           !mhg_board_identity_hex(identity, sizeof(identity)) &&
           identity_matches(record, identity);
}

enum mhg_resource_reconcile_result
mhg_resource_lan_seed_guard(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    char identity[32];
    cJSON *reply = NULL;
    if (!binding_matches(owner, record) ||
        mhg_board_identity_hex(identity, sizeof(identity)) ||
        !identity_matches(record, identity)) {
        mhg_errorf(error, EPROTO, "resource target binding differs");
        return MHG_RESOURCE_RECONCILE_DRIFTED;
    }
    if (call(owner, "/api/getDevList", NULL, &reply, error))
        return MHG_RESOURCE_RECONCILE_RETRY;
    const cJSON *devices =
        cJSON_GetObjectItemCaseSensitive(result_of(reply), "devList");
    const cJSON *target = cJSON_GetObjectItemCaseSensitive(
        devices, (const char *)record->target_did.data);
    const cJSON *urn = cJSON_GetObjectItemCaseSensitive(target, "urn");
    bool valid = cJSON_IsString(urn) &&
                 !strcmp(urn->valuestring, (const char *)record->action_urn.data);
    cJSON_Delete(reply);
    if (!valid)
        mhg_errorf(error, EPROTO, "live target action differs");
    return valid ? MHG_RESOURCE_RECONCILE_OK : MHG_RESOURCE_RECONCILE_DRIFTED;
}
static enum mhg_resource_seed_probe_result
seed_probe_scope(void *userdata, const struct mhg_resource_record *record, bool global,
                 struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    cJSON *params = NULL;
    cJSON *reply = NULL;
    const cJSON *list;
    int found = 0;
    int type_ok = 0;
    enum mhg_resource_seed_probe_result result = MHG_RESOURCE_SEED_RETRY;

    if (!owned_identity(owner, record)) {
        mhg_errorf(error, EPROTO, "resource target binding differs");
        return MHG_RESOURCE_SEED_DRIFTED;
    }
    params = cJSON_CreateObject();
    if (!params ||
        !cJSON_AddStringToObject(
            params, "scope", global ? "global" : (const char *)record->scope.data)) {
        mhg_errorf(error, ENOMEM, "seed probe allocation failed");
        goto done;
    }
    if (call(owner, "/api/getVarList", params, &reply, error)) {
        if (error && error->code == EACCES)
            result = MHG_RESOURCE_SEED_SESSION_UNCERTAIN;
        goto done;
    }
    list = result_of(reply);
    if (variable_list_rejected(list)) {
        mhg_errorf(error, EACCES, "seed variable list rejected");
        result = MHG_RESOURCE_SEED_SESSION_UNCERTAIN;
        goto done;
    }
    if (find_variable(list,
                      (const char *)(global ? record->global_variables[0].data
                                            : record->local_variables[0].data),
                      &found, &type_ok) != 0) {
        mhg_errorf(error, EPROTO, "seed variable list shape differs");
        goto done;
    }
    /* The barrier proves that the scope exists. Type repair belongs to the
     * disabled provisioning pass and must not recreate an existing ID. */
    result = found ? MHG_RESOURCE_SEED_PRESENT : MHG_RESOURCE_SEED_MISSING;
done:
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return result;
}

enum mhg_resource_seed_probe_result
mhg_resource_lan_seed_probe(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error)
{
    return seed_probe_scope(userdata, record, false, error);
}

enum mhg_resource_seed_probe_result mhg_resource_lan_global_seed_probe(
    void *userdata, const struct mhg_resource_record *record, struct mhg_error *error)
{
    return seed_probe_scope(userdata, record, true, error);
}

static int seed_create_scope(void *userdata, const struct mhg_resource_record *record,
                             bool global, struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    char global_name[128];
    cJSON *params = NULL;
    cJSON *user_data = NULL;
    cJSON *reply = NULL;
    const cJSON *code;
    int status = -1;

    if (!owned_identity(owner, record))
        return mhg_errorf(error, EPROTO, "resource target binding differs");
    params = cJSON_CreateObject();
    user_data = cJSON_CreateObject();
    if ((global && global_variable_name(0u, global_name, sizeof(global_name)) != 0) ||
        !params || !user_data ||
        !cJSON_AddStringToObject(
            params, "scope", global ? "global" : (const char *)record->scope.data) ||
        !cJSON_AddStringToObject(
            params, "id",
            (const char *)(global ? record->global_variables[0].data
                                  : record->local_variables[0].data)) ||
        !cJSON_AddStringToObject(params, "type", "number") ||
        !cJSON_AddNumberToObject(params, "value", 2.0) ||
        !cJSON_AddStringToObject(
            user_data, "name", global ? global_name : local_state_variable_labels[0]) ||
        !attach_object(params, "userData", &user_data)) {
        mhg_errorf(error, ENOMEM, "seed create allocation failed");
        goto done;
    }
    if (call(owner, "/api/createVar", params, &reply, error))
        goto done;
    code = cJSON_GetObjectItemCaseSensitive(result_of(reply), "code");
    if (cJSON_IsNumber(code) && code->valuedouble < 0.0) {
        mhg_errorf(error, EREMOTEIO, "seed create rejected by gateway");
        goto done;
    }
    status = 0;
done:
    cJSON_Delete(reply);
    cJSON_Delete(user_data);
    cJSON_Delete(params);
    return status;
}

int mhg_resource_lan_seed_create(void *userdata,
                                 const struct mhg_resource_record *record,
                                 struct mhg_error *error)
{
    return seed_create_scope(userdata, record, false, error);
}

int mhg_resource_lan_global_seed_create(void *userdata,
                                        const struct mhg_resource_record *record,
                                        struct mhg_error *error)
{
    return seed_create_scope(userdata, record, true, error);
}

int mhg_resource_lan_seed_end_generation(void *userdata, struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);

    if (!owner || !owner->config.ops.end_generation)
        return mhg_errorf(error, EINVAL, "resource generation end is unavailable");
    return owner->config.ops.end_generation(owner->config.userdata, error);
}

static enum mhg_resource_reconcile_result inspect_new_scope(
    struct mhg_resource_lan *owner, const char *scope,
    const struct mhg_secret_buf variables[MHG_RESOURCE_STATE_VARIABLE_COUNT],
    bool missing[MHG_RESOURCE_STATE_VARIABLE_COUNT], struct mhg_error *error)
{
    cJSON *params = cJSON_CreateObject();
    cJSON *reply = NULL;
    const cJSON *list;
    size_t index;
    enum mhg_resource_reconcile_result result = MHG_RESOURCE_RECONCILE_RETRY;

    if (!params || !cJSON_AddStringToObject(params, "scope", scope)) {
        mhg_errorf(error, ENOMEM, "variable inspection allocation failed");
        goto done;
    }
    if (call(owner, "/api/getVarList", params, &reply, error))
        goto done;
    list = result_of(reply);
    if (variable_list_rejected(list)) {
        mhg_errorf(error, EACCES, "variable scope list rejected");
        goto done;
    }
    if (!cJSON_IsObject(list) && !cJSON_IsArray(list)) {
        mhg_errorf(error, EPROTO, "variable scope has invalid shape");
        goto done;
    }
    for (index = 0u; index < MHG_RESOURCE_STATE_VARIABLE_COUNT; ++index) {
        int found = 0;
        int type_ok = 0;

        if (find_variable(list, (const char *)variables[index].data, &found,
                          &type_ok) != 0) {
            mhg_errorf(error, EPROTO, "variable scope has invalid entries");
            goto done;
        }
        if (found && !type_ok) {
            mhg_errorf(error, EPROTO, "owned variable has wrong type");
            result = MHG_RESOURCE_RECONCILE_DRIFTED;
            goto done;
        }
        missing[index] = !found;
    }
    result = MHG_RESOURCE_RECONCILE_OK;
done:
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return result;
}

static int create_number_variable(struct mhg_resource_lan *owner, const char *scope,
                                  const char *id, const char *name,
                                  struct mhg_error *error)
{
    cJSON *params = cJSON_CreateObject();
    cJSON *user_data = cJSON_CreateObject();
    cJSON *reply = NULL;
    const cJSON *code;
    int status = -1;

    if (!params || !user_data || !cJSON_AddStringToObject(params, "scope", scope) ||
        !cJSON_AddStringToObject(params, "id", id) ||
        !cJSON_AddStringToObject(params, "type", "number") ||
        !cJSON_AddNumberToObject(params, "value", 2.0) ||
        !cJSON_AddStringToObject(user_data, "name", name) ||
        !attach_object(params, "userData", &user_data)) {
        mhg_errorf(error, ENOMEM, "variable create allocation failed");
        goto done;
    }
    if (call(owner, "/api/createVar", params, &reply, error))
        goto done;
    code = cJSON_GetObjectItemCaseSensitive(result_of(reply), "code");
    if (cJSON_IsNumber(code) && code->valuedouble < 0.0) {
        mhg_errorf(error, EREMOTEIO, "variable create rejected by gateway");
        goto done;
    }
    status = 0;
done:
    cJSON_Delete(reply);
    cJSON_Delete(user_data);
    cJSON_Delete(params);
    return status;
}

static int remove_wrong_type(struct mhg_resource_lan *owner, const char *scope,
                             const struct mhg_secret_buf *variables,
                             struct mhg_error *error)
{
    cJSON *params = cJSON_CreateObject(), *reply = NULL;
    int result = -1;
    if (!params || !cJSON_AddStringToObject(params, "scope", scope) ||
        call(owner, "/api/getVarList", params, &reply, error))
        goto done;
    const cJSON *list = result_of(reply);
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; ++i) {
        int found = 0, type_ok = 0;
        if (find_variable(list, (const char *)variables[i].data, &found, &type_ok))
            goto done;
        if (!found || type_ok)
            continue;
        cJSON *request = cJSON_CreateObject(), *answer = NULL;
        if (request && cJSON_AddStringToObject(request, "scope", scope) &&
            cJSON_AddStringToObject(request, "id", (const char *)variables[i].data))
            (void)call(owner, "/api/deleteVar", request, &answer, error);
        cJSON_Delete(answer);
        cJSON_Delete(request);
        /* Never infer deletion from its ACK. The next pass reads exact IDs
         * again before create; a retained variable remains a repair retry. */
        mhg_errorf(error, EAGAIN, "owned variable type repair awaits readback");
        goto done;
    }
    result = 0;
done:
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return result;
}

static enum mhg_resource_reconcile_result provision_new_scope(
    struct mhg_resource_lan *owner, const char *scope,
    const struct mhg_secret_buf variables[MHG_RESOURCE_STATE_VARIABLE_COUNT],
    bool global, struct mhg_error *error)
{
    bool missing[MHG_RESOURCE_STATE_VARIABLE_COUNT] = {false};
    enum mhg_resource_reconcile_result status;
    size_t index;

    if (remove_wrong_type(owner, scope, variables, error))
        return MHG_RESOURCE_RECONCILE_RETRY;
    status = inspect_new_scope(owner, scope, variables, missing, error);
    if (status != MHG_RESOURCE_RECONCILE_OK)
        return status;
    for (index = 0u; index < MHG_RESOURCE_STATE_VARIABLE_COUNT; ++index) {
        char display[128];
        const char *name = local_state_variable_labels[index];

        if (!missing[index])
            continue;
        if (global) {
            if (global_variable_name(index, display, sizeof(display)) != 0) {
                mhg_errorf(error, ENODEV, "global variable identity is unavailable");
                return MHG_RESOURCE_RECONCILE_RETRY;
            }
            name = display;
        }
        if (create_number_variable(owner, scope, (const char *)variables[index].data,
                                   name, error))
            return MHG_RESOURCE_RECONCILE_RETRY;
    }
    status = inspect_new_scope(owner, scope, variables, missing, error);
    if (status != MHG_RESOURCE_RECONCILE_OK)
        return status;
    for (index = 0u; index < MHG_RESOURCE_STATE_VARIABLE_COUNT; ++index)
        if (missing[index]) {
            mhg_errorf(error, EAGAIN, "created variable is not readable yet");
            return MHG_RESOURCE_RECONCILE_RETRY;
        }
    return MHG_RESOURCE_RECONCILE_OK;
}

static enum mhg_resource_reconcile_result
owned_graph_state(struct mhg_resource_lan *owner,
                  const struct mhg_resource_record *record, bool *present,
                  bool *enabled, struct mhg_error *error)
{
    cJSON *params = cJSON_CreateObject(), *reply = NULL;
    const cJSON *item;
    unsigned matches = 0;
    int status = -1;
    *present = false;
    *enabled = false;
    if (!params || call(owner, "/api/getGraphList", params, &reply, error))
        goto done;
    const cJSON *list = result_of(reply);
    if (!cJSON_IsArray(list))
        goto malformed;
    cJSON_ArrayForEach(item, list)
    {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "id");
        if (!cJSON_IsString(id) ||
            strcmp(id->valuestring, (const char *)record->graph_id.data))
            continue;
        const cJSON *flag = cJSON_GetObjectItemCaseSensitive(item, "enable");
        if (!cJSON_IsBool(flag) || ++matches > 1)
            goto malformed;
        *enabled = cJSON_IsTrue(flag);
    }
    *present = matches == 1;
    status = 0;
    goto done;
malformed:
    mhg_errorf(error, EPROTO, "graph list shape differs");
done:
    cJSON_Delete(params);
    cJSON_Delete(reply);
    return status;
}
static cJSON *read_nodes(struct mhg_resource_lan *owner,
                         const struct mhg_resource_record *record,
                         struct mhg_error *error)
{
    cJSON *params = cJSON_CreateObject(), *reply = NULL, *nodes = NULL;
    if (params &&
        cJSON_AddStringToObject(params, "id", (const char *)record->graph_id.data) &&
        !call(owner, "/api/getGraph", params, &reply, error)) {
        const cJSON *value =
            cJSON_GetObjectItemCaseSensitive(result_of(reply), "nodes");
        if (cJSON_IsArray(value))
            nodes = cJSON_Duplicate(value, 1);
        else
            mhg_errorf(error, EPROTO, "graph nodes malformed");
    }
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return nodes;
}
/* A write result is not proof. Even a lost ACK must be followed by a read;
 * the next pass reads again before any repeat mutation. */
static int write_graph(struct mhg_resource_lan *owner,
                       const struct mhg_resource_record *record, bool enabled,
                       struct mhg_error *error)
{
    cJSON *graph = mhg_resource_graph_build(&owner->config, record, enabled, error),
          *reply = NULL;
    if (!graph)
        return -1;
    (void)call(owner, "/api/setGraph", graph, &reply, error);
    cJSON_Delete(reply);
    cJSON_Delete(graph);
    return mhg_resource_lan_readback(owner, record, enabled, error);
}
static int variable_names(struct mhg_resource_lan *owner,
                          const struct mhg_resource_record *record, bool global,
                          bool repair, struct mhg_error *error)
{
    const char *scope = global ? "global" : (const char *)record->scope.data;
    const struct mhg_secret_buf *ids =
        global ? record->global_variables : record->local_variables;
    cJSON *params = cJSON_CreateObject(), *reply = NULL;
    int status = -1;
    if (!params || !cJSON_AddStringToObject(params, "scope", scope) ||
        call(owner, "/api/getVarList", params, &reply, error))
        goto done;
    const cJSON *list = result_of(reply);
    if (variable_list_rejected(list) || (!cJSON_IsObject(list) && !cJSON_IsArray(list)))
        goto done;
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; i++) {
        const char *id = (const char *)ids[i].data;
        char label[128];
        const char *wanted = local_state_variable_labels[i];
        if (global) {
            if (global_variable_name(i, label, sizeof(label)))
                goto done;
            wanted = label;
        }
        const cJSON *entry = variable_entry_for_id(list, id);
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(
            cJSON_GetObjectItemCaseSensitive(entry, "userData"), "name");
        if (cJSON_IsString(name) && !strcmp(name->valuestring, wanted))
            continue;
        if (!repair) {
            status = 1;
            goto done;
        }
        cJSON *change = cJSON_CreateObject(), *answer = NULL;
        cJSON *data = change ? cJSON_AddObjectToObject(change, "userData") : NULL;
        bool built = change && data &&
                     cJSON_AddStringToObject(change, "scope", scope) &&
                     cJSON_AddStringToObject(change, "id", id) &&
                     cJSON_AddStringToObject(data, "name", wanted);
        int rc = built ? call(owner, "/api/setVarConfig", change, &answer, error) : -1;
        cJSON_Delete(answer);
        cJSON_Delete(change);
        if (rc)
            goto done;
    }
    status = 0;
done:
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return status;
}
static int verify_variables(struct mhg_resource_lan *owner,
                            const struct mhg_resource_record *record,
                            struct mhg_error *error)
{
    bool missing[MHG_PRESENCE_SLOT_COUNT];
    for (int global = 0; global < 2; global++) {
        int rc = inspect_new_scope(
            owner, global ? "global" : (const char *)record->scope.data,
            global ? record->global_variables : record->local_variables, missing,
            error);
        if (rc)
            return rc;
        for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; i++)
            if (missing[i])
                return 1;
    }
    return 0;
}
int mhg_resource_lan_readback(void *userdata, const struct mhg_resource_record *record,
                              bool expect_enabled, struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    bool present = false, enabled = false;
    int result = -1;
    if (!owned_identity(owner, record))
        return mhg_errorf(error, EPROTO, "resource ownership differs");
    cJSON *desired =
              mhg_resource_graph_build(&owner->config, record, expect_enabled, error),
          *actual = NULL;
    if (!desired || owned_graph_state(owner, record, &present, &enabled, error) ||
        !present || enabled != expect_enabled)
        goto done;
    actual = read_nodes(owner, record, error);
    if (!actual ||
        !mhg_resource_graph_nodes_match(
            cJSON_GetObjectItemCaseSensitive(desired, "nodes"), actual, false) ||
        verify_variables(owner, record, error) ||
        variable_names(owner, record, false, false, error) ||
        variable_names(owner, record, true, false, error))
        goto done;
    result = 0;
    if (error)
        memset(error, 0, sizeof(*error));
done:
    cJSON_Delete(actual);
    cJSON_Delete(desired);
    if (result && error && !error->code)
        mhg_errorf(error, EPROTO, "resource readback differs");
    return result;
}
static int change_enabled(struct mhg_resource_lan *owner,
                          const struct mhg_resource_record *record, bool enabled,
                          struct mhg_error *error);
int mhg_resource_lan_create_disabled(void *userdata,
                                     const struct mhg_resource_record *record,
                                     struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    if (!owned_identity(owner, record))
        return mhg_errorf(error, EPROTO, "resource ownership differs");
    bool present = false, enabled = false;
    if (owned_graph_state(owner, record, &present, &enabled, error))
        return -1;
    if (present && enabled && change_enabled(owner, record, false, error))
        return -1;
    if (provision_new_scope(owner, (const char *)record->scope.data,
                            record->local_variables, false, error) ||
        provision_new_scope(owner, "global", record->global_variables, true, error) ||
        variable_names(owner, record, false, true, error) ||
        variable_names(owner, record, true, true, error))
        return -1;
    if (!mhg_resource_lan_readback(owner, record, true, error))
        return 0;
    if (!mhg_resource_lan_readback(owner, record, false, error))
        return 0;
    return write_graph(owner, record, false, error);
}
static int change_enabled(struct mhg_resource_lan *owner,
                          const struct mhg_resource_record *record, bool enabled,
                          struct mhg_error *error)
{
    cJSON *list_params = cJSON_CreateObject();
    cJSON *list_reply = NULL;
    cJSON *enable_params = cJSON_CreateObject();
    cJSON *enable_reply = NULL;
    const cJSON *list;
    const cJSON *item;
    int result = -1;

    if (!owned_identity(owner, record)) {
        cJSON_Delete(list_params);
        cJSON_Delete(enable_params);
        return mhg_errorf(error, EPROTO, "resource ownership differs");
    }
    if (!list_params) {
        cJSON_Delete(enable_params);
        return -1;
    }
    if (call(owner, "/api/getGraphList", list_params, &list_reply, error))
        goto done;
    list = result_of(list_reply);
    if (!cJSON_IsArray(list)) {
        mhg_errorf(error, EPROTO, "graph list is not an array");
        goto done;
    }
    cJSON_ArrayForEach(item, list)
    {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "id");
        cJSON *entry;

        if (!cJSON_IsString(id) ||
            strcmp(id->valuestring, (const char *)record->graph_id.data) != 0)
            continue;
        /* The hub expects the complete list entry back, with the flag flipped:
         * id, uiType and userData all belong to the configuration. */
        cJSON_Delete(enable_params);
        enable_params = cJSON_Duplicate(item, 1);
        entry = enable_params;
        if (!entry || !cJSON_ReplaceItemInObjectCaseSensitive(
                          entry, "enable", cJSON_CreateBool(enabled))) {
            mhg_errorf(error, ENOMEM, "enable request allocation failed");
            goto done;
        }
        (void)call(owner, "/api/changeGraphConfig", entry, &enable_reply, error);
        bool present = false, observed = false;
        result = owned_graph_state(owner, record, &present, &observed, error);
        if (!result && (!present || observed != enabled))
            result = -1;
        goto done;
    }
    mhg_errorf(error, EPROTO, "owned graph is absent from the list");

done:
    cJSON_Delete(enable_reply);
    cJSON_Delete(enable_params);
    cJSON_Delete(list_reply);
    cJSON_Delete(list_params);
    return result;
}

int mhg_resource_lan_enable(void *userdata, const struct mhg_resource_record *record,
                            struct mhg_error *error)
{
    return change_enabled(lan(userdata), record, true, error);
}

enum mhg_resource_reconcile_result
mhg_resource_lan_reconcile_config(void *userdata, struct mhg_resource_record *record,
                                  bool *changed, struct mhg_error *error)
{
    struct mhg_resource_lan *owner = lan(userdata);
    bool present = false, enabled = false;
    int rc = -1;
    cJSON *desired = NULL, *actual = NULL;
    char digest[33];
    *changed = false;
    if (!owned_identity(owner, record)) {
        mhg_errorf(error, EPROTO, "resource target binding differs");
        return MHG_RESOURCE_RECONCILE_DRIFTED;
    }
    if (owned_graph_state(owner, record, &present, &enabled, error))
        return MHG_RESOURCE_RECONCILE_RETRY;
    desired = mhg_resource_graph_build(&owner->config, record, true, error);
    if (!desired)
        goto done;
    if (present) {
        actual = read_nodes(owner, record, error);
        if (!actual)
            goto done;
    }
    int vars = present ? verify_variables(owner, record, error) : 1;
    if (vars < 0 && error && error->code != EACCES)
        goto done;
    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(desired, "nodes");
    if (!present || !enabled || vars ||
        !mhg_resource_graph_nodes_match(nodes, actual, true)) {
        /* Persist repair intent and return before mutating any functional resource.
         * The runtime closes delivery before the next synchronization pass. */
        record->stage = MHG_RESOURCE_STAGE_PROVISIONING;
        if (!present || vars) {
            record->seed_state = MHG_RESOURCE_SEED_CREATE_UNCERTAIN;
            record->global_seed_state = MHG_RESOURCE_SEED_CREATE_UNCERTAIN;
        }
        *changed = true;
        rc = MHG_RESOURCE_RECONCILE_OK;
        goto done;
    }
    if (!mhg_resource_graph_nodes_match(nodes, actual, false) ||
        variable_names(owner, record, false, false, error) ||
        variable_names(owner, record, true, false, error)) {
        if (variable_names(owner, record, false, true, error) ||
            variable_names(owner, record, true, true, error) ||
            write_graph(owner, record, true, error)) {
            /* A presentation failure is deliverable only while a fresh read
             * still proves the functional graph and variable contract. */
            cJSON_Delete(actual);
            actual = read_nodes(owner, record, error);
            if (actual &&
                !owned_graph_state(owner, record, &present, &enabled, error) &&
                present && enabled && !verify_variables(owner, record, error) &&
                mhg_resource_graph_nodes_match(nodes, actual, true))
                rc = MHG_RESOURCE_RECONCILE_PRESENTATION_PENDING;
            goto done;
        }
    }
    if (mhg_resource_graph_digest(nodes, digest))
        goto done;
    if (record->config_generation != owner->config.config_generation ||
        strcmp((const char *)record->digest.data, digest)) {
        if (mhg_secret_buf_set(&record->digest, digest, strlen(digest)))
            goto done;
        record->config_generation = owner->config.config_generation;
        *changed = true;
    }
    rc = MHG_RESOURCE_RECONCILE_OK;
    if (error)
        memset(error, 0, sizeof(*error));
done:
    cJSON_Delete(actual);
    cJSON_Delete(desired);
    return rc;
}
