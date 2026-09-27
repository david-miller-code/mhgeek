#include "emit_lan.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>

struct mhg_emit_lan {
    struct mhg_emit_lan_config config;
    struct mhg_resource_record record;
};

static bool record_can_emit(const struct mhg_resource_record *record)
{
    size_t slot;

    if (!record || record->version != MHG_RESOURCE_VERSION ||
        record->stage != MHG_RESOURCE_STAGE_READY || !record->scope.data ||
        !record->graph_id.data || record->seed_state != MHG_RESOURCE_SEED_VERIFIED ||
        record->global_seed_state != MHG_RESOURCE_SEED_VERIFIED)
        return false;
    for (slot = 0u; slot < MHG_PRESENCE_SLOT_COUNT; ++slot)
        if (!record->local_variables[slot].data)
            return false;
    return true;
}

int mhg_emit_lan_create(struct mhg_emit_lan **owner_out,
                        const struct mhg_emit_lan_config *config)
{
    struct mhg_emit_lan *owner;

    if (owner_out)
        *owner_out = NULL;
    if (!owner_out || !config || !config->ops.call || !record_can_emit(config->record))
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner)
        return -1;
    owner->config = *config;
    if (mhg_resource_record_clone(&owner->record, config->record) != 0) {
        mhg_emit_lan_destroy(owner);
        return -1;
    }
    owner->config.record = &owner->record;
    *owner_out = owner;
    return 0;
}

void mhg_emit_lan_destroy(struct mhg_emit_lan *owner)
{
    if (!owner)
        return;
    mhg_resource_record_clear(&owner->record);
    OPENSSL_clear_free(owner, sizeof(*owner));
}

int mhg_emit_lan_replace_record(struct mhg_emit_lan *owner,
                                const struct mhg_resource_record *record)
{
    if (!owner || !record_can_emit(record) ||
        mhg_resource_record_clone(&owner->record, record) != 0)
        return -1;
    owner->config.record = &owner->record;
    return 0;
}

static int write_value(struct mhg_emit_lan *owner, enum mhg_presence_slot slot,
                       double value, struct mhg_error *error)
{
    cJSON *params = NULL;
    cJSON *reply = NULL;
    const cJSON *outer_error;
    const cJSON *result;
    const cJSON *code;
    int status = -1;

    params = cJSON_CreateObject();
    if (!params ||
        !cJSON_AddStringToObject(params, "scope",
                                 (const char *)owner->record.scope.data) ||
        !cJSON_AddStringToObject(
            params, "id", (const char *)owner->record.local_variables[slot].data) ||
        !cJSON_AddNumberToObject(params, "value", value)) {
        mhg_errorf(error, ENOMEM, "state write allocation failed");
        goto done;
    }
    if (owner->config.ops.call(owner->config.userdata, "/api/setVarValue", params,
                               &reply, error))
        goto done;
    outer_error = reply ? cJSON_GetObjectItemCaseSensitive(reply, "error") : NULL;
    result = reply ? cJSON_GetObjectItemCaseSensitive(reply, "result") : NULL;
    if (outer_error || !cJSON_IsObject(result)) {
        mhg_errorf(error, EREMOTEIO, "state write JSON-RPC was rejected");
        goto done;
    }
    code = cJSON_GetObjectItemCaseSensitive(result, "code");
    if (code && !cJSON_IsNumber(code)) {
        mhg_errorf(error, EPROTO, "state write business code is malformed");
        goto done;
    }
    if (cJSON_IsNumber(code) && code->valuedouble < 0.0) {
        mhg_errorf(error, EREMOTEIO, "state write rejected: code=%.0f",
                   code->valuedouble);
        goto done;
    }
    status = 0;
done:
    cJSON_Delete(reply);
    cJSON_Delete(params);
    return status;
}

int mhg_emit_lan_send(void *userdata, enum mhg_presence_slot slot, bool present,
                      struct mhg_error *error)
{
    struct mhg_emit_lan *owner = userdata;

    if (!owner || slot >= MHG_PRESENCE_SLOT_COUNT || !record_can_emit(&owner->record))
        return mhg_errorf(error, EINVAL, "state emitter is unavailable");
    if (write_value(owner, slot, 2.0, error))
        return -1;
    return write_value(owner, slot, present ? 1.0 : 0.0, error);
}
