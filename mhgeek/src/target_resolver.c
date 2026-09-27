#include "target_resolver.h"

#include "https_client.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MHG_TARGET_RESOLVER_PATH_LIMIT 4096u

enum target_store_pending_operation {
    TARGET_STORE_PENDING_NONE = 0,
    TARGET_STORE_PENDING_INSTALL,
    TARGET_STORE_PENDING_CLEAR,
};

struct mhg_target_resolver {
    struct mhg_catalog *catalog;
    struct mhg_bootstrap *bootstrap;
    unsigned long probe_timeout_ms;
    char target_path[MHG_TARGET_RESOLVER_PATH_LIMIT];
    pthread_mutex_t lock;
    enum mhg_target_state state;
    enum mhg_target_outcome outcome;
    enum mhg_cloud_error last_error;
    enum target_store_pending_operation store_pending;
    struct mhg_target_record record;
    struct mhg_bootstrap_evidence evidence;
    struct mhg_target_resolver_stats stats;
};

int mhg_target_resolver_create(struct mhg_target_resolver **owner_out,
                               const struct mhg_target_resolver_config *config)
{
    struct mhg_target_resolver *owner;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || !config->target_path ||
        !config->target_path[0] || !config->probe_timeout_ms ||
        strlen(config->target_path) >= MHG_TARGET_RESOLVER_PATH_LIMIT)
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->probe_timeout_ms = config->probe_timeout_ms;
    owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    owner->store_pending = TARGET_STORE_PENDING_NONE;
    owner->record = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    owner->evidence = (struct mhg_bootstrap_evidence)MHG_BOOTSTRAP_EVIDENCE_INIT;
    owner->stats =
        (struct mhg_target_resolver_stats)MHG_TARGET_RESOLVER_STATS_INIT;
    memcpy(owner->target_path, config->target_path,
           strlen(config->target_path) + 1u);
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return -1;
    }
    if (mhg_catalog_create(&owner->catalog, &config->catalog) != 0 ||
        mhg_bootstrap_create(&owner->bootstrap, &config->bootstrap) != 0) {
        mhg_catalog_destroy(owner->catalog);
        pthread_mutex_destroy(&owner->lock);
        mhg_secure_clear(owner, sizeof(*owner));
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_target_resolver_destroy(struct mhg_target_resolver *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    mhg_bootstrap_destroy(owner->bootstrap);
    mhg_catalog_destroy(owner->catalog);
    mhg_bootstrap_evidence_clear(&owner->evidence);
    mhg_target_record_clear(&owner->record);
    pthread_mutex_unlock(&owner->lock);
    pthread_mutex_destroy(&owner->lock);
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

enum mhg_cloud_error mhg_target_resolver_begin(
    struct mhg_target_resolver *owner)
{
    int loaded;

    if (!owner) return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    if (owner->store_pending != TARGET_STORE_PENDING_NONE) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INTERNAL;
    }
    loaded = mhg_target_store_load(owner->target_path, &owner->record);
    if (loaded == MHG_TARGET_STORE_PRESENT) {
        owner->state = MHG_TARGET_STATE_LOCKED;
        owner->outcome = MHG_TARGET_OUTCOME_NONE;
        owner->last_error = MHG_CLOUD_OK;
    } else {
        owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
        owner->outcome = loaded == MHG_TARGET_STORE_ABSENT ?
                         MHG_TARGET_OUTCOME_NONE : MHG_TARGET_OUTCOME_STORE;
        owner->last_error = loaded == MHG_TARGET_STORE_ABSENT ?
                            MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
    }
    pthread_mutex_unlock(&owner->lock);
    return owner->last_error;
}

/* A rename may have happened even when the target store reports failure.
 * Keep the resolver closed and reload exactly the file that survived. */
static void freeze_store_locked(struct mhg_target_resolver *owner,
                                enum target_store_pending_operation operation)
{
    struct mhg_target_record loaded = MHG_TARGET_RECORD_INIT;

    if (mhg_target_store_load(owner->target_path, &loaded) ==
        MHG_TARGET_STORE_PRESENT) {
        mhg_target_record_clear(&owner->record);
        owner->record = loaded;
        loaded = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    } else {
        mhg_target_record_clear(&owner->record);
    }
    mhg_target_record_clear(&loaded);
    mhg_bootstrap_evidence_clear(&owner->evidence);
    owner->state = MHG_TARGET_STATE_UNRESOLVED;
    owner->outcome = MHG_TARGET_OUTCOME_STORE;
    owner->last_error = MHG_CLOUD_INTERNAL;
    owner->store_pending = operation;
}

enum mhg_cloud_error mhg_target_resolver_recover_store(
    struct mhg_target_resolver *owner)
{
    struct mhg_target_record loaded = MHG_TARGET_RECORD_INIT;
    int committed;

    if (!owner) return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    if (owner->state != MHG_TARGET_STATE_UNRESOLVED ||
        owner->outcome != MHG_TARGET_OUTCOME_STORE ||
        owner->store_pending == TARGET_STORE_PENDING_NONE) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    committed = mhg_target_store_load(owner->target_path, &loaded);
    if (owner->store_pending == TARGET_STORE_PENDING_CLEAR &&
        committed == MHG_TARGET_STORE_ABSENT) {
        if (mhg_target_store_clear(owner->target_path) !=
            MHG_TARGET_STORE_COMMITTED_DURABLE) {
            freeze_store_locked(owner, TARGET_STORE_PENDING_CLEAR);
            goto done;
        }
        mhg_target_record_clear(&owner->record);
        mhg_bootstrap_evidence_clear(&owner->evidence);
        owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
        owner->outcome = MHG_TARGET_OUTCOME_NONE;
        owner->last_error = MHG_CLOUD_OK;
        owner->store_pending = TARGET_STORE_PENDING_NONE;
        goto done;
    }
    if (committed != MHG_TARGET_STORE_PRESENT) {
        freeze_store_locked(owner, owner->store_pending);
        goto done;
    }
    /* v1 is a selected identity. Reinstalling as v2 makes the authority
     * explicit without fabricating an Action tuple. */
    loaded.version = MHG_TARGET_VERSION_V2;
    committed = mhg_target_store_commit(owner->target_path, &loaded);
    if (committed != MHG_TARGET_STORE_COMMITTED_DURABLE) {
        freeze_store_locked(owner, owner->store_pending);
        goto done;
    }
    mhg_target_record_clear(&owner->record);
    owner->record = loaded;
    loaded = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    owner->state = MHG_TARGET_STATE_LOCKED;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    owner->store_pending = TARGET_STORE_PENDING_NONE;

done:
    mhg_target_record_clear(&loaded);
    pthread_mutex_unlock(&owner->lock);
    return owner->last_error;
}

static int text_equal(const struct mhg_secret_buf *value, const char *text)
{
    return value->data && text && value->len == strlen(text) &&
           memcmp(value->data, text, value->len) == 0;
}

enum mhg_cloud_error mhg_target_resolver_commit_action(
    struct mhg_target_resolver *owner, const char *did, const char *model,
    const char *urn, int siid, int aiid, int piid)
{
    struct mhg_target_record disk = MHG_TARGET_RECORD_INIT;
    struct mhg_target_record next = MHG_TARGET_RECORD_INIT;
    enum mhg_cloud_error result = MHG_CLOUD_INTERNAL;

    if (!owner || !mhg_target_field_is_valid(did, MHG_TARGET_DID_LIMIT) ||
        !mhg_target_field_is_valid(model, MHG_TARGET_MODEL_LIMIT) ||
        !mhg_target_field_is_valid(urn, MHG_TARGET_URN_LIMIT) ||
        siid <= 0 || aiid <= 0 || piid <= 0)
        return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    if (owner->state != MHG_TARGET_STATE_LOCKED ||
        !text_equal(&owner->record.did, did) ||
        !text_equal(&owner->record.model, model)) {
        result = MHG_CLOUD_TARGET_MISMATCH;
        goto done;
    }
    if (mhg_target_store_load(owner->target_path, &disk) !=
            MHG_TARGET_STORE_PRESENT ||
        !mhg_target_record_same_device(&disk, &owner->record) ||
        !text_equal(&disk.ip, (const char *)owner->record.ip.data) ||
        disk.catalog_generation != owner->record.catalog_generation) {
        freeze_store_locked(owner, TARGET_STORE_PENDING_INSTALL);
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    if (disk.action_state == MHG_TARGET_ACTION_VERIFIED) {
        if (text_equal(&disk.action_urn, urn) && disk.action_siid == siid &&
            disk.action_aiid == aiid && disk.action_piid == piid) {
            result = MHG_CLOUD_OK;
        } else {
            owner->outcome = MHG_TARGET_OUTCOME_DRIFTED;
            owner->last_error = MHG_CLOUD_TARGET_MISMATCH;
            result = MHG_CLOUD_TARGET_MISMATCH;
        }
        goto done;
    }
    if (mhg_target_record_clone(&next, &disk) != 0 ||
        mhg_secret_buf_set(&next.action_urn, urn, strlen(urn)) != 0) {
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    next.version = MHG_TARGET_VERSION_V2;
    next.action_state = MHG_TARGET_ACTION_VERIFIED;
    next.action_siid = siid;
    next.action_aiid = aiid;
    next.action_piid = piid;
    if (mhg_target_store_commit(owner->target_path, &next) !=
        MHG_TARGET_STORE_COMMITTED_DURABLE) {
        freeze_store_locked(owner, TARGET_STORE_PENDING_INSTALL);
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    mhg_target_record_clear(&owner->record);
    owner->record = next;
    next = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    result = MHG_CLOUD_OK;

done:
    mhg_target_record_clear(&next);
    mhg_target_record_clear(&disk);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

static void stop_unresolved(struct mhg_target_resolver *owner,
                            enum mhg_target_outcome outcome,
                            enum mhg_cloud_error error)
{
    owner->state = MHG_TARGET_STATE_UNRESOLVED;
    owner->outcome = outcome;
    owner->last_error = error;
}

static void stop_decision_required(struct mhg_target_resolver *owner,
                                   enum mhg_target_outcome outcome,
                                   enum mhg_cloud_error error)
{
    owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
    owner->outcome = outcome;
    owner->last_error = error;
}

enum mhg_cloud_error mhg_target_resolver_submit(
    struct mhg_target_resolver *owner,
    const struct mhg_service_session *xiaomiio_session,
    const struct mhg_service_session *mijia_session, const char *ip,
    const char *did)
{
    const struct mhg_catalog_snapshot *snapshot;
    const struct mhg_catalog_device *chosen = NULL;
    struct mhg_bootstrap_target target;
    struct mhg_target_record record = MHG_TARGET_RECORD_INIT;
    enum mhg_cloud_error result;
    size_t index;
    size_t hits = 0u;
    size_t eligible = 0u;
    unsigned tier;
    uint64_t deadline;
    struct in_addr address;
    struct mhg_secret_buf selected_url = MHG_SECRET_BUF_INIT;
    bool did_given;

    if (!owner) return MHG_CLOUD_INPUT;
    if (!xiaomiio_session || !mijia_session) return MHG_CLOUD_INPUT;
    /* One owner per SID: a session that does not own its leg is a caller bug,
     * so it is refused before any counter, state or request. */
    if (xiaomiio_session->sid != MHG_XIAOMI_SID_XIAOMIIO ||
        mijia_session->sid != MHG_XIAOMI_SID_MIJIA)
        return MHG_CLOUD_SID_MISMATCH;
    did_given = did && did[0];
    if (!mhg_target_field_is_valid(ip, MHG_TARGET_IP_LIMIT) ||
        inet_pton(AF_INET, ip, &address) != 1 ||
        (did_given && !mhg_target_field_is_valid(did, MHG_TARGET_DID_LIMIT))) {
        pthread_mutex_lock(&owner->lock);
        if (owner->state != MHG_TARGET_STATE_LOCKED)
            stop_decision_required(owner, MHG_TARGET_OUTCOME_INPUT,
                                   MHG_CLOUD_INPUT);
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    pthread_mutex_lock(&owner->lock);
    if (owner->store_pending != TARGET_STORE_PENDING_NONE) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INTERNAL;
    }
    if (owner->state == MHG_TARGET_STATE_LOCKED) {
        /* A locked target is read-only: changing it starts with a clear. */
        owner->stats.locked_rejections++;
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    owner->stats.submissions++;
    mhg_target_record_clear(&owner->record);
    mhg_bootstrap_evidence_clear(&owner->evidence);
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;

    /* Submitting a target is one of the two times the directory is ever
     * queried: resolve against a fresh snapshot, then never again. */
    owner->stats.catalog_queries++;
    result = mhg_catalog_refresh(owner->catalog, xiaomiio_session);
    if (result != MHG_CLOUD_OK) {
        stop_unresolved(owner, MHG_TARGET_OUTCOME_CATALOG, result);
        goto done;
    }
    snapshot = mhg_catalog_current(owner->catalog);
    if (!snapshot) {
        stop_unresolved(owner, MHG_TARGET_OUTCOME_CATALOG, MHG_CLOUD_INTERNAL);
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    for (index = 0u; index < snapshot->device_count; ++index) {
        const struct mhg_catalog_device *device = &snapshot->devices[index];
        if (!text_equal(&device->local_ip, ip)) continue;
        ++hits;
        if (!did_given || text_equal(&device->did, did)) ++eligible;
    }
    if (!hits || !eligible) {
        result = MHG_CLOUD_TARGET_MISMATCH;
        if (!hits)
            stop_unresolved(owner, MHG_TARGET_OUTCOME_NOT_FOUND, result);
        else
            stop_decision_required(owner, MHG_TARGET_OUTCOME_CONFLICT, result);
        goto done;
    }
    /* Online entries have priority. Unknown and offline entries are checked
     * only when every online candidate was definitively excluded. */
    deadline = mhg_https_now_ms() + owner->probe_timeout_ms;
    for (tier = 0u; tier < 2u; ++tier) {
        size_t successes = 0u;
        enum mhg_cloud_error uncertain = MHG_CLOUD_OK;
        for (index = 0u; index < snapshot->device_count; ++index) {
            const struct mhg_catalog_device *device = &snapshot->devices[index];
            struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
            if (!text_equal(&device->local_ip, ip) ||
                (did_given && !text_equal(&device->did, did)) ||
                ((device->online == MHG_CATALOG_ONLINE) != (tier == 0u)))
                continue;
            target = (struct mhg_bootstrap_target){
                (const char *)device->did.data,
                (const char *)device->model.data,
                (const char *)device->token.data, ip};
            owner->stats.probes++;
            result = mhg_bootstrap_probe_url(owner->bootstrap, mijia_session,
                                             &target, &url, deadline);
            if (result == MHG_CLOUD_OK) {
                ++successes;
                if (successes == 1u) {
                    chosen = device;
                    selected_url = url;
                    url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
                }
            } else if (result != MHG_CLOUD_TARGET_MISMATCH &&
                       (uncertain == MHG_CLOUD_OK || result == MHG_CLOUD_AUTH_REJECTED)) {
                /* Transport/auth/provider/malformed failures do not establish
                 * absence of capability, so they cannot justify a binding. */
                uncertain = result;
            }
            mhg_secret_buf_clear(&url);
            if (successes > 1u || result == MHG_CLOUD_AUTH_REJECTED ||
                mhg_https_now_ms() >= deadline) {
                if (successes < 2u && uncertain == MHG_CLOUD_OK)
                    uncertain = MHG_CLOUD_NETWORK;
                break;
            }
        }
        if (successes > 1u) {
            result = MHG_CLOUD_TARGET_MISMATCH;
            stop_unresolved(owner, MHG_TARGET_OUTCOME_AMBIGUOUS, result);
            goto done;
        }
        if (uncertain != MHG_CLOUD_OK) {
            result = uncertain;
            stop_unresolved(owner, MHG_TARGET_OUTCOME_PROBE, result);
            goto done;
        }
        if (successes == 1u) break;
    }
    if (!chosen) {
        result = MHG_CLOUD_TARGET_MISMATCH;
        stop_unresolved(owner, MHG_TARGET_OUTCOME_PROBE, result);
        goto done;
    }
    target = (struct mhg_bootstrap_target){
        (const char *)chosen->did.data, (const char *)chosen->model.data,
        (const char *)chosen->token.data, ip};
    result = mhg_bootstrap_finish(owner->bootstrap, mijia_session, &target,
                                  &selected_url, &owner->evidence);
    if (result != MHG_CLOUD_OK) {
        stop_unresolved(owner, MHG_TARGET_OUTCOME_PROBE, result);
        goto done;
    }

    record.version = MHG_TARGET_VERSION_V2;
    record.catalog_generation = snapshot->directory_generation;
    result = mhg_secret_buf_set(&record.ip, ip, strlen(ip)) == 0 &&
             mhg_secret_buf_set(&record.did, chosen->did.data,
                                chosen->did.len) == 0 &&
             mhg_secret_buf_set(&record.model, chosen->model.data,
                                chosen->model.len) == 0 ?
             MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
    if (result != MHG_CLOUD_OK) {
        mhg_bootstrap_evidence_clear(&owner->evidence);
        stop_unresolved(owner, MHG_TARGET_OUTCOME_STORE, MHG_CLOUD_INTERNAL);
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    if (mhg_target_store_commit(owner->target_path, &record) !=
        MHG_TARGET_STORE_COMMITTED_DURABLE) {
        mhg_bootstrap_evidence_clear(&owner->evidence);
        freeze_store_locked(owner, TARGET_STORE_PENDING_INSTALL);
        result = MHG_CLOUD_INTERNAL;
        goto done;
    }
    owner->record = record;
    record = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    owner->state = MHG_TARGET_STATE_LOCKED;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    result = MHG_CLOUD_OK;

done:
    mhg_secret_buf_clear(&selected_url);
    mhg_target_record_clear(&record);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

enum mhg_cloud_error mhg_target_resolver_refresh_catalog(
    struct mhg_target_resolver *owner,
    const struct mhg_service_session *xiaomiio_session)
{
    enum mhg_cloud_error result;

    if (!owner || !xiaomiio_session) return MHG_CLOUD_INPUT;
    if (xiaomiio_session->sid != MHG_XIAOMI_SID_XIAOMIIO)
        return MHG_CLOUD_SID_MISMATCH;
    pthread_mutex_lock(&owner->lock);
    owner->stats.catalog_queries++;
    result = mhg_catalog_refresh(owner->catalog, xiaomiio_session);
    if (result != MHG_CLOUD_OK) {
        owner->outcome = MHG_TARGET_OUTCOME_CATALOG;
        owner->last_error = result;
    } else {
        owner->outcome = MHG_TARGET_OUTCOME_NONE;
        owner->last_error = MHG_CLOUD_OK;
    }
    pthread_mutex_unlock(&owner->lock);
    return result;
}

enum mhg_cloud_error mhg_target_resolver_refresh_bootstrap(
    struct mhg_target_resolver *owner,
    const struct mhg_catalog_snapshot *snapshot,
    const struct mhg_service_session *mijia_session)
{
    const struct mhg_catalog_device *entry = NULL;
    struct mhg_bootstrap_target target;
    enum mhg_cloud_error result = MHG_CLOUD_TARGET_MISMATCH;
    size_t index;

    if (!owner || !snapshot || !mijia_session) return MHG_CLOUD_INPUT;
    if (mijia_session->sid != MHG_XIAOMI_SID_MIJIA) return MHG_CLOUD_SID_MISMATCH;
    pthread_mutex_lock(&owner->lock);
    if (owner->state != MHG_TARGET_STATE_LOCKED) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    for (index = 0u; index < snapshot->device_count; ++index) {
        const struct mhg_catalog_device *device = &snapshot->devices[index];

        if (text_equal(&device->did, (const char *)owner->record.did.data)) {
            entry = device;
            break;
        }
    }
    /* The persisted identity is the authority: a directory that no longer
     * matches it stops here for the user instead of being followed. */
    if (!entry ||
        !text_equal(&entry->model, (const char *)owner->record.model.data) ||
        !text_equal(&entry->local_ip, (const char *)owner->record.ip.data)) {
        owner->outcome = MHG_TARGET_OUTCOME_DRIFTED;
        owner->last_error = MHG_CLOUD_TARGET_MISMATCH;
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_TARGET_MISMATCH;
    }
    if (!entry->token.data || !entry->token.len) {
        owner->outcome = MHG_TARGET_OUTCOME_PROBE;
        owner->last_error = MHG_CLOUD_INPUT;
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    target.did = (const char *)entry->did.data;
    target.model = (const char *)entry->model.data;
    target.access_key = (const char *)entry->token.data;
    target.expected_host = (const char *)owner->record.ip.data;
    owner->stats.probes++;
    result = mhg_bootstrap_run(owner->bootstrap, mijia_session, &target,
                               &owner->evidence);
    if (result != MHG_CLOUD_OK) {
        owner->outcome = MHG_TARGET_OUTCOME_PROBE;
        owner->last_error = result;
        pthread_mutex_unlock(&owner->lock);
        return result;
    }
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    pthread_mutex_unlock(&owner->lock);
    return MHG_CLOUD_OK;
}

enum mhg_cloud_error mhg_target_resolver_verify(
    struct mhg_target_resolver *owner,
    const struct mhg_catalog_snapshot *snapshot,
    const struct mhg_catalog_device **matched_out)
{
    const struct mhg_catalog_device *matched = NULL;
    struct mhg_target_record updated = MHG_TARGET_RECORD_INIT;
    enum mhg_cloud_error result = MHG_CLOUD_TARGET_MISMATCH;
    size_t index;

    if (matched_out) *matched_out = NULL;
    if (!owner || !snapshot) return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    if (owner->state != MHG_TARGET_STATE_LOCKED) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INPUT;
    }
    for (index = 0u; index < snapshot->device_count; ++index) {
        const struct mhg_catalog_device *device = &snapshot->devices[index];

        if (!text_equal(&device->did, (const char *)owner->record.did.data))
            continue;
        if (matched || !text_equal(&device->model,
                                    (const char *)owner->record.model.data))
            goto drift;
        matched = device;
    }
    if (!matched || snapshot->directory_generation == 0u ||
        !matched->local_ip.data ||
        !mhg_target_field_is_valid((const char *)matched->local_ip.data,
                                    MHG_TARGET_IP_LIMIT))
        goto drift;
    if (owner->record.catalog_generation != snapshot->directory_generation ||
        !text_equal(&owner->record.ip,
                    (const char *)matched->local_ip.data) ||
        owner->record.version == MHG_TARGET_VERSION_V1) {
        /* A refreshed catalog can change generation or DHCP address without
         * changing the target device. Clone the full record so a verified
         * tuple survives the one-file atomic replacement. */
        if (mhg_target_record_clone(&updated, &owner->record) != 0 ||
            mhg_secret_buf_set(&updated.ip, matched->local_ip.data,
                               matched->local_ip.len) != 0) {
            result = MHG_CLOUD_INTERNAL;
            goto done;
        }
        updated.version = MHG_TARGET_VERSION_V2;
        updated.catalog_generation = snapshot->directory_generation;
        if (mhg_target_store_commit(owner->target_path, &updated) !=
            MHG_TARGET_STORE_COMMITTED_DURABLE) {
            freeze_store_locked(owner, TARGET_STORE_PENDING_INSTALL);
            result = MHG_CLOUD_INTERNAL;
            goto done;
        }
        mhg_target_record_clear(&owner->record);
        owner->record = updated;
        updated = (struct mhg_target_record)MHG_TARGET_RECORD_INIT;
    }
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    if (matched_out) *matched_out = matched;
    result = MHG_CLOUD_OK;
    goto done;

drift:
    /* The target stays locked: the user clears it explicitly to choose again. */
    owner->outcome = MHG_TARGET_OUTCOME_DRIFTED;
    owner->last_error = result;

done:
    mhg_target_record_clear(&updated);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

void mhg_target_resolver_forget_authorization(struct mhg_target_resolver *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    mhg_target_record_clear(&owner->record);
    mhg_bootstrap_evidence_clear(&owner->evidence);
    mhg_catalog_invalidate(owner->catalog);
    owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    owner->store_pending = TARGET_STORE_PENDING_NONE;
    pthread_mutex_unlock(&owner->lock);
}

enum mhg_cloud_error mhg_target_resolver_clear(
    struct mhg_target_resolver *owner)
{
    int cleared;

    if (!owner) return MHG_CLOUD_INPUT;
    pthread_mutex_lock(&owner->lock);
    if (owner->store_pending != TARGET_STORE_PENDING_NONE) {
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INTERNAL;
    }
    cleared = mhg_target_store_clear(owner->target_path);
    if (cleared != MHG_TARGET_STORE_COMMITTED_DURABLE) {
        freeze_store_locked(owner, TARGET_STORE_PENDING_CLEAR);
        pthread_mutex_unlock(&owner->lock);
        return MHG_CLOUD_INTERNAL;
    }
    mhg_target_record_clear(&owner->record);
    mhg_bootstrap_evidence_clear(&owner->evidence);
    owner->state = MHG_TARGET_STATE_DECISION_REQUIRED;
    owner->outcome = MHG_TARGET_OUTCOME_NONE;
    owner->last_error = MHG_CLOUD_OK;
    owner->store_pending = TARGET_STORE_PENDING_NONE;
    pthread_mutex_unlock(&owner->lock);
    return owner->last_error;
}

enum mhg_target_state mhg_target_resolver_state(
    const struct mhg_target_resolver *owner)
{
    return owner ? owner->state : MHG_TARGET_STATE_DECISION_REQUIRED;
}

enum mhg_target_outcome mhg_target_resolver_outcome(
    const struct mhg_target_resolver *owner)
{
    return owner ? owner->outcome : MHG_TARGET_OUTCOME_NONE;
}

enum mhg_cloud_error mhg_target_resolver_last_error(
    const struct mhg_target_resolver *owner)
{
    return owner ? owner->last_error : MHG_CLOUD_INPUT;
}

const struct mhg_target_record *mhg_target_resolver_record(
    const struct mhg_target_resolver *owner)
{
    return owner && owner->state == MHG_TARGET_STATE_LOCKED ?
           &owner->record : NULL;
}

const struct mhg_bootstrap_evidence *mhg_target_resolver_evidence(
    const struct mhg_target_resolver *owner)
{
    return owner && owner->evidence.url.data ? &owner->evidence : NULL;
}

const struct mhg_catalog_snapshot *mhg_target_resolver_snapshot(
    const struct mhg_target_resolver *owner)
{
    return owner ? mhg_catalog_current(owner->catalog) : NULL;
}

void mhg_target_resolver_catalog_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_catalog_stats *stats)
{
    if (!stats) return;
    if (!owner) {
        *stats = (struct mhg_catalog_stats)MHG_CATALOG_STATS_INIT;
        return;
    }
    mhg_catalog_stats_get(owner->catalog, stats);
}

void mhg_target_resolver_bootstrap_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_bootstrap_stats *stats)
{
    if (!stats) return;
    if (!owner) {
        *stats = (struct mhg_bootstrap_stats)MHG_BOOTSTRAP_STATS_INIT;
        return;
    }
    mhg_bootstrap_stats_get(owner->bootstrap, stats);
}

void mhg_target_resolver_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_target_resolver_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_target_resolver_stats)
        MHG_TARGET_RESOLVER_STATS_INIT;
}

const char *mhg_target_state_name(enum mhg_target_state state)
{
    switch (state) {
    case MHG_TARGET_STATE_DECISION_REQUIRED: return "decision_required";
    case MHG_TARGET_STATE_UNRESOLVED: return "unresolved";
    case MHG_TARGET_STATE_LOCKED: return "locked";
    }
    return NULL;
}

const char *mhg_target_outcome_name(enum mhg_target_outcome outcome)
{
    switch (outcome) {
    case MHG_TARGET_OUTCOME_NONE: return "none";
    case MHG_TARGET_OUTCOME_CATALOG: return "catalog";
    case MHG_TARGET_OUTCOME_NOT_FOUND: return "not_found";
    case MHG_TARGET_OUTCOME_AMBIGUOUS: return "ambiguous";
    case MHG_TARGET_OUTCOME_CONFLICT: return "conflict";
    case MHG_TARGET_OUTCOME_PROBE: return "probe";
    case MHG_TARGET_OUTCOME_STORE: return "store";
    case MHG_TARGET_OUTCOME_DRIFTED: return "drifted";
    case MHG_TARGET_OUTCOME_INPUT: return "input";
    }
    return NULL;
}
