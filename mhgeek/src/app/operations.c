#include "operations.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

bool mhg_app_request_is_auth(enum mhg_app_request_kind kind)
{
    switch (kind) {
    case MHG_APP_REQUEST_AUTH_START:
    case MHG_APP_REQUEST_AUTH_VERIFY:
    case MHG_APP_REQUEST_AUTH_RESEND:
    case MHG_APP_REQUEST_AUTH_CANCEL:
    case MHG_APP_REQUEST_AUTH_CLEAR:
    case MHG_APP_REQUEST_AUTH_RETRY:
        return true;
    default:
        return false;
    }
}

bool mhg_app_operation_terminal(enum mhg_app_operation_state state)
{
    switch (state) {
    case MHG_OP_SUCCEEDED:
    case MHG_OP_FAILED:
    case MHG_OP_SUPERSEDED:
        return true;
    default:
        return false;
    }
}

int mhg_app_operations_init(struct mhg_app_operations *owner)
{
    unsigned char nonce[16];
    size_t done = 0;

    memset(owner, 0, sizeof(*owner));
    while (done < sizeof(nonce)) {
        ssize_t bytes = getrandom(nonce + done, sizeof(nonce) - done, 0);
        if (bytes < 0 && errno == EINTR)
            continue;
        if (bytes <= 0)
            return -1;
        done += (size_t)bytes;
    }
    for (size_t i = 0; i < sizeof(nonce); ++i)
        snprintf(owner->instance_id + i * 2, 3, "%02x", nonce[i]);
    return pthread_mutex_init(&owner->lock, NULL);
}

void mhg_app_operations_destroy(struct mhg_app_operations *owner)
{
    pthread_mutex_destroy(&owner->lock);
    memset(owner, 0, sizeof(*owner));
}

bool mhg_app_operations_get(struct mhg_app_operations *owner, uint64_t id,
                            struct mhg_app_operation *out)
{
    pthread_mutex_lock(&owner->lock);
    *out = owner->records[id % MHG_APP_OPERATION_CAPACITY];
    bool found = id && out->operation_id == id;
    pthread_mutex_unlock(&owner->lock);
    return found;
}

void mhg_app_operations_snapshot(struct mhg_app_operations *owner,
                                 struct mhg_app_operation *out)
{
    pthread_mutex_lock(&owner->lock);
    memcpy(out, owner->records, sizeof(owner->records));
    pthread_mutex_unlock(&owner->lock);
}

void mhg_app_operations_finish(struct mhg_app_operations *owner, uint64_t id,
                               enum mhg_app_operation_state state,
                               enum mhg_app_operation_error error, uint64_t generation,
                               const char *diagnostic, const char *message_key)
{
    pthread_mutex_lock(&owner->lock);
    struct mhg_app_operation *op = &owner->records[id % MHG_APP_OPERATION_CAPACITY];
    if (op->operation_id == id && !mhg_app_operation_terminal(op->state)) {
        op->state = state;
        op->error = error;
        if (op->kind == MHG_APP_REQUEST_CONFIG_SET && !op->config_generation)
            op->config_generation = generation;
        snprintf(op->diagnostic, sizeof(op->diagnostic), "%s",
                 diagnostic ? diagnostic : "");
        snprintf(op->message_key, sizeof(op->message_key), "%s",
                 message_key ? message_key : "");
    }
    pthread_mutex_unlock(&owner->lock);
}

bool mhg_app_operations_enqueue(struct mhg_app_operations *owner,
                                struct mhg_app_request *request)
{
    bool accepted = false;
    bool conflict = false;
    pthread_mutex_lock(&owner->lock);
    uint64_t id = owner->next_id + 1u;
    struct mhg_app_operation *op = &owner->records[id % MHG_APP_OPERATION_CAPACITY];
    for (size_t i = 0; i < MHG_APP_OPERATION_CAPACITY && op->operation_id &&
                       !mhg_app_operation_terminal(op->state);
         ++i)
        op = &owner->records[++id % MHG_APP_OPERATION_CAPACITY];
    /* Authorization executor owns one challenge/work item. Other operations,
     * including later configuration generations, may queue independently. */
    if (mhg_app_request_is_auth(request->kind) &&
        request->kind != MHG_APP_REQUEST_AUTH_CANCEL &&
        request->kind != MHG_APP_REQUEST_AUTH_CLEAR)
        for (size_t i = 0; i < MHG_APP_OPERATION_CAPACITY; ++i)
            if (owner->records[i].operation_id &&
                !mhg_app_operation_terminal(owner->records[i].state) &&
                mhg_app_request_is_auth(owner->records[i].kind))
                conflict = true;
    if (!conflict && owner->count < MHG_APP_QUEUE_CAPACITY &&
        (!op->operation_id || mhg_app_operation_terminal(op->state))) {
        request->operation_id = id;
        snprintf(request->instance_id, sizeof(request->instance_id), "%s",
                 owner->instance_id);
        owner->next_id = id;
        owner->requests[(owner->head + owner->count++) % MHG_APP_QUEUE_CAPACITY] =
            *request;
        *op = (struct mhg_app_operation){
            .operation_id = id, .kind = request->kind, .state = MHG_OP_QUEUED};
        snprintf(op->instance_id, sizeof(op->instance_id), "%s", owner->instance_id);
        accepted = true;
    }
    pthread_mutex_unlock(&owner->lock);
    return accepted;
}

bool mhg_app_operations_take(struct mhg_app_operations *owner,
                             struct mhg_app_request *out, bool config_ready)
{
    pthread_mutex_lock(&owner->lock);
    size_t offset = 0;
    while (offset < owner->count && !config_ready &&
           owner->requests[(owner->head + offset) % MHG_APP_QUEUE_CAPACITY].kind ==
               MHG_APP_REQUEST_CONFIG_SET)
        ++offset;
    /* Authorization runs ahead of cloud/resource work. Cancellation runs
     * first so a queued SMS can be cancelled before any provider call. */
    for (size_t i = 0; i < owner->count; ++i) {
        enum mhg_app_request_kind kind =
            owner->requests[(owner->head + i) % MHG_APP_QUEUE_CAPACITY].kind;
        if (mhg_app_request_is_auth(kind)) {
            offset = i;
            break;
        }
    }
    for (size_t i = 0; i < owner->count; ++i) {
        enum mhg_app_request_kind kind =
            owner->requests[(owner->head + i) % MHG_APP_QUEUE_CAPACITY].kind;
        if (kind == MHG_APP_REQUEST_AUTH_CANCEL || kind == MHG_APP_REQUEST_AUTH_CLEAR) {
            offset = i;
            break;
        }
    }
    bool pending = offset < owner->count;
    if (pending) {
        *out = owner->requests[(owner->head + offset) % MHG_APP_QUEUE_CAPACITY];
        for (size_t i = offset; i + 1 < owner->count; ++i)
            owner->requests[(owner->head + i) % MHG_APP_QUEUE_CAPACITY] =
                owner->requests[(owner->head + i + 1) % MHG_APP_QUEUE_CAPACITY];
        --owner->count;
        memset(&owner->requests[(owner->head + owner->count) % MHG_APP_QUEUE_CAPACITY],
               0, sizeof(*out));
        owner->records[out->operation_id % MHG_APP_OPERATION_CAPACITY].state =
            MHG_OP_RUNNING;
    }
    pthread_mutex_unlock(&owner->lock);
    return pending;
}

void mhg_app_operations_sync(struct mhg_app_operations *owner, uint64_t desired,
                             uint64_t synced, bool authority_ready, bool graph_ready)
{
    if (!authority_ready)
        return;
    pthread_mutex_lock(&owner->lock);
    for (size_t i = 0; i < MHG_APP_OPERATION_CAPACITY; ++i) {
        struct mhg_app_operation *op = &owner->records[i];
        if (!op->operation_id || op->kind != MHG_APP_REQUEST_CONFIG_SET ||
            op->state != MHG_OP_WAITING_SYNC)
            continue;
        if (op->config_generation < desired)
            op->state = MHG_OP_SUPERSEDED;
        else if (op->config_generation > desired) {
            op->state = MHG_OP_FAILED;
            op->error = MHG_OP_STORE_FAILED;
            snprintf(op->diagnostic, sizeof(op->diagnostic),
                     "requested generation was not committed");
        } else if (graph_ready && synced == op->config_generation)
            op->state = MHG_OP_SUCCEEDED;
    }
    pthread_mutex_unlock(&owner->lock);
}

void mhg_app_operations_cancel_auth_before(struct mhg_app_operations *owner,
                                           uint64_t id)
{
    pthread_mutex_lock(&owner->lock);
    for (size_t i = 0; i < MHG_APP_OPERATION_CAPACITY; ++i) {
        struct mhg_app_operation *op = &owner->records[i];
        if (op->operation_id && op->operation_id < id &&
            mhg_app_request_is_auth(op->kind) &&
            !mhg_app_operation_terminal(op->state)) {
            op->state = MHG_OP_FAILED;
            op->error = MHG_OP_CANCELLED;
        }
    }
    size_t retained = 0;
    for (size_t i = 0; i < owner->count; ++i) {
        struct mhg_app_request queued =
            owner->requests[(owner->head + i) % MHG_APP_QUEUE_CAPACITY];
        if (mhg_app_operation_terminal(
                owner->records[queued.operation_id % MHG_APP_OPERATION_CAPACITY].state))
            continue;
        owner->requests[(owner->head + retained++) % MHG_APP_QUEUE_CAPACITY] = queued;
    }
    for (size_t i = retained; i < owner->count; ++i)
        memset(&owner->requests[(owner->head + i) % MHG_APP_QUEUE_CAPACITY], 0,
               sizeof(struct mhg_app_request));
    owner->count = retained;
    pthread_mutex_unlock(&owner->lock);
}
