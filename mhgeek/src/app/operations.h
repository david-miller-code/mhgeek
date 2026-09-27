#ifndef MHGEEK_APP_OPERATIONS_H
#define MHGEEK_APP_OPERATIONS_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "event_config_store.h"
#include "target_store.h"

enum mhg_app_request_kind {
    MHG_APP_REQUEST_NONE = 0,
    MHG_APP_REQUEST_REPLAY = 1,
    MHG_APP_REQUEST_RECONNECT = 2,
    MHG_APP_REQUEST_TARGET_SET = 3,
    MHG_APP_REQUEST_TARGET_CLEAR = 4,
    /* Recheck the plugin-owned resources. */
    MHG_APP_REQUEST_RESYNC = 5,
    /* Phone-only SMS authorization: every state change is queued and
     * executed by the scheduler thread through the auth executor. */
    MHG_APP_REQUEST_AUTH_START = 7,
    MHG_APP_REQUEST_AUTH_VERIFY = 8,
    MHG_APP_REQUEST_AUTH_RESEND = 9,
    MHG_APP_REQUEST_AUTH_CANCEL = 10,
    MHG_APP_REQUEST_AUTH_CLEAR = 11,
    MHG_APP_REQUEST_AUTH_RETRY = 12,
    /* Event text and per-slot absence duration update. */
    MHG_APP_REQUEST_CONFIG_SET = 13,
};

struct mhg_app_request {
    enum mhg_app_request_kind kind;
    char ip[MHG_TARGET_IP_LIMIT];
    char did[MHG_TARGET_DID_LIMIT];
    bool has_did;
    /* Authorization payload (only the fields of the chosen kind are read). */
    uint64_t operation_id;
    char instance_id[33];
    uint64_t challenge_generation;
    char calling_code[8];
    char national_number[24];
    char code[16];
    bool retry_persist;
    /* Event configuration update: only the fields the frontend sent. */
    bool set_absent_seconds[MHG_PRESENCE_SLOT_COUNT];
    double absent_seconds[MHG_PRESENCE_SLOT_COUNT];
    bool has_prefix;
    char prefix[MHG_EVENT_PREFIX_LIMIT + 1u];
    bool set_texts[MHG_PRESENCE_SLOT_COUNT * 2u];
    char texts[MHG_PRESENCE_SLOT_COUNT * 2u][MHG_EVENT_TEXT_LIMIT + 1u];
};

enum mhg_app_operation_state {
    MHG_OP_QUEUED,
    MHG_OP_RUNNING,
    MHG_OP_WAITING_SYNC,
    MHG_OP_SUCCEEDED,
    MHG_OP_FAILED,
    MHG_OP_SUPERSEDED,
};

enum mhg_app_operation_error {
    MHG_OP_OK,
    MHG_OP_UNAUTHORIZED,
    MHG_OP_CLOUD_FAILED,
    MHG_OP_TARGET_FAILED,
    MHG_OP_STORE_FAILED,
    MHG_OP_SYNC_FAILED,
    MHG_OP_AUTH_FAILED,
    MHG_OP_CANCELLED,
    MHG_OP_TARGET_CATALOG_FAILED,
    MHG_OP_TARGET_NOT_FOUND,
    MHG_OP_TARGET_AMBIGUOUS,
    MHG_OP_TARGET_CONFLICT,
    MHG_OP_TARGET_PROBE_FAILED,
};

struct mhg_app_operation {
    uint64_t operation_id;
    char instance_id[33];
    enum mhg_app_request_kind kind;
    enum mhg_app_operation_state state;
    enum mhg_app_operation_error error;
    uint64_t config_generation;
    char diagnostic[200];
    char message_key[40];
};

#define MHG_APP_QUEUE_CAPACITY 32u
#define MHG_APP_OPERATION_CAPACITY 64u

struct mhg_app_operations {
    pthread_mutex_t lock;
    struct mhg_app_request requests[MHG_APP_QUEUE_CAPACITY];
    size_t head;
    size_t count;
    struct mhg_app_operation records[MHG_APP_OPERATION_CAPACITY];
    uint64_t next_id;
    char instance_id[33];
};

bool mhg_app_request_is_auth(enum mhg_app_request_kind kind);
bool mhg_app_operation_terminal(enum mhg_app_operation_state state);
int mhg_app_operations_init(struct mhg_app_operations *owner);
void mhg_app_operations_destroy(struct mhg_app_operations *owner);
bool mhg_app_operations_enqueue(struct mhg_app_operations *owner,
                                struct mhg_app_request *request);
bool mhg_app_operations_take(struct mhg_app_operations *owner,
                             struct mhg_app_request *out, bool config_ready);
bool mhg_app_operations_get(struct mhg_app_operations *owner, uint64_t id,
                            struct mhg_app_operation *out);
void mhg_app_operations_snapshot(struct mhg_app_operations *owner,
                                 struct mhg_app_operation *out);
void mhg_app_operations_cancel_auth_before(struct mhg_app_operations *owner,
                                           uint64_t id);
void mhg_app_operations_sync(struct mhg_app_operations *owner, uint64_t desired,
                             uint64_t synced, bool authority_ready, bool graph_ready);
void mhg_app_operations_finish(struct mhg_app_operations *owner, uint64_t id,
                               enum mhg_app_operation_state state,
                               enum mhg_app_operation_error error,
                               uint64_t config_generation, const char *diagnostic,
                               const char *message_key);

#endif
