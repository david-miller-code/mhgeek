#ifndef MHGEEK_RESOURCE_STORE_H
#define MHGEEK_RESOURCE_STORE_H
#include "cloud_wire_types.h"
#include "presence_delivery.h"
#include <stddef.h>
#include <stdint.h>
#define MHG_RESOURCE_VARIABLE_COUNT (MHG_PRESENCE_SLOT_COUNT * 2u)
#define MHG_RESOURCE_STATE_VARIABLE_COUNT MHG_PRESENCE_SLOT_COUNT
#define MHG_RESOURCE_VERSION 4u
enum mhg_resource_stage {
    MHG_RESOURCE_STAGE_PROVISIONING = 0,
    MHG_RESOURCE_STAGE_READY = 1
};
enum mhg_resource_seed_state {
    MHG_RESOURCE_SEED_UNSTARTED = 0,
    MHG_RESOURCE_SEED_CREATE_UNCERTAIN,
    MHG_RESOURCE_SEED_RETRY_CREATE,
    MHG_RESOURCE_SEED_VERIFIED,
};
struct mhg_resource_record {
    uint64_t version;
    uint64_t resource_generation;
    uint64_t spec_generation;
    /* Durable events.json generation whose complete graph passed readback. */
    uint64_t config_generation;
    enum mhg_resource_stage stage;
    enum mhg_resource_seed_state seed_state;
    enum mhg_resource_seed_state global_seed_state;
    struct mhg_secret_buf digest;
    struct mhg_secret_buf target_did;
    struct mhg_secret_buf target_model;
    struct mhg_secret_buf graph_id;
    struct mhg_secret_buf scope;
    struct mhg_secret_buf action_urn;
    int action_siid;
    int action_aiid;
    int action_piid;
    struct mhg_secret_buf local_variables[MHG_RESOURCE_STATE_VARIABLE_COUNT];
    struct mhg_secret_buf global_variables[MHG_RESOURCE_STATE_VARIABLE_COUNT];
};
#define MHG_RESOURCE_RECORD_INIT {0}
enum mhg_resource_store_load_result {
    MHG_RESOURCE_STORE_ERROR = -1,
    MHG_RESOURCE_STORE_ABSENT = 0,
    MHG_RESOURCE_STORE_PRESENT = 1
};
enum mhg_resource_store_commit_result {
    MHG_RESOURCE_STORE_FAILED = -1,
    MHG_RESOURCE_STORE_COMMITTED_DURABLE = 0,
    MHG_RESOURCE_STORE_COMMITTED_NOT_DURABLE = 1
};
/* Private derived ownership cache; no credentials or user configuration. */
int mhg_resource_store_prepare(const char *data_root, char *path, size_t path_size);
int mhg_resource_store_select_path(const char *base_path,
                                   const struct mhg_secret_buf *target_did,
                                   const struct mhg_secret_buf *target_model,
                                   char *selected, size_t selected_size);
int mhg_resource_store_load(const char *path, struct mhg_resource_record *record);
int mhg_resource_store_commit(const char *path,
                              const struct mhg_resource_record *record);
int mhg_resource_store_clear(const char *path);
int mhg_resource_store_confirm_durable(const char *path,
                                       const struct mhg_resource_record *expected);
const struct mhg_secret_buf *
mhg_resource_variable(const struct mhg_resource_record *record,
                      enum mhg_presence_slot slot, bool present);
const struct mhg_secret_buf *
mhg_resource_global_variable(const struct mhg_resource_record *record,
                             enum mhg_presence_slot slot);
int mhg_resource_node_id(enum mhg_presence_slot slot, bool present, bool trigger,
                         char *out, size_t out_size);
void mhg_resource_record_clear(struct mhg_resource_record *record);
int mhg_resource_record_clone(struct mhg_resource_record *destination,
                              const struct mhg_resource_record *source);
#endif
