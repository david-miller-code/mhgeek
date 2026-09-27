#ifndef MHGEEK_TARGET_STORE_H
#define MHGEEK_TARGET_STORE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "cloud_wire_types.h"

/* The selected target identity and, once LAN + Spec verification completed,
 * its exact Action identity. v1 files load as selected; all new commits use
 * v2. The accessKey and LAN dynamic passcode are never persisted here. */
enum mhg_target_action_state {
    MHG_TARGET_ACTION_SELECTED = 0,
    MHG_TARGET_ACTION_VERIFIED = 1,
};

struct mhg_target_record {
    uint64_t version;
    uint64_t catalog_generation;
    struct mhg_secret_buf ip;
    struct mhg_secret_buf did;
    struct mhg_secret_buf model;
    enum mhg_target_action_state action_state;
    struct mhg_secret_buf action_urn;
    int action_siid;
    int action_aiid;
    int action_piid;
};

#define MHG_TARGET_RECORD_INIT {0}

#define MHG_TARGET_VERSION_V1 1u
#define MHG_TARGET_VERSION_V2 2u

enum mhg_target_store_load_result {
    MHG_TARGET_STORE_ERROR = -1,
    MHG_TARGET_STORE_ABSENT = 0,
    MHG_TARGET_STORE_PRESENT = 1,
};

enum mhg_target_store_commit_result {
    MHG_TARGET_STORE_FAILED = -1,
    MHG_TARGET_STORE_COMMITTED_DURABLE = 0,
    MHG_TARGET_STORE_COMMITTED_NOT_DURABLE = 1,
};

/* data_root is a caller-owned plugin directory such as
 * /data/plugins/mhgeek. It is created or repaired to 0700 and must be an
 * absolute, non-symlink directory owned by the process effective uid. The
 * target path is `<data_root>/target.json`. */
int mhg_target_store_prepare(const char *data_root, char *target_path,
                             size_t target_path_size);

/* The local format is a closed, versioned strict-JSON record; load clears a
 * reusable output first and only publishes a fully validated 0600 record.
 * Every text field is bounded and restricted to printable ASCII, so a record
 * can always be re-read and never smuggles control or non-ASCII bytes. */
int mhg_target_store_load(const char *target_path,
                          struct mhg_target_record *record);

/* Replaces the record through a same-directory atomic install followed by a
 * directory fsync and strict readback. COMMITTED_NOT_DURABLE means the new
 * record is authoritative in the running process but the final directory
 * fsync failed. */
int mhg_target_store_commit(const char *target_path,
                            const struct mhg_target_record *record);

/* Removes the binding and any leftover temporary copy. There is no
 * tombstone: a cleared store simply has no target, so the user can submit a
 * new address without the previous binding limiting the choice. */
int mhg_target_store_clear(const char *target_path);

void mhg_target_record_clear(struct mhg_target_record *record);
int mhg_target_record_clone(struct mhg_target_record *destination,
                            const struct mhg_target_record *source);
bool mhg_target_record_same_device(const struct mhg_target_record *left,
                                   const struct mhg_target_record *right);
/* A live getDevList URN either matches a persisted verified Action (0), needs
 * first-time Spec derivation for a selected target (1), or is inconsistent
 * with the binding (-1). This does not itself authorize delivery: the caller
 * must still read back the graph and its Action parameters. */
int mhg_target_record_action_for_urn(const struct mhg_target_record *record,
                                     const char *live_urn, int *siid,
                                     int *aiid, int *piid);
#ifdef MHG_TARGET_STORE_TESTING
void mhg_target_store_test_fail_commit_sync_once(void);
void mhg_target_store_test_fail_clear_sync_once(void);
#endif

/* The exact field shape the record accepts. The resolver uses the same
 * predicate so an address it accepts can always be persisted. */
#define MHG_TARGET_IP_LIMIT 45u
#define MHG_TARGET_DID_LIMIT 128u
#define MHG_TARGET_MODEL_LIMIT 128u
#define MHG_TARGET_URN_LIMIT 191u
int mhg_target_field_is_valid(const char *text, size_t limit);

#endif
