#ifndef MHGEEK_ACCOUNT_STORE_H
#define MHGEEK_ACCOUNT_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "cloud_wire_types.h"

enum mhg_account_store_load_result {
    MHG_ACCOUNT_STORE_ERROR = -1,
    MHG_ACCOUNT_STORE_ABSENT = 0,
    MHG_ACCOUNT_STORE_PRESENT = 1,
};

enum mhg_account_store_commit_result {
    MHG_ACCOUNT_STORE_FAILED = -1,
    MHG_ACCOUNT_STORE_COMMITTED_DURABLE = 0,
    MHG_ACCOUNT_STORE_COMMITTED_NOT_DURABLE = 1,
};

struct mhg_account_record {
    uint64_t generation;
    struct mhg_secret_buf device_id;
    struct mhg_secret_buf user_id;
    struct mhg_secret_buf pass_token;
};

#define MHG_ACCOUNT_RECORD_INIT \
    {0u, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

/* data_root is a caller-owned plugin directory such as
 * /data/plugins/mhgeek. It is created or repaired to 0700 and must be an
 * absolute, non-symlink directory owned by the process effective uid. */
int mhg_account_store_prepare(const char *data_root,
                              char *account_path,
                              size_t account_path_size);

/* The local format is a closed, versioned strict-JSON record. load clears a
 * reusable output first and only publishes a fully validated 0600 record. */
int mhg_account_store_load(const char *account_path,
                           struct mhg_account_record *record);

/* COMMITTED_DURABLE is returned only after same-directory atomic install,
 * directory fsync, strict readback, and a durable commit decision. FAILED
 * leaves a recovery marker that makes the previous record authoritative.
 * COMMITTED_NOT_DURABLE means the new record is authoritative in the running
 * process, but the final directory fsync failed; both copies are retained so
 * restart recovery can safely select the marker state that reached storage. */
int mhg_account_store_commit(const char *account_path,
                             const struct mhg_account_record *record);

/* Clear returns an mhg_account_store_commit_result and atomically replaces
 * the credential-bearing record with a credential-
 * free generation tombstone so generation remains monotonic after restart.
 * A failure before durability restores the prior record. */
int mhg_account_store_clear(const char *account_path,
                            uint64_t cleared_generation);

void mhg_account_record_clear(struct mhg_account_record *record);

#ifdef MHG_ACCOUNT_STORE_TESTING
enum mhg_account_store_test_point {
    MHG_ACCOUNT_STORE_TEST_NONE = 0,
    MHG_ACCOUNT_STORE_TEST_TEMP_OPEN,
    MHG_ACCOUNT_STORE_TEST_WRITE,
    MHG_ACCOUNT_STORE_TEST_FILE_MODE,
    MHG_ACCOUNT_STORE_TEST_FILE_SYNC,
    MHG_ACCOUNT_STORE_TEST_INSTALL,
    MHG_ACCOUNT_STORE_TEST_DIRECTORY_SYNC,
    MHG_ACCOUNT_STORE_TEST_READBACK,
    MHG_ACCOUNT_STORE_TEST_CLEAR_INSTALL,
    MHG_ACCOUNT_STORE_TEST_CLEAR_DIRECTORY_SYNC,
    MHG_ACCOUNT_STORE_TEST_COMMIT_DIRECTORY_SYNC,
    MHG_ACCOUNT_STORE_TEST_ROLLBACK_EXCHANGE,
    MHG_ACCOUNT_STORE_TEST_ROLLBACK_RENAME,
    MHG_ACCOUNT_STORE_TEST_ROLLBACK_DIRECTORY_SYNC,
};

void mhg_account_store_test_fail_once(
    enum mhg_account_store_test_point point);
void mhg_account_store_test_fail_then(
    enum mhg_account_store_test_point first,
    enum mhg_account_store_test_point second);
#endif

#endif
