#include "auth_sms_file_store.h"
#include "target_store.h"

#include <errno.h>
#include <string.h>

static int file_load(void *userdata, struct mhg_account_record *record)
{
    const struct mhg_auth_sms_file_store *store = userdata;
    int loaded = mhg_account_store_load(store->account_path, record);

    /* A nonzero absent generation is the durable clear intent. Complete the
     * second half before exposing a usable owner, including after power loss. */
    if (loaded == MHG_ACCOUNT_STORE_ABSENT && record->generation != 0u &&
        mhg_target_store_clear(store->target_path) !=
            MHG_TARGET_STORE_COMMITTED_DURABLE)
        return MHG_ACCOUNT_STORE_ERROR;
    return loaded;
}

static int file_commit(void *userdata,
                       const struct mhg_account_record *record)
{
    const struct mhg_auth_sms_file_store *store = userdata;
    return mhg_account_store_commit(store->account_path, record);
}

static int file_clear(void *userdata, uint64_t cleared_generation)
{
    struct mhg_auth_sms_file_store *store = userdata;
    int cleared = mhg_account_store_clear(store->account_path, cleared_generation);

    if (cleared == MHG_ACCOUNT_STORE_FAILED) return cleared;
    store->binding_invalidated = true;
    /* Once the tombstone is installed, the old credential/target pair must
     * not be used, even if either directory durability check fails. Retrying
     * persistence repeats this same transaction; startup replays its intent. */
    if (mhg_target_store_clear(store->target_path) !=
            MHG_TARGET_STORE_COMMITTED_DURABLE)
        return MHG_ACCOUNT_STORE_COMMITTED_NOT_DURABLE;
    return cleared;
}

int mhg_auth_sms_file_store_init(struct mhg_auth_sms_file_store *file_store,
                                 const char *data_root,
                                 struct mhg_auth_sms_store *binding)
{
    static const struct mhg_auth_sms_store_ops operations = {
        file_load, file_commit, file_clear,
    };

    if (!file_store || !data_root || !binding) {
        errno = EINVAL;
        return -1;
    }
    memset(file_store, 0, sizeof(*file_store));
    memset(binding, 0, sizeof(*binding));
    if (mhg_account_store_prepare(data_root, file_store->account_path,
                                  sizeof(file_store->account_path)) != 0 ||
        mhg_target_store_prepare(data_root, file_store->target_path,
                                 sizeof(file_store->target_path)) != 0)
        return -1;
    binding->ops = &operations;
    binding->userdata = file_store;
    return 0;
}
