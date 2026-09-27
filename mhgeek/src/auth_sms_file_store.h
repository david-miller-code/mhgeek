#ifndef MHGEEK_AUTH_SMS_FILE_STORE_H
#define MHGEEK_AUTH_SMS_FILE_STORE_H

#include <limits.h>

#include "auth_sms.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct mhg_auth_sms_file_store {
    char account_path[PATH_MAX];
    char target_path[PATH_MAX];
    bool binding_invalidated;
};

/* Prepares the independent MHGeek private directory and returns a binding
 * suitable for mhg_auth_sms_create(). No MHCamera or MiGateway path is read. */
int mhg_auth_sms_file_store_init(struct mhg_auth_sms_file_store *file_store,
                                 const char *data_root,
                                 struct mhg_auth_sms_store *binding);

#endif
