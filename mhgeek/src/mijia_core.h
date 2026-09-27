#ifndef MHGEEK_MIJIA_CORE_H
#define MHGEEK_MIJIA_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "xiaomi_service.h"

enum mhg_core_method {
    MHG_CORE_AUTOWEBCONFIG = 1,
    MHG_CORE_CENTRAL_LINK_PASSCODE = 2,
};

enum mhg_core_header_value_source {
    MHG_CORE_HEADER_CONSTANT = 1,
    MHG_CORE_HEADER_MODEL = 2,
};

struct mhg_core_header {
    const char *name;
    const char *value;
    enum mhg_core_header_value_source source;
};

struct mhg_core_passcode {
    struct mhg_secret_buf value;
};

struct mhg_core_autowebconfig {
    struct mhg_secret_buf url;
};

#define MHG_CORE_PASSCODE_INIT {MHG_SECRET_BUF_INIT}
#define MHG_CORE_AUTOWEBCONFIG_INIT {MHG_SECRET_BUF_INIT}

/* Buffer/struct outputs must start at their INIT value. Public writers clear
 * reusable outputs on entry and leave them empty on failure. */

const char *mhg_core_base_url(void);
const char *mhg_core_method_name(enum mhg_core_method method);
const struct mhg_core_header *mhg_core_compatible_headers(size_t *count);

enum mhg_cloud_error mhg_core_canonical_path(
    const struct mhg_service_session *session, const char *did,
    struct mhg_secret_buf *path);
enum mhg_cloud_error mhg_core_build_data(
    enum mhg_core_method method, uint64_t id, const char *access_key,
    struct mhg_secret_buf *data_json);
enum mhg_cloud_error mhg_core_validate_data(const char *data_json);

enum mhg_cloud_error mhg_core_parse_passcode(
    const struct mhg_service_session *session, struct mhg_bytes_view result_json,
    struct mhg_core_passcode *passcode);
enum mhg_cloud_error mhg_core_parse_autowebconfig(
    const struct mhg_service_session *session,
    struct mhg_bytes_view result_json,
    struct mhg_core_autowebconfig *autowebconfig);
void mhg_core_passcode_clear(struct mhg_core_passcode *passcode);
void mhg_core_autowebconfig_clear(
    struct mhg_core_autowebconfig *autowebconfig);

#endif
