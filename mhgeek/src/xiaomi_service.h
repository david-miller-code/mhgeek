#ifndef MHGEEK_XIAOMI_SERVICE_H
#define MHGEEK_XIAOMI_SERVICE_H

#include <stdbool.h>
#include <stddef.h>

#include "cloud_wire_types.h"

struct mhg_service_login {
    enum mhg_xiaomi_sid sid;
    struct mhg_secret_buf ssecurity;
    struct mhg_secret_buf pass_token;
    struct mhg_secret_buf location;
};

#define MHG_SERVICE_LOGIN_INIT \
    {0, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

enum mhg_service_provider_class {
    MHG_SERVICE_PROVIDER_NONE = 0,
    MHG_SERVICE_PROVIDER_CREDENTIAL_REJECTED = 1,
    MHG_SERVICE_PROVIDER_OTHER = 2,
};

/* Nonsecret provider metadata. Response text is deliberately never retained. */
struct mhg_service_provider_diagnostic {
    enum mhg_service_provider_class provider_class;
    int provider_code;
};

#define MHG_SERVICE_PROVIDER_DIAGNOSTIC_INIT \
    {MHG_SERVICE_PROVIDER_NONE, 0}
const char *mhg_service_provider_class_name(
    enum mhg_service_provider_class provider_class);

struct mhg_service_login_request_contract {
    const char *method;
    const char *path;
    const char *json_query_name;
    const char *json_query_value;
    const char *sid_query_name;
    const char *user_cookie_name;
    const char *pass_token_cookie_name;
};

struct mhg_cookie_pair {
    const char *name;
    const char *value;
};

struct mhg_service_session {
    enum mhg_xiaomi_sid sid;
    struct mhg_secret_buf user_id;
    struct mhg_secret_buf pass_token;
    struct mhg_secret_buf cuser_id;
    struct mhg_secret_buf service_token;
    struct mhg_secret_buf ssecurity;
};

#define MHG_SERVICE_SESSION_INIT \
    {0, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT}

enum mhg_catalog_online {
    MHG_CATALOG_ONLINE_UNKNOWN = 0,
    MHG_CATALOG_OFFLINE,
    MHG_CATALOG_ONLINE,
};

struct mhg_catalog_device {
    struct mhg_secret_buf did;
    struct mhg_secret_buf model;
    struct mhg_secret_buf local_ip;
    struct mhg_secret_buf token;
    enum mhg_catalog_online online;
};

#define MHG_CATALOG_DEVICE_INIT \
    {MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT, MHG_CATALOG_ONLINE_UNKNOWN}

struct mhg_catalog_page {
    bool has_more;
    size_t device_count;
    /* Entries a structurally valid page could not use (missing or mistyped
     * did). They are skipped and counted instead of
     * failing the whole page; the page itself is still published atomically. */
    size_t skipped;
    struct mhg_catalog_device *devices;
    struct mhg_secret_buf next_start_did;
};

#define MHG_CATALOG_PAGE_INIT \
    {false, 0u, 0u, NULL, MHG_SECRET_BUF_INIT}

/* All mutable outputs must start at the matching INIT value. Public writers
 * clear reusable outputs on entry and leave them empty on failure. */

const char *mhg_service_login_base_url(void);
const char *mhg_service_login_path(void);
const char *mhg_service_login_response_prefix(void);
int mhg_service_redirect_is_trusted(enum mhg_xiaomi_sid sid,
                                    const char *url);
/* The SID's exact STS host and the cookie visibility rules the service
 * redirect chain applies to it. Every one of these is a pure string
 * predicate; none of them performs I/O. */
const char *mhg_service_sts_host(enum mhg_xiaomi_sid sid);
int mhg_service_sts_request_path(enum mhg_xiaomi_sid sid, const char *url,
                                 const char **path_out, size_t *length_out);
int mhg_service_cookie_domain_matches(enum mhg_xiaomi_sid sid,
                                      const char *domain, size_t length);
int mhg_service_cookie_path_matches(const char *cookie_path,
                                    size_t cookie_length,
                                    const char *request_path,
                                    size_t request_length);

/* The tracked client gives up after four redirect hops. */
#define MHG_SERVICE_MAX_REDIRECT_HOPS 4u

const struct mhg_service_login_request_contract *
mhg_service_login_request_contract(void);
/* Service token-login carries the candidate pair only. The tracked client
 * drops the Passport jar (deviceId included) before this boundary. */
enum mhg_cloud_error mhg_service_login_cookie_header(
    const char *user_id, const char *pass_token,
    struct mhg_secret_buf *cookie_header);
enum mhg_cloud_error mhg_service_parse_token_login(
    enum mhg_xiaomi_sid sid, struct mhg_bytes_view response,
    struct mhg_service_login *login,
    struct mhg_service_provider_diagnostic *diagnostic);
void mhg_service_login_clear(struct mhg_service_login *login);

enum mhg_cloud_error mhg_service_finish_redirect(
    const struct mhg_service_login *login, const char *expected_user_id,
    const struct mhg_cookie_pair *cookies, size_t cookie_count,
    struct mhg_bytes_view extension_pragma_json,
    struct mhg_service_session *session);
void mhg_service_session_clear(struct mhg_service_session *session);
enum mhg_cloud_error mhg_service_cookie_profile(
    const struct mhg_service_session *session, const char *passport_device_id,
    struct mhg_secret_buf *cookie_header);

const char *mhg_catalog_base_url(void);
const char *mhg_catalog_path(void);
const char *mhg_catalog_initial_params(void);
enum mhg_cloud_error mhg_catalog_next_params(
    const char *start_did, struct mhg_secret_buf *params_json);
enum mhg_cloud_error mhg_catalog_parse_page(
    const struct mhg_service_session *session, struct mhg_bytes_view result_json,
    struct mhg_catalog_page *page);
void mhg_catalog_page_clear(struct mhg_catalog_page *page);

#endif
