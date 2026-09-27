#ifndef MHGEEK_HTTPS_CLIENT_H
#define MHGEEK_HTTPS_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <curl/curl.h>

#include "cloud_wire_types.h"

struct mhg_https_client;

/* One HTTPS owner: a single CURL handle, its in-memory cookie jar and its
 * response buffers. The owner is not internally locked; the module that owns
 * the client serializes every call on it so two callers can never interleave a
 * transfer or share a jar. */
struct mhg_https_client_config {
    const char *ca_info;
    unsigned long connect_timeout_ms;
    unsigned long total_timeout_ms;
    size_t response_limit;
    bool allow_system_proxy;
    /* NULL-terminated libcurl CONNECT_TO entries, test-only: empty in
     * production so a trusted cloud hostname can never be pointed at another
     * peer. */
    const char *connect_to[4];
};

#define MHG_HTTPS_CLIENT_CONFIG_INIT \
    {NULL, 10000ul, 30000ul, 262144u, true, {NULL, NULL, NULL, NULL}}

/* A completed exchange. Location and Extension-Pragma are captured for the
 * callers that follow redirect chains themselves; a duplicate or empty
 * occurrence of either makes the response malformed. */
struct mhg_https_response {
    unsigned char *data;
    size_t len;
    size_t capacity;
    size_t limit;
    bool overflow;
    bool internal_failure;
    bool header_malformed;
    bool saw_location;
    bool saw_extension_pragma;
    struct mhg_secret_buf location;
    struct mhg_secret_buf extension_pragma;
};

#define MHG_HTTPS_RESPONSE_INIT \
    {NULL, 0u, 0u, 0u, false, false, false, false, false, \
     MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

struct mhg_https_request {
    const char *url;
    /* "GET" or "POST". A POST sends body and no content type of its own. */
    const char *method;
    struct curl_slist *headers;
    const struct mhg_secret_buf *body;
    const char *cookie;
    /* A 3xx is a completed exchange the caller inspects itself. */
    bool accept_redirect;
    /* 401 and 403 become MHG_CLOUD_AUTH_REJECTED; when false the caller
     * classifies the status itself. */
    bool reject_auth_status;
    /* Monotonic milliseconds; a value at or before now leaves the minimum
     * transfer timeout. */
    uint64_t deadline;
};

#define MHG_HTTPS_REQUEST_INIT \
    {NULL, NULL, NULL, NULL, NULL, false, false, 0u}

int mhg_https_client_create(struct mhg_https_client **client_out,
                            const struct mhg_https_client_config *config);
void mhg_https_client_destroy(struct mhg_https_client *client);

/* Runs one synchronous exchange. The response starts empty and must be
 * released with mhg_https_response_clear. */
enum mhg_cloud_error mhg_https_client_perform(
    struct mhg_https_client *client, const struct mhg_https_request *request,
    struct mhg_https_response *response, long *http_status);
void mhg_https_response_clear(struct mhg_https_response *response);

int mhg_https_client_clear_jar(struct mhg_https_client *client);
/* Hands the current jar contents to the caller; release with
 * mhg_https_client_free_cookie_list. */
enum mhg_cloud_error mhg_https_client_cookie_list(
    struct mhg_https_client *client, struct curl_slist **cookies_out);
void mhg_https_client_free_cookie_list(struct curl_slist *cookies);

struct curl_slist *mhg_https_client_append_header(struct curl_slist *headers,
                                                  const char *name,
                                                  const char *value);
void mhg_https_client_free_headers(struct curl_slist *headers);

/* Resolves a Location value against a base URL and requires both the base and
 * the resolved URL to pass the caller's exact-host trust predicate. Relative
 * locations are allowed; a resolved URL that leaves the trusted host, or an
 * unusable Location, fails. */
enum mhg_cloud_error mhg_https_resolve_redirect(
    const char *base, const char *location, const void *context,
    int (*is_trusted)(const void *context, const char *url),
    struct mhg_secret_buf *resolved);

uint64_t mhg_https_now_ms(void);

#endif
