#define _POSIX_C_SOURCE 200809L

#include "https_client.h"

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

struct mhg_https_client {
    CURL *curl;
    struct mhg_https_client_config config;
};

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_global_result = CURLE_FAILED_INIT;

static void init_curl(void)
{
    curl_global_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

uint64_t mhg_https_now_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0u;
    return (uint64_t)value.tv_sec * 1000u +
           (uint64_t)value.tv_nsec / 1000000u;
}

void mhg_https_response_clear(struct mhg_https_response *response)
{
    if (!response) return;
    if (response->data) {
        mhg_secure_clear(response->data, response->capacity);
        free(response->data);
    }
    mhg_secret_buf_clear(&response->location);
    mhg_secret_buf_clear(&response->extension_pragma);
    memset(response, 0, sizeof(*response));
}

static size_t response_write(char *input, size_t size, size_t count,
                             void *userdata)
{
    struct mhg_https_response *response = userdata;
    size_t bytes;
    size_t needed;
    size_t capacity;
    unsigned char *grown;

    if (!response || (size != 0u && count > SIZE_MAX / size)) return 0u;
    bytes = size * count;
    if (bytes > response->limit - response->len) {
        response->overflow = true;
        return 0u;
    }
    needed = response->len + bytes + 1u;
    if (needed > response->capacity) {
        capacity = response->capacity ? response->capacity : 1024u;
        while (capacity < needed) {
            if (capacity > (response->limit + 1u) / 2u) {
                capacity = response->limit + 1u;
                break;
            }
            capacity *= 2u;
        }
        grown = realloc(response->data, capacity);
        if (!grown) {
            response->internal_failure = true;
            return 0u;
        }
        response->data = grown;
        response->capacity = capacity;
    }
    if (bytes) memcpy(response->data + response->len, input, bytes);
    response->len += bytes;
    response->data[response->len] = '\0';
    return bytes;
}

static size_t response_header(char *input, size_t size, size_t count,
                              void *userdata)
{
    static const char extension_name[] = "extension-pragma:";
    static const char location_name[] = "location:";
    struct mhg_https_response *response = userdata;
    struct mhg_secret_buf *destination;
    size_t name_length;
    size_t bytes;
    size_t begin;
    size_t end;

    if (!response || (size != 0u && count > SIZE_MAX / size)) return 0u;
    bytes = size * count;
    if (bytes >= 5u && strncasecmp(input, "HTTP/", 5u) == 0) {
        mhg_secret_buf_clear(&response->extension_pragma);
        mhg_secret_buf_clear(&response->location);
        response->header_malformed = false;
        response->saw_extension_pragma = false;
        response->saw_location = false;
        return bytes;
    }
    if (bytes >= sizeof(extension_name) - 1u &&
        strncasecmp(input, extension_name,
                    sizeof(extension_name) - 1u) == 0) {
        name_length = sizeof(extension_name) - 1u;
        destination = &response->extension_pragma;
        if (response->saw_extension_pragma) {
            response->header_malformed = true;
            return bytes;
        }
        response->saw_extension_pragma = true;
    } else if (bytes >= sizeof(location_name) - 1u &&
               strncasecmp(input, location_name,
                           sizeof(location_name) - 1u) == 0) {
        name_length = sizeof(location_name) - 1u;
        destination = &response->location;
        if (response->saw_location) {
            response->header_malformed = true;
            return bytes;
        }
        response->saw_location = true;
    } else {
        return bytes;
    }
    begin = name_length;
    while (begin < bytes && (input[begin] == ' ' || input[begin] == '\t'))
        ++begin;
    end = bytes;
    while (end > begin && (input[end - 1u] == '\r' ||
                           input[end - 1u] == '\n' ||
                           input[end - 1u] == ' ' || input[end - 1u] == '\t'))
        --end;
    if (end - begin > response->limit) {
        response->overflow = true;
        return 0u;
    }
    if (end == begin) {
        response->header_malformed = true;
        return bytes;
    }
    if (mhg_secret_buf_set(destination, input + begin, end - begin) != 0) {
        response->internal_failure = true;
        return 0u;
    }
    return bytes;
}

static enum mhg_cloud_error map_curl(CURLcode code,
                                     const struct mhg_https_response *response)
{
    if (response->overflow) return MHG_CLOUD_MALFORMED;
    if (response->internal_failure) return MHG_CLOUD_INTERNAL;
    switch (code) {
    case CURLE_OK: return MHG_CLOUD_OK;
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CIPHER:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_SSL_ISSUER_ERROR:
        return MHG_CLOUD_CRYPTO;
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_COULDNT_CONNECT:
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_ABORTED_BY_CALLBACK:
        return MHG_CLOUD_NETWORK;
    case CURLE_WEIRD_SERVER_REPLY: return MHG_CLOUD_MALFORMED;
    case CURLE_OUT_OF_MEMORY: return MHG_CLOUD_INTERNAL;
    default: return MHG_CLOUD_NETWORK;
    }
}

struct curl_slist *mhg_https_client_append_header(struct curl_slist *headers,
                                                  const char *name,
                                                  const char *value)
{
    size_t name_length;
    size_t value_length;
    unsigned char *rendered;
    struct curl_slist *grown;

    if (!name || !value || strchr(name, ':') || strpbrk(name, "\r\n") ||
        strpbrk(value, "\r\n"))
        return NULL;
    name_length = strlen(name);
    value_length = strlen(value);
    rendered = malloc(name_length + value_length + 3u);
    if (!rendered) return NULL;
    memcpy(rendered, name, name_length);
    memcpy(rendered + name_length, ": ", 2u);
    memcpy(rendered + name_length + 2u, value, value_length);
    rendered[name_length + value_length + 2u] = '\0';
    grown = curl_slist_append(headers, (const char *)rendered);
    mhg_secure_clear(rendered, name_length + value_length + 3u);
    free(rendered);
    return grown;
}

void mhg_https_client_free_headers(struct curl_slist *headers)
{
    struct curl_slist *item;
    for (item = headers; item; item = item->next)
        if (item->data) mhg_secure_clear(item->data, strlen(item->data));
    curl_slist_free_all(headers);
}

int mhg_https_client_clear_jar(struct mhg_https_client *client)
{
    if (!client) return -1;
    return curl_easy_setopt(client->curl, CURLOPT_COOKIELIST, "ALL") == CURLE_OK
        ? 0 : -1;
}

enum mhg_cloud_error mhg_https_client_cookie_list(
    struct mhg_https_client *client, struct curl_slist **cookies_out)
{
    struct curl_slist *cookies = NULL;
    if (cookies_out) *cookies_out = NULL;
    if (!client || !cookies_out) return MHG_CLOUD_INPUT;
    if (curl_easy_getinfo(client->curl, CURLINFO_COOKIELIST, &cookies) !=
        CURLE_OK)
        return MHG_CLOUD_INTERNAL;
    *cookies_out = cookies;
    return MHG_CLOUD_OK;
}

void mhg_https_client_free_cookie_list(struct curl_slist *cookies)
{
    mhg_https_client_free_headers(cookies);
}

enum mhg_cloud_error mhg_https_resolve_redirect(
    const char *base, const char *location, const void *context,
    int (*is_trusted)(const void *context, const char *url),
    struct mhg_secret_buf *resolved)
{
    CURLU *url = NULL;
    char *value = NULL;
    CURLUcode code;
    enum mhg_cloud_error result = MHG_CLOUD_MALFORMED;

    if (resolved) mhg_secret_buf_clear(resolved);
    if (!base || !location || !location[0] || !is_trusted || !resolved)
        return MHG_CLOUD_INPUT;
    if (!is_trusted(context, base)) return MHG_CLOUD_INPUT;
    url = curl_url();
    if (!url) return MHG_CLOUD_INTERNAL;
    code = curl_url_set(url, CURLUPART_URL, base, 0u);
    if (code == CURLUE_OK)
        code = curl_url_set(url, CURLUPART_URL, location, 0u);
    if (code == CURLUE_OK)
        code = curl_url_get(url, CURLUPART_URL, &value, 0u);
    if (code != CURLUE_OK || !is_trusted(context, value)) goto out;
    if (mhg_secret_buf_set(resolved, value, strlen(value)) != 0)
        result = MHG_CLOUD_INTERNAL;
    else
        result = MHG_CLOUD_OK;
out:
    if (value) {
        mhg_secure_clear(value, strlen(value));
        curl_free(value);
    }
    curl_url_cleanup(url);
    return result;
}

int mhg_https_client_create(struct mhg_https_client **client_out,
                            const struct mhg_https_client_config *config)
{
    struct mhg_https_client *client;
    CURL *curl;

    if (client_out) *client_out = NULL;
    if (!client_out || !config || config->connect_timeout_ms == 0ul ||
        config->total_timeout_ms == 0ul || config->response_limit == 0u ||
        config->response_limit > INT_MAX)
        return -1;
    pthread_once(&curl_once, init_curl);
    if (curl_global_result != CURLE_OK) return -1;
    client = calloc(1u, sizeof(*client));
    if (!client) return -1;
    client->config = *config;
    curl = curl_easy_init();
    if (!curl) {
        free(client);
        return -1;
    }
    client->curl = curl;
    *client_out = client;
    return 0;
}

void mhg_https_client_destroy(struct mhg_https_client *client)
{
    if (!client) return;
    if (client->curl) {
        (void)curl_easy_setopt(client->curl, CURLOPT_COOKIELIST, "ALL");
        curl_easy_cleanup(client->curl);
    }
    mhg_secure_clear(client, sizeof(*client));
    free(client);
}

static unsigned long remaining_ms(const struct mhg_https_client *client,
                                  uint64_t deadline)
{
    uint64_t now = mhg_https_now_ms();
    uint64_t left;

    if (!now || now >= deadline) return 1ul;
    left = deadline - now;
    if (left > client->config.total_timeout_ms)
        left = client->config.total_timeout_ms;
    return left > ULONG_MAX ? ULONG_MAX : (unsigned long)left;
}

enum mhg_cloud_error mhg_https_client_perform(
    struct mhg_https_client *client, const struct mhg_https_request *request,
    struct mhg_https_response *response, long *http_status)
{
    CURLcode code;
    CURLcode info;
    unsigned long timeout;
    struct curl_slist *connect_to = NULL;
    bool is_post;
    size_t index;

    if (response) mhg_https_response_clear(response);
    if (!client || !request || !response || !http_status || !request->url ||
        !request->method)
        return MHG_CLOUD_INPUT;
    is_post = strcmp(request->method, "POST") == 0;
    if (!is_post && strcmp(request->method, "GET") != 0) return MHG_CLOUD_INPUT;
    *http_status = 0;
    response->limit = client->config.response_limit;
    timeout = remaining_ms(client, request->deadline);
    curl_easy_reset(client->curl);
    if (curl_easy_setopt(client->curl, CURLOPT_URL, request->url) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER,
                         request->headers) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION,
                         response_write) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, response) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_HEADERFUNCTION,
                         response_header) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_HEADERDATA, response) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_PROTOCOLS_STR, "https") !=
            CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_REDIR_PROTOCOLS_STR, "https") !=
            CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_SUPPRESS_CONNECT_HEADERS,
                         1L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_CONNECTTIMEOUT_MS,
                         client->config.connect_timeout_ms) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_TIMEOUT_MS, timeout) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(client->curl, CURLOPT_COOKIEFILE, "") != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (request->cookie &&
        curl_easy_setopt(client->curl, CURLOPT_COOKIE,
                         request->cookie) != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (client->config.ca_info &&
        curl_easy_setopt(client->curl, CURLOPT_CAINFO,
                         client->config.ca_info) != CURLE_OK)
        return MHG_CLOUD_NOT_DISPATCHED;
    if (!client->config.allow_system_proxy &&
        (curl_easy_setopt(client->curl, CURLOPT_PROXY, "") != CURLE_OK ||
         curl_easy_setopt(client->curl, CURLOPT_NOPROXY, "*") != CURLE_OK))
        return MHG_CLOUD_NOT_DISPATCHED;
    for (index = 0u; index < 4u; ++index) {
        if (!client->config.connect_to[index]) continue;
        {
            struct curl_slist *grown = curl_slist_append(
                connect_to, client->config.connect_to[index]);
            if (!grown) {
                curl_slist_free_all(connect_to);
                return MHG_CLOUD_NOT_DISPATCHED;
            }
            connect_to = grown;
        }
    }
    if (connect_to &&
        curl_easy_setopt(client->curl, CURLOPT_CONNECT_TO, connect_to) !=
            CURLE_OK) {
        curl_slist_free_all(connect_to);
        return MHG_CLOUD_NOT_DISPATCHED;
    }
    if (is_post &&
        (curl_easy_setopt(client->curl, CURLOPT_POST, 1L) != CURLE_OK ||
         curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS,
                          request->body && request->body->data ?
                              (const char *)request->body->data : "") !=
             CURLE_OK ||
         curl_easy_setopt(client->curl, CURLOPT_POSTFIELDSIZE_LARGE,
                          (curl_off_t)(request->body ? request->body->len :
                                                       0u)) != CURLE_OK)) {
        curl_slist_free_all(connect_to);
        return MHG_CLOUD_NOT_DISPATCHED;
    }
    code = curl_easy_perform(client->curl);
    info = curl_easy_getinfo(client->curl, CURLINFO_RESPONSE_CODE,
                            http_status);
    curl_slist_free_all(connect_to);
    /* CURLOPT_FAILONERROR is never set: a 4xx/5xx is a completed exchange and
     * is classified by status, not by the transport layer. */
    if (code != CURLE_OK) return map_curl(code, response);
    if (info != CURLE_OK) return MHG_CLOUD_INTERNAL;
    if (response->overflow || response->header_malformed)
        return MHG_CLOUD_MALFORMED;
    if (response->internal_failure) return MHG_CLOUD_INTERNAL;
    if (*http_status == 401 || *http_status == 403)
        return request->reject_auth_status ? MHG_CLOUD_AUTH_REJECTED
                                           : MHG_CLOUD_OK;
    if (*http_status >= 200 && *http_status < 300) return MHG_CLOUD_OK;
    if (request->accept_redirect && *http_status >= 300 && *http_status < 400)
        return MHG_CLOUD_OK;
    return MHG_CLOUD_HTTP;
}
