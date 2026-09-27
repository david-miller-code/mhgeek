#define _POSIX_C_SOURCE 200809L
#include "transport.h"

#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if LIBCURL_VERSION_NUM < 0x081400
#error "mhgeek WebSocket transport requires libcurl 8.20.0 or newer"
#endif

#define MHG_TRANSPORT_POLL_MS 30u

struct mhg_transport {
    CURL *easy;
    CURLM *multi;
    curl_socket_t socket;
    const volatile sig_atomic_t *stop;
    size_t max_message;
    struct mhg_buf incoming;
    size_t incoming_used;
    size_t incoming_frame_offset;
    uint64_t connect_deadline;
    struct mhg_error connect_error;
    bool added;
    bool failed;
};

static int curl_error(struct mhg_error *error, CURLcode code,
                       const char *operation)
{
    int number = code == CURLE_OUT_OF_MEMORY ? ENOMEM :
                 code == CURLE_OPERATION_TIMEDOUT ? ETIMEDOUT :
                 code == CURLE_GOT_NOTHING ? ECONNRESET : EIO;
    return mhg_errorf(error, number, "%s failed: %s", operation,
                      curl_easy_strerror(code));
}

static int connect_progress(void *userdata, curl_off_t download_total,
                             curl_off_t downloaded, curl_off_t upload_total,
                             curl_off_t uploaded)
{
    struct mhg_transport *transport = userdata;
    (void)download_total;
    (void)downloaded;
    (void)upload_total;
    (void)uploaded;
    return mhg_remaining_ms(transport->connect_deadline,
                            MHG_TRANSPORT_POLL_MS, transport->stop,
                            &transport->connect_error) < 0;
}

static size_t discard_http_body(char *data, size_t size, size_t count,
                                 void *userdata)
{
    (void)data;
    (void)userdata;
    return size && count > SIZE_MAX / size ? 0 : size * count;
}

static char *websocket_url(const char *base_url, struct mhg_error *error)
{
    CURLU *url = NULL;
    char *scheme = NULL;
    char *host = NULL;
    char *result = NULL;
    const char *target_scheme;
    CURLUcode code;

    if (!base_url || !base_url[0]) {
        mhg_errorf(error, EINVAL, "gateway URL is required");
        return NULL;
    }
    url = curl_url();
    if (!url) {
        mhg_errorf(error, ENOMEM, "gateway URL allocation failed");
        return NULL;
    }
    code = curl_url_set(url, CURLUPART_URL, base_url, CURLU_DISALLOW_USER);
    if (code != CURLUE_OK ||
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK || !host[0]) {
        mhg_errorf(error, EINVAL, "invalid gateway URL or embedded credentials");
        goto done;
    }
    if (strcmp(scheme, "http") == 0 || strcmp(scheme, "ws") == 0)
        target_scheme = "ws";
    else if (strcmp(scheme, "https") == 0 || strcmp(scheme, "wss") == 0)
        target_scheme = "wss";
    else {
        mhg_errorf(error, EINVAL, "gateway URL must use HTTP, HTTPS, WS or WSS");
        goto done;
    }
    if (curl_url_set(url, CURLUPART_SCHEME, target_scheme, 0) != CURLUE_OK ||
        curl_url_set(url, CURLUPART_PATH, "/centrallinkws/", 0) != CURLUE_OK ||
        curl_url_set(url, CURLUPART_QUERY, NULL, 0) != CURLUE_OK ||
        curl_url_set(url, CURLUPART_FRAGMENT, NULL, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_URL, &result, 0) != CURLUE_OK) {
        mhg_errorf(error, EINVAL, "gateway WebSocket URL construction failed");
    }
done:
    curl_free(scheme);
    curl_free(host);
    curl_url_cleanup(url);
    return result;
}

static int wait_socket(struct mhg_transport *transport, short events,
                        uint64_t deadline, struct mhg_error *error)
{
    struct pollfd descriptor = { .fd = transport->socket, .events = events };
    for (;;) {
        int remaining = mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                                          transport->stop, error);
        int result;
        if (remaining < 0) return -1;
        result = poll(&descriptor, 1, remaining);
        if (result < 0) {
            if (errno == EINTR) continue;
            return mhg_errorf(error, errno, "WebSocket polling failed");
        }
        if (result == 0) continue;
        if (descriptor.revents & POLLNVAL)
            return mhg_errorf(error, EBADF, "WebSocket socket is invalid");
        /* Let curl consume buffered data or report TLS/EOF on HUP/ERR. */
        if (descriptor.revents & (events | POLLHUP | POLLERR)) return 0;
    }
}

static int connect_until(struct mhg_transport *transport, uint64_t deadline,
                          struct mhg_error *error)
{
    CURLMcode multi_code;
    CURLMsg *message;
    int running = 0;
    int messages;
    for (;;) {
        int wait_ms = mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                                        transport->stop, error);
        if (wait_ms < 0) return -1;
        multi_code = curl_multi_perform(transport->multi, &running);
        if (multi_code != CURLM_OK)
            return mhg_errorf(error, EIO, "WebSocket connect driver failed: %s",
                              curl_multi_strerror(multi_code));
        while ((message = curl_multi_info_read(transport->multi, &messages))) {
            if (message->msg != CURLMSG_DONE || message->easy_handle != transport->easy)
                continue;
            if (message->data.result != CURLE_OK) {
                if (transport->connect_error.code)
                    return mhg_errorf(error, transport->connect_error.code,
                                      "%s", transport->connect_error.message);
                return curl_error(error, message->data.result, "WebSocket connect");
            }
            return mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                                     transport->stop, error) < 0 ? -1 : 0;
        }
        if (!running)
            return mhg_errorf(error, EIO, "WebSocket connect completed without result");
        multi_code = curl_multi_poll(transport->multi, NULL, 0, wait_ms, NULL);
        if (multi_code != CURLM_OK)
            return mhg_errorf(error, EIO, "WebSocket connect polling failed: %s",
                              curl_multi_strerror(multi_code));
    }
}

struct mhg_transport *mhg_transport_open(
    const char *base_url, size_t max_message, uint64_t deadline,
    const volatile sig_atomic_t *stop, struct mhg_error *error)
{
    struct mhg_transport *transport = NULL;
    char *url = NULL;
    CURLcode code;
    CURLMcode multi_code;
    int remaining;
    long response_code = 0;

    if (!max_message || max_message > INT64_MAX) {
        mhg_errorf(error, EINVAL, "invalid WebSocket message capacity");
        return NULL;
    }
    remaining = mhg_remaining_ms(deadline, INT_MAX, stop, error);
    if (remaining < 0) return NULL;
    url = websocket_url(base_url, error);
    if (!url) return NULL;
    transport = calloc(1, sizeof(*transport));
    if (!transport) {
        mhg_errorf(error, ENOMEM, "WebSocket transport allocation failed");
        goto failed;
    }
    transport->socket = CURL_SOCKET_BAD;
    transport->max_message = max_message;
    transport->stop = stop;
    transport->connect_deadline = deadline;
    transport->easy = curl_easy_init();
    transport->multi = curl_multi_init();
    if (!transport->easy || !transport->multi) {
        mhg_errorf(error, ENOMEM, "WebSocket curl allocation failed");
        goto failed;
    }
    /* A canceled DNS/NSS worker must not extend the caller's deadline while
     * curl_multi_cleanup joins resolver threads. Detached curl workers retain
     * their own storage until the resolver returns. */
    multi_code = curl_multi_setopt(transport->multi, CURLMOPT_QUICK_EXIT, 1L);
    if (multi_code != CURLM_OK) {
        mhg_errorf(error, EIO, "WebSocket resolver cleanup configuration failed: %s",
                    curl_multi_strerror(multi_code));
        goto failed;
    }
#define SET_OPTION(option, value) do { \
    code = curl_easy_setopt(transport->easy, option, value); \
    if (code != CURLE_OK) { curl_error(error, code, #option); goto failed; } \
} while (0)
    SET_OPTION(CURLOPT_URL, url);
    SET_OPTION(CURLOPT_CONNECT_ONLY, 2L);
    SET_OPTION(CURLOPT_PROTOCOLS_STR, "ws,wss");
    SET_OPTION(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    SET_OPTION(CURLOPT_FOLLOWLOCATION, 0L);
    SET_OPTION(CURLOPT_WRITEFUNCTION, discard_http_body);
    SET_OPTION(CURLOPT_NOSIGNAL, 1L);
    SET_OPTION(CURLOPT_PROXY, "");
    SET_OPTION(CURLOPT_NOPROXY, "*");
    SET_OPTION(CURLOPT_SSL_VERIFYPEER, 1L);
    SET_OPTION(CURLOPT_SSL_VERIFYHOST, 2L);
    SET_OPTION(CURLOPT_TIMEOUT_MS, (long)remaining);
    SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, (long)remaining);
    SET_OPTION(CURLOPT_NOPROGRESS, 0L);
    SET_OPTION(CURLOPT_XFERINFOFUNCTION, connect_progress);
    SET_OPTION(CURLOPT_XFERINFODATA, transport);
#undef SET_OPTION
    multi_code = curl_multi_add_handle(transport->multi, transport->easy);
    if (multi_code != CURLM_OK) {
        mhg_errorf(error, EIO, "WebSocket connect admission failed: %s",
                    curl_multi_strerror(multi_code));
        goto failed;
    }
    transport->added = true;
    if (connect_until(transport, deadline, error) != 0) goto failed;
    code = curl_easy_getinfo(transport->easy, CURLINFO_RESPONSE_CODE, &response_code);
    if (code != CURLE_OK) {
        curl_error(error, code, "WebSocket response status");
        goto failed;
    }
    if (response_code != 101L) {
        mhg_errorf(error, EPROTO, "gateway did not upgrade WebSocket connection");
        goto failed;
    }
    code = curl_easy_getinfo(transport->easy, CURLINFO_ACTIVESOCKET, &transport->socket);
    if (code != CURLE_OK || transport->socket == CURL_SOCKET_BAD) {
        if (code != CURLE_OK) curl_error(error, code, "WebSocket socket lookup");
        else mhg_errorf(error, ENOTCONN, "WebSocket has no active socket");
        goto failed;
    }
    curl_free(url);
    return transport;
failed:
    curl_free(url);
    mhg_transport_close(transport);
    return NULL;
}

int mhg_transport_send(struct mhg_transport *transport, const void *data,
                       size_t length, uint64_t deadline,
                       struct mhg_error *error)
{
    const unsigned char *bytes = data;
    size_t offset = 0;
    if (!transport || transport->failed || (!data && length))
        return mhg_errorf(error, EINVAL, "invalid WebSocket send state");
    if (length > transport->max_message)
        return mhg_errorf(error, EMSGSIZE, "WebSocket message exceeds capacity");
    for (;;) {
        size_t sent = 0;
        CURLcode code;
        if (mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                              transport->stop, error) < 0) goto failed;
        code = curl_ws_send(transport->easy, bytes ? (const void *)(bytes + offset) : "",
                            length - offset, &sent, 0, CURLWS_BINARY);
        if (sent > length - offset) {
            mhg_errorf(error, EPROTO, "invalid WebSocket send count");
            goto failed;
        }
        offset += sent;
        if (code == CURLE_OK && offset == length) {
            if (mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                                  transport->stop, error) < 0) goto failed;
            return 0;
        }
        if (code != CURLE_OK && code != CURLE_AGAIN) {
            curl_error(error, code, "WebSocket send");
            goto failed;
        }
        if (wait_socket(transport, POLLOUT, deadline, error) != 0) goto failed;
    }
failed:
    transport->failed = true;
    return -1;
}

static int message_append(struct mhg_buf *storage, size_t *used,
                            const void *chunk, size_t length, size_t required,
                            size_t maximum, struct mhg_error *error)
{
    if (required > storage->len) {
        struct mhg_buf next = {0};
        size_t capacity = storage->len ? storage->len : 1024u;
        if (capacity > maximum) capacity = maximum;
        while (capacity < required) {
            if (capacity > maximum / 2u) capacity = maximum;
            else capacity *= 2u;
        }
        if (mhg_buf_alloc(&next, capacity, error) != 0) return -1;
        if (*used) memcpy(next.data, storage->data, *used);
        mhg_buf_clear(storage);
        *storage = next;
    }
    if (length) memcpy(storage->data + *used, chunk, length);
    *used += length;
    return 0;
}

int mhg_transport_pump(struct mhg_transport *transport, struct mhg_buf *out,
                       int *complete, struct mhg_error *error)
{
    unsigned char chunk[8192];
    if (!transport || transport->failed || !out || !complete || out->data || out->len)
        return mhg_errorf(error, EINVAL, "invalid WebSocket receive state");
    *complete = 0;
    for (;;) {
        const struct curl_ws_frame *frame = NULL;
        size_t received = 0;
        size_t required;
        CURLcode code;
        int kind;
        if (transport->stop && *transport->stop) {
            mhg_errorf(error, ECANCELED, "WebSocket receive stopped");
            goto failed;
        }
        code = curl_ws_recv(transport->easy, chunk, sizeof(chunk), &received, &frame);
        if (code == CURLE_AGAIN) return 0;
        if (code != CURLE_OK) {
            curl_error(error, code, "WebSocket receive");
            goto failed;
        }
        if (!frame || received > sizeof(chunk) || frame->offset < 0 ||
            frame->bytesleft < 0) {
            mhg_errorf(error, EPROTO, "invalid WebSocket frame metadata");
            goto failed;
        }
        kind = frame->flags & (CURLWS_BINARY | CURLWS_TEXT | CURLWS_CLOSE |
                               CURLWS_PING | CURLWS_PONG);
        if (kind == CURLWS_CLOSE) {
            mhg_errorf(error, ECONNRESET, "gateway closed WebSocket connection");
            goto failed;
        }
        /* libcurl answers PING itself. PONG is unrelated to binary messages. */
        if (kind == CURLWS_PING || kind == CURLWS_PONG) continue;
        if (kind != CURLWS_BINARY ||
            (uint64_t)frame->offset != transport->incoming_frame_offset) {
            mhg_errorf(error, EPROTO, "gateway sent an unexpected WebSocket frame");
            goto failed;
        }
        if (received > transport->max_message - transport->incoming_used ||
            (uint64_t)frame->bytesleft >
                transport->max_message - transport->incoming_used - received) {
            mhg_errorf(error, EMSGSIZE, "WebSocket message exceeds capacity");
            goto failed;
        }
        required = transport->incoming_used + received + (size_t)frame->bytesleft;
        if (message_append(&transport->incoming, &transport->incoming_used,
                            chunk, received, required,
                            transport->max_message, error) != 0) goto failed;
        transport->incoming_frame_offset += received;
        if (frame->bytesleft != 0) continue;
        transport->incoming_frame_offset = 0;
        if (frame->flags & CURLWS_CONT) continue;
        if (transport->incoming_used) {
            struct mhg_buf message = {0};
            if (mhg_buf_alloc(&message, transport->incoming_used, error) != 0)
                goto failed;
            memcpy(message.data, transport->incoming.data, transport->incoming_used);
            *out = message;
        } else mhg_buf_clear(out);
        mhg_buf_clear(&transport->incoming);
        transport->incoming_used = 0;
        *complete = 1;
        return 0;
    }
failed:
    mhg_buf_clear(&transport->incoming);
    transport->incoming_used = 0;
    transport->incoming_frame_offset = 0;
    transport->failed = true;
    return -1;
}

int mhg_transport_receive(struct mhg_transport *transport, struct mhg_buf *out,
                          uint64_t deadline, struct mhg_error *error)
{
    if (!transport || transport->failed || !out)
        return mhg_errorf(error, EINVAL, "invalid WebSocket receive state");
    /* Preserve the original blocking API contract: each successful receive
     * replaces the caller's previous message.  The nonblocking pump keeps a
     * stricter empty-output contract so ownership cannot be lost on AGAIN. */
    mhg_buf_clear(out);
    for (;;) {
        int complete = 0;
        if (mhg_remaining_ms(deadline, MHG_TRANSPORT_POLL_MS,
                              transport->stop, error) < 0) goto failed;
        if (mhg_transport_pump(transport, out, &complete, error)) return -1;
        if (complete) return 0;
        if (wait_socket(transport, POLLIN, deadline, error) != 0) goto failed;
    }
failed:
    mhg_buf_clear(&transport->incoming);
    transport->incoming_used = 0;
    transport->incoming_frame_offset = 0;
    transport->failed = true;
    return -1;
}

void mhg_transport_close(struct mhg_transport *transport)
{
    if (!transport) return;
    mhg_buf_clear(&transport->incoming);
    if (transport->added)
        (void)curl_multi_remove_handle(transport->multi, transport->easy);
    if (transport->easy) curl_easy_cleanup(transport->easy);
    if (transport->multi) (void)curl_multi_cleanup(transport->multi);
    free(transport);
}
