#define _POSIX_C_SOURCE 200809L
#include "common.h"

#include <string.h>

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

int mhg_errorf(struct mhg_error *error, int code, const char *format, ...)
{
    if (error) {
        va_list args;
        error->code = code;
        va_start(args, format);
        vsnprintf(error->message, sizeof(error->message), format, args);
        va_end(args);
    }
    errno = code;
    return -1;
}

void mhg_buf_clear(struct mhg_buf *buffer)
{
    if (!buffer) return;
    OPENSSL_clear_free(buffer->data, buffer->len);
    buffer->data = NULL;
    buffer->len = 0;
}

int mhg_buf_alloc(struct mhg_buf *buffer, size_t length, struct mhg_error *error)
{
    unsigned char *data;
    if (!buffer || !length) return mhg_errorf(error, EINVAL, "invalid buffer length");
    data = OPENSSL_malloc(length);
    if (!data) return mhg_errorf(error, ENOMEM, "buffer allocation failed");
    mhg_buf_clear(buffer);
    buffer->data = data;
    buffer->len = length;
    return 0;
}

static int monotonic_ms(uint64_t *value, struct mhg_error *error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return mhg_errorf(error, errno, "monotonic clock failed");
    *value = (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
    return 0;
}

int mhg_deadline_after(unsigned int timeout_ms, uint64_t *deadline,
                       struct mhg_error *error)
{
    uint64_t now;
    if (!deadline || !timeout_ms) return mhg_errorf(error, EINVAL, "invalid timeout");
    if (monotonic_ms(&now, error) != 0) return -1;
    if (UINT64_MAX - now < timeout_ms)
        return mhg_errorf(error, EOVERFLOW, "deadline overflow");
    *deadline = now + timeout_ms;
    return 0;
}

int mhg_remaining_ms(uint64_t deadline, unsigned int cap_ms,
                     const volatile sig_atomic_t *stop, struct mhg_error *error)
{
    uint64_t now, left;
    if (stop && *stop) return mhg_errorf(error, ECANCELED, "operation stopped");
    if (!cap_ms || cap_ms > INT_MAX) return mhg_errorf(error, EINVAL, "invalid wait cap");
    if (monotonic_ms(&now, error) != 0) return -1;
    if (now >= deadline) return mhg_errorf(error, ETIMEDOUT, "operation deadline exceeded");
    left = deadline - now;
    return (int)(left < cap_ms ? left : cap_ms);
}

static const char *scheme_body(const char *url)
{
    static const char https_scheme[] = "https://";
    static const char http_scheme[] = "http://";

    if (!url) return NULL;
    if (strncmp(url, https_scheme, sizeof(https_scheme) - 1u) == 0)
        return url + sizeof(https_scheme) - 1u;
    if (strncmp(url, http_scheme, sizeof(http_scheme) - 1u) == 0)
        return url + sizeof(http_scheme) - 1u;
    return NULL;
}

int mhg_url_host_matches(const char *url, const char *host)
{
    const char *authority;
    const char *authority_end;
    const char *colon;
    size_t host_length;
    size_t port_length;
    unsigned port = 0u;
    size_t index;

    if (!host || !host[0] || strchr(url ? url : "", '#')) return 0;
    authority = scheme_body(url);
    if (!authority) return 0;
    authority_end = authority + strcspn(authority, "/?#");
    /* An empty, userinfo-bearing or bracketed authority is not a plain LAN
     * address, so it can never confirm the configured host. */
    if (authority_end == authority ||
        memchr(authority, '@', (size_t)(authority_end - authority)) ||
        memchr(authority, '[', (size_t)(authority_end - authority)) ||
        memchr(authority, ']', (size_t)(authority_end - authority)))
        return 0;
    colon = memchr(authority, ':', (size_t)(authority_end - authority));
    host_length = colon ? (size_t)(colon - authority) :
                          (size_t)(authority_end - authority);
    if (host_length != strlen(host) ||
        memcmp(authority, host, host_length) != 0)
        return 0;
    if (!colon) return 1;
    port_length = (size_t)(authority_end - colon) - 1u;
    if (port_length == 0u || port_length > 5u) return 0;
    for (index = 0u; index < port_length; ++index) {
        unsigned char byte = (unsigned char)colon[index + 1u];
        if (byte < '0' || byte > '9') return 0;
        port = port * 10u + (unsigned)(byte - '0');
    }
    return port >= 1u && port <= 65535u;
}
