#ifndef MHGEEK_COMMON_H
#define MHGEEK_COMMON_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

struct mhg_buf {
    unsigned char *data;
    size_t len;
};

struct mhg_error {
    int code;
    char message[192];
};

int mhg_errorf(struct mhg_error *error, int code, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
/* Buffers must be zero-initialized. Allocation replaces and clears old data. */
int mhg_buf_alloc(struct mhg_buf *buffer, size_t length, struct mhg_error *error);
void mhg_buf_clear(struct mhg_buf *buffer);
int mhg_deadline_after(unsigned int timeout_ms, uint64_t *deadline,
                       struct mhg_error *error);
/* Returns remaining milliseconds, capped at cap_ms, or -1 on stop/timeout/error. */
int mhg_remaining_ms(uint64_t deadline, unsigned int cap_ms,
                     const volatile sig_atomic_t *stop, struct mhg_error *error);

/* True only when url is an absolute http(s) URL whose authority is exactly
 * `host` (optional valid port), with no userinfo, brackets or fragment. */
int mhg_url_host_matches(const char *url, const char *host);

#endif
