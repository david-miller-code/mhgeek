#ifndef MHGEEK_CLOUD_WIRE_TYPES_H
#define MHGEEK_CLOUD_WIRE_TYPES_H

#include <stdbool.h>
#include <stddef.h>

/* Internal result categories, not platform ABI or Xiaomi provider codes.
 * Preserve raw Xiaomi response codes separately in provider_code fields. */
enum mhg_cloud_error {
    MHG_CLOUD_OK = 0,
    MHG_CLOUD_INPUT,
    MHG_CLOUD_HTTP,
    MHG_CLOUD_AUTH_REJECTED,
    MHG_CLOUD_SID_MISMATCH,
    MHG_CLOUD_MALFORMED,
    MHG_CLOUD_SERVICE,
    MHG_CLOUD_CRYPTO,
    MHG_CLOUD_DECRYPT,
    MHG_CLOUD_INTERNAL,
    MHG_CLOUD_NETWORK,
    /* The owner failed locally before handing the request to transport. */
    MHG_CLOUD_NOT_DISPATCHED,
    /* The cloud answered for a different LAN host than the configured target. */
    MHG_CLOUD_TARGET_MISMATCH,
};

enum mhg_xiaomi_sid {
    MHG_XIAOMI_SID_XIAOMIIO = 1,
    MHG_XIAOMI_SID_MIJIA = 2,
};

struct mhg_secret_buf {
    /* Invariant: data owns len + 1 bytes and data[len] is a zero sentinel.
     * Code must use mhg_secret_buf_set rather than attach a len-byte buffer. */
    unsigned char *data;
    size_t len;
};

struct mhg_bytes_view {
    /* External response parsers require the exact transport/decrypt length.
     * data may be NULL only when len is zero. */
    const unsigned char *data;
    size_t len;
};

#define MHG_BYTES_VIEW(bytes, length) \
    ((struct mhg_bytes_view){(const unsigned char *)(bytes), (length)})
/* For compile-time string literals in offline tests and fixed protocol data. */
#define MHG_BYTES_LITERAL(text) MHG_BYTES_VIEW((text), sizeof(text) - 1u)
#define MHG_BYTES_EMPTY MHG_BYTES_VIEW(NULL, 0u)

#define MHG_SECRET_BUF_INIT {NULL, 0u}

/* Every output containing mhg_secret_buf must be initialized with its INIT
 * macro before first use. Public writers clear a reusable output on entry;
 * every failure therefore leaves it empty. */

const char *mhg_cloud_error_name(enum mhg_cloud_error error);
const char *mhg_xiaomi_sid_name(enum mhg_xiaomi_sid sid);
int mhg_secret_buf_set(struct mhg_secret_buf *buffer,
                       const void *data, size_t length);
void mhg_secret_buf_clear(struct mhg_secret_buf *buffer);
void mhg_secure_clear(void *data, size_t length);

#endif
