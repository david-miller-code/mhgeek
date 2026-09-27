#include "cloud_wire_types.h"

#include <openssl/crypto.h>

#include <string.h>

const char *mhg_cloud_error_name(enum mhg_cloud_error error)
{
    switch (error) {
    case MHG_CLOUD_OK: return "none";
    case MHG_CLOUD_INPUT: return "input";
    case MHG_CLOUD_HTTP: return "http";
    case MHG_CLOUD_AUTH_REJECTED: return "auth_rejected";
    case MHG_CLOUD_SID_MISMATCH: return "sid_mismatch";
    case MHG_CLOUD_MALFORMED: return "malformed";
    case MHG_CLOUD_SERVICE: return "service";
    case MHG_CLOUD_CRYPTO: return "crypto";
    case MHG_CLOUD_DECRYPT: return "decrypt";
    case MHG_CLOUD_INTERNAL: return "internal";
    case MHG_CLOUD_NETWORK: return "network";
    case MHG_CLOUD_NOT_DISPATCHED: return "not_dispatched";
    case MHG_CLOUD_TARGET_MISMATCH: return "target_mismatch";
    }
    return NULL;
}

const char *mhg_xiaomi_sid_name(enum mhg_xiaomi_sid sid)
{
    if (sid == MHG_XIAOMI_SID_XIAOMIIO) return "xiaomiio";
    if (sid == MHG_XIAOMI_SID_MIJIA) return "mijia";
    return NULL;
}

void mhg_secure_clear(void *data, size_t length)
{
    if (data && length != 0u) OPENSSL_cleanse(data, length);
}

void mhg_secret_buf_clear(struct mhg_secret_buf *buffer)
{
    if (!buffer) return;
    OPENSSL_clear_free(buffer->data, buffer->len + 1u);
    buffer->data = NULL;
    buffer->len = 0u;
}

int mhg_secret_buf_set(struct mhg_secret_buf *buffer,
                       const void *data, size_t length)
{
    unsigned char *copy;

    if (!buffer) return -1;
    if (!data || length == 0u) {
        mhg_secret_buf_clear(buffer);
        return -1;
    }
    copy = OPENSSL_malloc(length + 1u);
    if (!copy) {
        mhg_secret_buf_clear(buffer);
        return -1;
    }
    memcpy(copy, data, length);
    copy[length] = '\0';
    mhg_secret_buf_clear(buffer);
    buffer->data = copy;
    buffer->len = length;
    return 0;
}
