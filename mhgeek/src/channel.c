#include "channel.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>
#include <zlib.h>

static uint32_t read_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void write_le32(unsigned char *p, uint32_t n)
{
    for (unsigned int i = 0; i < 4; ++i) p[i] = (unsigned char)(n >> (8 * i));
}

void mhg_cipher_init(struct mhg_cipher *cipher, const unsigned char material[24])
{
    memcpy(cipher->key, material, 16);
    memcpy(cipher->salt, material + 16, 8);
    cipher->counter = 0;
}

void mhg_cipher_clear(struct mhg_cipher *cipher)
{
    OPENSSL_cleanse(cipher, sizeof(*cipher));
}

int mhg_encrypt(struct mhg_cipher *cipher, const void *plain, size_t length,
                struct mhg_buf *out, struct mhg_error *error)
{
    struct mhg_buf result = {0};
    unsigned char nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint32_t counter;
    int size = 0, tail = 0, rc = -1;
    if (!cipher || !out || (!plain && length) || length > INT_MAX - 20)
        return mhg_errorf(error, EINVAL, "invalid encryption input");
    if (cipher->counter == UINT32_MAX)
        return mhg_errorf(error, EOVERFLOW, "encryption counter exhausted");
    counter = cipher->counter + 1;
    memcpy(nonce, cipher->salt, 8);
    write_le32(nonce + 8, counter);
    if (mhg_buf_alloc(&result, length + 20, error)) goto done;
    write_le32(result.data, counter);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, cipher->key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, result.data + 4, &size, plain, (int)length) != 1 ||
        EVP_EncryptFinal_ex(ctx, result.data + 4 + size, &tail) != 1 ||
        (size_t)(size + tail) != length ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                             result.data + 4 + length) != 1) {
        mhg_errorf(error, EIO, "AES-GCM encryption failed");
        goto done;
    }
    cipher->counter = counter;
    mhg_buf_clear(out);
    *out = result;
    result = (struct mhg_buf){0};
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    mhg_buf_clear(&result);
    return rc;
}

int mhg_decrypt(struct mhg_cipher *cipher, const void *wire, size_t length,
                struct mhg_buf *out, struct mhg_error *error)
{
    const unsigned char *bytes = wire;
    struct mhg_buf result = {0};
    unsigned char nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint32_t counter;
    size_t plain_length;
    int size = 0, tail = 0, rc = -1;
    if (!cipher || !out || !wire || length < 20 || length > INT_MAX)
        return mhg_errorf(error, EINVAL, "invalid encrypted message length");
    counter = read_le32(bytes);
    if (!counter || counter <= cipher->counter)
        return mhg_errorf(error, EPROTO, "stale encrypted message counter");
    plain_length = length - 20;
    memcpy(nonce, cipher->salt, 8);
    memcpy(nonce + 8, bytes, 4);
    if (mhg_buf_alloc(&result, plain_length ? plain_length : 1, error)) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, cipher->key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, result.data, &size, bytes + 4, (int)plain_length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             (void *)(bytes + length - 16)) != 1 ||
        EVP_DecryptFinal_ex(ctx, result.data + size, &tail) != 1 ||
        (size_t)(size + tail) != plain_length) {
        mhg_errorf(error, EPROTO, "AES-GCM authentication failed");
        goto done;
    }
    cipher->counter = counter;
    result.len = plain_length;
    mhg_buf_clear(out);
    *out = result;
    result = (struct mhg_buf){0};
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    mhg_buf_clear(&result);
    return rc;
}

int mhg_pack_json(const char *json, size_t length, size_t budget,
                  struct mhg_buf *out, struct mhg_error *error)
{
    struct mhg_buf result = {0};
    z_stream stream = {0};
    uLong bound;
    int rc;
    if (!json || !length || !out || length > budget || length > UINT_MAX ||
        budget < 5 || budget > UINT_MAX || memchr(json, 0, length))
        return mhg_errorf(error, EINVAL, "invalid JSON compression input");
    rc = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                      -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) return mhg_errorf(error, EIO, "raw DEFLATE initialization failed");
    bound = deflateBound(&stream, (uLong)length);
    if (bound > budget - 4) bound = (uLong)budget - 4;
    if (mhg_buf_alloc(&result, (size_t)bound + 4, error)) {
        deflateEnd(&stream);
        return -1;
    }
    write_le32(result.data, (uint32_t)length);
    stream.next_in = (Bytef *)json;
    stream.avail_in = (uInt)length;
    stream.next_out = result.data + 4;
    stream.avail_out = (uInt)bound;
    rc = deflate(&stream, Z_FINISH);
    if (rc != Z_STREAM_END || stream.avail_in) {
        deflateEnd(&stream);
        mhg_buf_clear(&result);
        return mhg_errorf(error, EMSGSIZE, "compressed JSON exceeds message budget");
    }
    result.len = (size_t)stream.total_out + 4;
    deflateEnd(&stream);
    mhg_buf_clear(out);
    *out = result;
    return 0;
}

int mhg_unpack_json(const void *wire, size_t length, size_t budget,
                    struct mhg_buf *out, struct mhg_error *error)
{
    const unsigned char *bytes = wire;
    struct mhg_buf result = {0};
    z_stream stream = {0};
    uint32_t declared;
    int rc;
    if (!wire || !out || length < 5 || length > budget || length > UINT_MAX)
        return mhg_errorf(error, EPROTO, "invalid compressed JSON length");
    declared = read_le32(bytes);
    if (!declared || declared > budget || declared >= UINT_MAX)
        return mhg_errorf(error, EMSGSIZE, "JSON size exceeds message budget");
    if (mhg_buf_alloc(&result, (size_t)declared + 1, error)) return -1;
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        mhg_buf_clear(&result);
        return mhg_errorf(error, EIO, "raw INFLATE initialization failed");
    }
    stream.next_in = (Bytef *)(bytes + 4);
    stream.avail_in = (uInt)(length - 4);
    stream.next_out = result.data;
    stream.avail_out = declared + 1;
    rc = inflate(&stream, Z_FINISH);
    if (rc != Z_STREAM_END || stream.avail_in || stream.total_out != declared ||
        memchr(result.data, 0, declared)) {
        inflateEnd(&stream);
        mhg_buf_clear(&result);
        return mhg_errorf(error, EPROTO, "invalid raw DEFLATE JSON payload");
    }
    inflateEnd(&stream);
    result.data[declared] = 0;
    mhg_buf_clear(out);
    *out = result;
    return 0;
}
