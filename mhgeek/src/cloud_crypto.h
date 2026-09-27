#ifndef MHGEEK_CLOUD_CRYPTO_H
#define MHGEEK_CLOUD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "cloud_wire_types.h"

struct mhg_cloud_form {
    struct mhg_secret_buf nonce_b64;
    struct mhg_secret_buf data_b64;
    struct mhg_secret_buf rc4_hash_b64;
    struct mhg_secret_buf signature_b64;
};

#define MHG_CLOUD_FORM_INIT \
    {MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT}

struct mhg_cloud_envelope {
    int provider_code;
    struct mhg_secret_buf result_json;
};

#define MHG_CLOUD_ENVELOPE_INIT {0, MHG_SECRET_BUF_INIT}

/* Struct and buffer outputs must start at the matching INIT value. Public
 * writers clear reusable outputs on entry and leave them empty on failure. */

void mhg_cloud_nonce(const unsigned char random_prefix[8], uint32_t minute,
                     unsigned char nonce[12]);
enum mhg_cloud_error mhg_cloud_signed_nonce(
    const unsigned char *ssecurity, size_t ssecurity_len,
    const unsigned char nonce[12], unsigned char output[32]);
enum mhg_cloud_error mhg_cloud_signature(
    const char *canonical_path, const char *data_value,
    const char *rc4_hash_value, const unsigned char signed_nonce[32],
    struct mhg_secret_buf *signature_b64);
enum mhg_cloud_error mhg_cloud_build_form(
    const char *canonical_path, const char *data_json,
    const unsigned char *ssecurity, size_t ssecurity_len,
    const unsigned char nonce[12], struct mhg_cloud_form *form);
enum mhg_cloud_error mhg_cloud_form_encode(
    const struct mhg_cloud_form *form, struct mhg_secret_buf *encoded);
void mhg_cloud_form_clear(struct mhg_cloud_form *form);

enum mhg_cloud_error mhg_cloud_classify_http(int status);
enum mhg_cloud_error mhg_cloud_classify_http_for_sid(
    enum mhg_xiaomi_sid expected, enum mhg_xiaomi_sid actual, int status);
/* On MHG_CLOUD_SERVICE the envelope keeps the rejected provider code and no
 * result; every other failure leaves both fields empty. */
enum mhg_cloud_error mhg_cloud_decrypt_envelope(
    struct mhg_bytes_view response_b64,
    const unsigned char signed_nonce[32],
    struct mhg_cloud_envelope *envelope);
void mhg_cloud_envelope_clear(struct mhg_cloud_envelope *envelope);

#endif
