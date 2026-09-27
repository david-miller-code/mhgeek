#ifndef MHGEEK_PASSPORT_WIRE_H
#define MHGEEK_PASSPORT_WIRE_H

#include <stddef.h>

#include <openssl/evp.h>

#include "cloud_wire_types.h"

enum mhg_passport_step {
    MHG_PASSPORT_POLICY = 1,
    MHG_PASSPORT_PREFERENCE = 2,
    MHG_PASSPORT_SEND_TICKET = 3,
    MHG_PASSPORT_PHONE_INFO = 4,
    MHG_PASSPORT_TICKET_AUTH = 5,
};

enum mhg_passport_value_source {
    MHG_PASSPORT_CONSTANT = 1,
    MHG_PASSPORT_SESSION = 2,
    MHG_PASSPORT_SECRET = 3,
    MHG_PASSPORT_EUI_ENCRYPTED = 4,
    MHG_PASSPORT_GENERATED = 5,
};

enum mhg_passport_provider_class {
    MHG_PASSPORT_PROVIDER_NONE = 0,
    MHG_PASSPORT_SMS_SEND_LIMIT_TOMORROW = 1,
    MHG_PASSPORT_SMS_CODE_INVALID_OR_EXPIRED = 2,
    MHG_PASSPORT_ADDITIONAL_VERIFICATION_REQUIRED = 3,
    MHG_PASSPORT_PROVIDER_OTHER = 4,
};

struct mhg_passport_field {
    const char *name;
    const char *constant_value;
    enum mhg_passport_value_source source;
};

struct mhg_passport_request_contract {
    enum mhg_passport_step step;
    const char *method;
    const char *path;
    const struct mhg_passport_field *query;
    size_t query_count;
    const struct mhg_passport_field *form;
    size_t form_count;
    const struct mhg_passport_field *headers;
    size_t header_count;
    const struct mhg_passport_field *cookies;
    size_t cookie_count;
    int uses_eui;
    int uses_challenge_referer;
    const char *eui_header_name;
    const char *const *observed_response_cookies;
    size_t observed_response_cookie_count;
};

struct mhg_passport_response {
    char policy_name[32];
    unsigned int code_length;
    unsigned int retry_after_seconds;
    int provider_code;
    enum mhg_passport_provider_class provider_class;
    struct mhg_secret_buf user_id;
    struct mhg_secret_buf pass_token;
    struct mhg_secret_buf location;
};

#define MHG_PASSPORT_RESPONSE_INIT \
    {{0}, 0u, 0u, 0, MHG_PASSPORT_PROVIDER_NONE, MHG_SECRET_BUF_INIT, \
     MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT}

const char *mhg_passport_base_url(void);
/* Single client identity for the whole Xiaomi service session. The passport
 * endpoints and service token-login must present the same User-Agent: on
 * 2026-09-21 the provider answered token-login with code 70016 for the
 * libcurl default agent while this one succeeded with the identical cookie
 * pair and triple. */
const char *mhg_passport_client_user_agent(void);
const struct mhg_passport_request_contract *mhg_passport_contract(
    enum mhg_passport_step step);
enum mhg_cloud_error mhg_passport_parse_response(
    enum mhg_passport_step step, struct mhg_bytes_view body,
    struct mhg_passport_response *response);
/* Applies the trusted ticket-auth redirect cookies transactionally. Each
 * non-empty cookie overrides its JSON counterpart. JSON userId and trusted
 * location are required; JSON passToken may be absent only when a non-empty
 * trusted CookieJar passToken completes the pair. The resulting pair is
 * revalidated. */
enum mhg_cloud_error mhg_passport_apply_ticket_redirect(
    struct mhg_passport_response *response, const char *user_id_cookie,
    const char *pass_token_cookie);
void mhg_passport_response_clear(struct mhg_passport_response *response);

/* Outputs must start at their INIT value. Writers clear reusable outputs at
 * entry and leave them empty on every failure. AES output is PKCS#7 padded
 * AES-128-CBC with the protocol fixed IV. */
enum mhg_cloud_error mhg_passport_eui_aes_encrypt(
    const unsigned char key[16], const unsigned char *plaintext,
    size_t plaintext_len, struct mhg_secret_buf *ciphertext);

/* The EUI header is base64(RSA-PKCS1-v1_5(base64(aes_key))) + "." +
 * base64(field_name). The public key is injectable for deterministic offline
 * validation; the product key loader exposes the tracked protocol material. */
enum mhg_cloud_error mhg_passport_eui_header(
    EVP_PKEY *public_key, const unsigned char aes_key[16],
    const char *field_name, struct mhg_secret_buf *header_value);
EVP_PKEY *mhg_passport_eui_protocol_public_key(void);
int mhg_passport_ticket_is_valid(const char *ticket, size_t expected_length);
const char *mhg_passport_provider_class_name(
    enum mhg_passport_provider_class provider_class);
enum mhg_passport_provider_class mhg_passport_provider_classify(int code);

#endif
