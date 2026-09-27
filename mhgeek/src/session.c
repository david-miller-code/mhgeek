#include "session.h"
#include "channel.h"
#include "jpake.h"
#include "json_strict.h"

#include <errno.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

struct mhg_session {
    struct mhg_transport *transport;
    struct mhg_cipher tx, rx;
    size_t budget;
    uint64_t next_id;
    int valid;
};

static void invalidate(struct mhg_session *session)
{
    session->valid = 0;
    mhg_cipher_clear(&session->tx);
    mhg_cipher_clear(&session->rx);
}

void mhg_session_free(struct mhg_session *session)
{
    if (!session) return;
    invalidate(session);
    OPENSSL_clear_free(session, sizeof(*session));
}

static int send_message(struct mhg_transport *transport, unsigned char type,
                         const void *data, size_t length, uint64_t deadline,
                         struct mhg_error *error)
{
    struct mhg_buf frame = {0};
    int rc;
    if (length == SIZE_MAX) return mhg_errorf(error, EOVERFLOW, "message overflow");
    if (mhg_buf_alloc(&frame, length + 1, error)) return -1;
    frame.data[0] = type;
    if (length) memcpy(frame.data + 1, data, length);
    rc = mhg_transport_send(transport, frame.data, frame.len, deadline, error);
    mhg_buf_clear(&frame);
    return rc;
}

static int receive_message(struct mhg_transport *transport, unsigned char type,
                            struct mhg_buf *frame, uint64_t deadline,
                            struct mhg_error *error)
{
    if (mhg_transport_receive(transport, frame, deadline, error)) return -1;
    if (!frame->len) return mhg_errorf(error, EPROTO, "empty protocol message");
    if (frame->data[0] == 0x04)
        return mhg_errorf(error, EACCES, "gateway rejected the exchange");
    if (frame->data[0] != type)
        return mhg_errorf(error, EPROTO, "unexpected protocol message type 0x%02x",
                           frame->data[0]);
    return 0;
}

cJSON *mhg_session_parse_json(const unsigned char *data, size_t length,
                              uint64_t deadline, struct mhg_error *error)
{
    struct mhg_buf text = {0};
    cJSON *json;
    if (!data || !length || length == SIZE_MAX || memchr(data, 0, length)) {
        mhg_errorf(error, EPROTO, "invalid JSON text");
        return NULL;
    }
    /* cJSON exposes C strings without decoded lengths. A decoded NUL would
     * hide suffixes in protocol names, version strings and object keys. Skip
     * escaped backslashes so the literal text "\\u0000" remains representable. */
    for (size_t i = 0; i < length; ++i) {
        if ((i & 4095u) == 0 && mhg_remaining_ms(deadline, 1, NULL, error) < 0)
            return NULL;
        if (data[i] != '\\') continue;
        if (length - i >= 6 && !memcmp(data + i, "\\u0000", 6)) {
            mhg_errorf(error, EPROTO, "JSON contains an unrepresentable NUL escape");
            return NULL;
        }
        if (i + 1 < length) ++i;
    }
    if (mhg_buf_alloc(&text, length + 1, error)) return NULL;
    memcpy(text.data, data, length);
    text.data[length] = 0;
    errno = 0;
    json = subsys_json_parse_strict_deadline((const char *)text.data, deadline);
    mhg_buf_clear(&text);
    if (!json) mhg_errorf(error, errno ? errno : EPROTO, "strict JSON parse failed");
    return json;
}

struct mhg_session *mhg_session_open(struct mhg_transport *transport,
                                      const char *passcode, size_t budget,
                                      uint64_t deadline, const char **phase,
                                      struct mhg_error *error)
{
    static const char protocols[] = "[\"passcode\"]";
    struct mhg_buf frame = {0}, payload = {0}, cipher_text = {0}, plain = {0};
    struct mhg_jpake *party = NULL;
    struct mhg_session *session = NULL;
    unsigned char secret[32] = {0}, own_material[24] = {0};
    cJSON *json = NULL;
    const cJSON *field;
    int success = 0;
    if (phase) *phase = "protocol";
    if (!transport || !passcode || !phase || budget < 22) {
        mhg_errorf(error, EINVAL, "invalid session arguments");
        return NULL;
    }
    session = OPENSSL_zalloc(sizeof(*session));
    if (!session) {
        mhg_errorf(error, ENOMEM, "session allocation failed");
        return NULL;
    }
    session->transport = transport;
    session->budget = budget;
    session->next_id = 1;
    *phase = "protocol";
    if (send_message(transport, 0x01, protocols, sizeof(protocols) - 1, deadline, error) ||
        receive_message(transport, 0x02, &frame, deadline, error)) goto done;
    json = mhg_session_parse_json(frame.data + 1, frame.len - 1, deadline, error);
    if (!json) goto done;
    field = cJSON_GetObjectItemCaseSensitive(json, "protocol");
    if (!cJSON_IsObject(json) || !cJSON_IsString(field) ||
        strcmp(field->valuestring, "passcode")) {
        mhg_errorf(error, EPROTO, "gateway did not select passcode authentication");
        goto done;
    }
    cJSON_Delete(json);
    json = NULL;
    *phase = "jpake-round-one";
    party = mhg_jpake_new(passcode, error);
    if (!party || mhg_jpake_round_one(party, &payload, error) ||
        send_message(transport, 0x20, payload.data, payload.len, deadline, error) ||
        receive_message(transport, 0x20, &frame, deadline, error) ||
        mhg_jpake_read_round_one(party, frame.data + 1, frame.len - 1, error)) goto done;
    *phase = "jpake-round-two";
    if (mhg_jpake_round_two(party, &payload, error) ||
        send_message(transport, 0x21, payload.data, payload.len, deadline, error) ||
        receive_message(transport, 0x21, &frame, deadline, error) ||
        mhg_jpake_read_round_two(party, frame.data + 1, frame.len - 1, error) ||
        mhg_jpake_secret(party, secret, error)) goto done;
    *phase = "key-exchange";
    mhg_cipher_init(&session->tx, secret);
    mhg_cipher_init(&session->rx, secret);
    OPENSSL_cleanse(secret, sizeof(secret));
    if (RAND_bytes(own_material, sizeof(own_material)) != 1) {
        mhg_errorf(error, EIO, "session randomness failed");
        goto done;
    }
    if (mhg_encrypt(&session->tx, own_material, sizeof(own_material), &cipher_text, error) ||
        send_message(transport, 0x03, cipher_text.data, cipher_text.len, deadline, error) ||
        receive_message(transport, 0x03, &frame, deadline, error) ||
        mhg_decrypt(&session->rx, frame.data + 1, frame.len - 1, &plain, error)) goto done;
    if (plain.len != 24) {
        mhg_errorf(error, EPROTO, "gateway session key has invalid length");
        goto done;
    }
    mhg_cipher_init(&session->tx, own_material);
    mhg_cipher_init(&session->rx, plain.data);
    if (mhg_remaining_ms(deadline, 1, NULL, error) < 0) goto done;
    session->valid = 1;
    success = 1;
    *phase = "authenticated";
done:
    cJSON_Delete(json);
    mhg_jpake_free(party);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(own_material, sizeof(own_material));
    mhg_buf_clear(&frame);
    mhg_buf_clear(&payload);
    mhg_buf_clear(&cipher_text);
    mhg_buf_clear(&plain);
    if (!success) {
        mhg_session_free(session);
        return NULL;
    }
    return session;
}

static int is_integer(const cJSON *value)
{
    double number;
    if (!cJSON_IsNumber(value)) return 0;
    number = value->valuedouble;
    /* Finite binary64 values at or above 2^52 already have no fraction. */
    return isfinite(number) &&
        (number >= 0x1p52 || number <= -0x1p52 || number == (double)(int64_t)number);
}

static int validate_notification(const cJSON *json, struct mhg_error *error)
{
    const cJSON *version, *id, *result, *rpc_error, *method, *params;
    version = cJSON_GetObjectItemCaseSensitive(json, "jsonrpc");
    id = cJSON_GetObjectItemCaseSensitive(json, "id");
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    rpc_error = cJSON_GetObjectItemCaseSensitive(json, "error");
    method = cJSON_GetObjectItemCaseSensitive(json, "method");
    params = cJSON_GetObjectItemCaseSensitive(json, "params");
    if (!cJSON_IsObject(json) || !cJSON_IsString(version) ||
        strcmp(version->valuestring, "2.0"))
        return mhg_errorf(error, EPROTO, "invalid JSON-RPC version");
    if (id || result || rpc_error || !cJSON_IsString(method) || !method->valuestring[0] ||
        (params && !cJSON_IsObject(params) && !cJSON_IsArray(params)))
        return mhg_errorf(error, EPROTO, "invalid JSON-RPC notification");
    return 0;
}

/* Returns 1 for a valid notification, 0 for a response, or -1 for invalid data. */
static int validate_envelope(const cJSON *json, uint64_t id,
                              struct mhg_error *error)
{
    const cJSON *field, *result, *rpc_error, *method, *params;
    field = cJSON_GetObjectItemCaseSensitive(json, "jsonrpc");
    if (!cJSON_IsObject(json) || !cJSON_IsString(field) || strcmp(field->valuestring, "2.0"))
        return mhg_errorf(error, EPROTO, "invalid JSON-RPC version");
    field = cJSON_GetObjectItemCaseSensitive(json, "id");
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    rpc_error = cJSON_GetObjectItemCaseSensitive(json, "error");
    method = cJSON_GetObjectItemCaseSensitive(json, "method");
    params = cJSON_GetObjectItemCaseSensitive(json, "params");
    if (!field) {
        return validate_notification(json, error) ? -1 : 1;
    }
    if (!cJSON_IsNumber(field) || field->valuedouble != (double)id)
        return mhg_errorf(error, EPROTO, "JSON-RPC response id mismatch");
    if (method || params || ((!result) == (!rpc_error)))
        return mhg_errorf(error, EPROTO, "invalid JSON-RPC result/error envelope");
    if (rpc_error) {
        if (!cJSON_IsObject(rpc_error) ||
            !is_integer(cJSON_GetObjectItemCaseSensitive(rpc_error, "code")) ||
            !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(rpc_error, "message")))
            return mhg_errorf(error, EPROTO, "invalid JSON-RPC error object");
    }
    return 0;
}

int mhg_session_service_idle(struct mhg_session *session, uint64_t deadline,
                             struct mhg_error *error)
{
    struct mhg_buf frame = {0}, plain = {0}, payload = {0};
    cJSON *json = NULL;
    int rc = -1;
    if (!session)
        return mhg_errorf(error, EINVAL, "invalid idle session arguments");
    if (!session->valid)
        return mhg_errorf(error, ENOTCONN, "session is invalid; authenticate again");
    for (;;) {
        int complete = 0;
        if (mhg_transport_pump(session->transport, &frame, &complete, error)) goto done;
        if (!complete) { rc = 0; break; }
        if (!frame.len) {
            mhg_errorf(error, EPROTO, "empty protocol message");
            goto done;
        }
        if (frame.data[0] == 0x04) {
            mhg_errorf(error, EACCES, "gateway rejected the exchange");
            goto done;
        }
        if (frame.data[0] != 0x05) {
            mhg_errorf(error, EPROTO, "unexpected protocol message type 0x%02x",
                       frame.data[0]);
            goto done;
        }
        if (mhg_decrypt(&session->rx, frame.data + 1, frame.len - 1, &plain, error) ||
            mhg_unpack_json(plain.data, plain.len, session->budget, &payload, error))
            goto done;
        json = mhg_session_parse_json(payload.data, payload.len - 1, deadline, error);
        if (!json || validate_notification(json, error)) goto done;
        cJSON_Delete(json); json = NULL;
        mhg_buf_clear(&frame);
        mhg_buf_clear(&plain);
        mhg_buf_clear(&payload);
    }
done:
    if (rc) invalidate(session);
    cJSON_Delete(json);
    mhg_buf_clear(&frame);
    mhg_buf_clear(&plain);
    mhg_buf_clear(&payload);
    return rc;
}

/* Decrypts one complete data frame into strict JSON. A rejected exchange,
 * another frame type, a crypto failure or malformed text is fatal for the
 * session, so every caller invalidates on NULL. */
static cJSON *mhg_session_frame_json(struct mhg_session *session,
                                     const struct mhg_buf *frame,
                                     uint64_t deadline,
                                     struct mhg_error *error)
{
    struct mhg_buf plain = {0}, payload = {0};
    cJSON *json = NULL;

    if (!frame->len)
        mhg_errorf(error, EPROTO, "empty protocol message");
    else if (frame->data[0] == 0x04)
        mhg_errorf(error, EACCES, "gateway rejected the exchange");
    else if (frame->data[0] != 0x05)
        mhg_errorf(error, EPROTO, "unexpected protocol message type 0x%02x",
                   frame->data[0]);
    else if (!mhg_decrypt(&session->rx, frame->data + 1, frame->len - 1,
                          &plain, error) &&
             !mhg_unpack_json(plain.data, plain.len, session->budget,
                              &payload, error))
        json = mhg_session_parse_json(payload.data, payload.len - 1, deadline,
                                      error);
    mhg_buf_clear(&plain);
    mhg_buf_clear(&payload);
    return json;
}

int mhg_session_send(struct mhg_session *session, const char *method,
                     const cJSON *params, uint64_t *id_out, uint64_t deadline,
                     struct mhg_error *error)
{
    struct mhg_buf payload = {0}, cipher_text = {0};
    cJSON *request = NULL;
    char *text = NULL;
    uint64_t id;
    int rc = -1;

    if (!session || !method || !id_out ||
        (params && !cJSON_IsObject(params) && !cJSON_IsArray(params)))
        return mhg_errorf(error, EINVAL, "invalid RPC arguments");
    if (!session->valid)
        return mhg_errorf(error, ENOTCONN,
                          "session is invalid; authenticate again");
    if (mhg_remaining_ms(deadline, 1, NULL, error) < 0) {
        invalidate(session);
        return -1;
    }
    /* cJSON stores numbers as double; never reuse or round a request id. */
    if (session->next_id > UINT64_C(9007199254740991)) {
        invalidate(session);
        return mhg_errorf(error, EOVERFLOW, "JSON-RPC request ids exhausted");
    }
    id = session->next_id;
    errno = 0;
    if (params && !subsys_json_value_has_unique_keys_deadline(params, deadline)) {
        int saved = errno ? errno : EINVAL;
        if (saved == ETIMEDOUT) invalidate(session);
        return mhg_errorf(error, saved, "invalid RPC params");
    }
    request = cJSON_CreateObject();
    if (!request || !cJSON_AddStringToObject(request, "jsonrpc", "2.0") ||
        !cJSON_AddNumberToObject(request, "id", (double)id) ||
        !cJSON_AddStringToObject(request, "method", method) ||
        (params ? !cJSON_AddItemReferenceToObject(request, "params", (cJSON *)params)
                : !cJSON_AddObjectToObject(request, "params")) ||
        !(text = cJSON_PrintUnformatted(request))) {
        mhg_errorf(error, ENOMEM, "RPC request allocation failed");
        goto done;
    }
    if (mhg_pack_json(text, strlen(text), session->budget - 21, &payload, error))
        goto done;
    /* From encryption onward a failed send leaves delivery uncertain, so the
     * session is invalidated instead of being retried implicitly. */
    if (mhg_encrypt(&session->tx, payload.data, payload.len, &cipher_text,
                    error) ||
        send_message(session->transport, 0x05, cipher_text.data,
                     cipher_text.len, deadline, error))
        goto done;
    ++session->next_id;
    *id_out = id;
    rc = 0;

done:
    if (rc) invalidate(session);
    cJSON_Delete(request);
    if (text) {
        OPENSSL_cleanse(text, strlen(text));
        cJSON_free(text);
    }
    mhg_buf_clear(&payload);
    mhg_buf_clear(&cipher_text);
    return rc;
}

int mhg_session_poll(struct mhg_session *session, uint64_t id, cJSON **reply,
                     int *ready, uint64_t deadline, struct mhg_error *error)
{
    struct mhg_buf frame = {0};
    int rc = -1;

    if (!session || !reply || !ready || *reply)
        return mhg_errorf(error, EINVAL, "invalid poll arguments");
    *ready = 0;
    if (!session->valid)
        return mhg_errorf(error, ENOTCONN,
                          "session is invalid; authenticate again");
    for (;;) {
        cJSON *json;
        int kind;
        int complete = 0;

        mhg_buf_clear(&frame);
        if (mhg_remaining_ms(deadline, 1, NULL, error) < 0) goto done;
        if (mhg_transport_pump(session->transport, &frame, &complete, error))
            goto done;
        if (!complete) {
            rc = 0;
            break;
        }
        json = mhg_session_frame_json(session, &frame, deadline, error);
        if (!json) goto done;
        kind = validate_envelope(json, id, error);
        if (kind < 0) {
            cJSON_Delete(json);
            goto done;
        }
        if (!kind) {
            *reply = json;
            *ready = 1;
            rc = 0;
            break;
        }
        cJSON_Delete(json);
    }

done:
    if (rc) invalidate(session);
    mhg_buf_clear(&frame);
    return rc;
}

int mhg_session_call(struct mhg_session *session, const char *method,
                       const cJSON *params, uint64_t deadline, cJSON **reply,
                       struct mhg_error *error)
{
    struct mhg_buf frame = {0};
    uint64_t id;
    int rc = -1;

    if (!reply || *reply)
        return mhg_errorf(error, EINVAL, "invalid RPC arguments");
    if (mhg_session_send(session, method, params, &id, deadline, error))
        return -1;
    for (;;) {
        cJSON *json;
        int kind;

        if (receive_message(session->transport, 0x05, &frame, deadline, error))
            goto done;
        json = mhg_session_frame_json(session, &frame, deadline, error);
        mhg_buf_clear(&frame);
        if (!json) goto done;
        kind = validate_envelope(json, id, error);
        if (kind < 0 || mhg_remaining_ms(deadline, 1, NULL, error) < 0) {
            cJSON_Delete(json);
            goto done;
        }
        if (!kind) {
            *reply = json;
            rc = 0;
            break;
        }
        cJSON_Delete(json);
    }

done:
    if (rc) invalidate(session);
    mhg_buf_clear(&frame);
    return rc;
}

int mhg_probe_devices(struct mhg_transport *transport, const char *passcode,
                       size_t budget, uint64_t deadline, size_t *device_count,
                       const char **phase, struct mhg_error *error)
{
    struct mhg_session *session;
    cJSON *json = NULL;
    const cJSON *result, *field;
    int rc = -1;
    if (!device_count || !phase)
        return mhg_errorf(error, EINVAL, "invalid probe arguments");
    *device_count = 0;
    session = mhg_session_open(transport, passcode, budget, deadline, phase, error);
    if (!session) return -1;
    *phase = "rpc";
    if (mhg_session_call(session, "/api/getDevList", NULL, deadline, &json, error))
        goto done;
    if (cJSON_GetObjectItemCaseSensitive(json, "error")) {
        mhg_errorf(error, EREMOTEIO, "gateway returned a JSON-RPC error");
        goto done;
    }
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    field = cJSON_GetObjectItemCaseSensitive(result, "devList");
    if (!cJSON_IsObject(result) || !cJSON_IsObject(field)) {
        mhg_errorf(error, EPROTO, "getDevList result has unexpected shape");
        goto done;
    }
    for (const cJSON *item = field->child; item; item = item->next) ++*device_count;
    rc = 0;
done:
    cJSON_Delete(json);
    mhg_session_free(session);
    return rc;
}
