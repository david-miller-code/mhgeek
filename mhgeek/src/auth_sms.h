#ifndef MHGEEK_AUTH_SMS_H
#define MHGEEK_AUTH_SMS_H

#include <stdbool.h>
#include <stdint.h>

#include "account_store.h"
#include "passport_wire.h"

enum mhg_auth_sms_state {
    MHG_AUTH_SMS_NEEDS_AUTHORIZATION = 0,
    MHG_AUTH_SMS_WORKING = 1,
    MHG_AUTH_SMS_CODE_REQUIRED = 2,
    MHG_AUTH_SMS_AUTHENTICATED = 3,
    MHG_AUTH_SMS_PERSIST_PENDING = 4,
    MHG_AUTH_SMS_RETRY_REQUIRED = 5,
    MHG_AUTH_SMS_SEND_UNKNOWN = 6,
};

enum mhg_auth_sms_phase {
    MHG_AUTH_SMS_PHASE_IDLE = 0,
    MHG_AUTH_SMS_PHASE_POLICY = 1,
    MHG_AUTH_SMS_PHASE_PREFERENCE = 2,
    MHG_AUTH_SMS_PHASE_SEND = 3,
    MHG_AUTH_SMS_PHASE_CODE = 4,
    MHG_AUTH_SMS_PHASE_PHONE_INFO = 5,
    MHG_AUTH_SMS_PHASE_TICKET_AUTH = 6,
    MHG_AUTH_SMS_PHASE_TOKEN_ROTATE = 7,
    MHG_AUTH_SMS_PHASE_PERSIST = 8,
    MHG_AUTH_SMS_PHASE_RETRY = 9,
    MHG_AUTH_SMS_PHASE_SEND_UNKNOWN = 10,
};

enum mhg_auth_sms_pending_store_outcome {
    MHG_AUTH_SMS_PENDING_STORE_NONE = 0,
    MHG_AUTH_SMS_PENDING_STORE_FAILED_OLD_AUTHORITATIVE = 1,
    MHG_AUTH_SMS_PENDING_STORE_COMMITTED_NOT_DURABLE = 2,
};

enum mhg_auth_sms_error {
    MHG_AUTH_SMS_ERROR_NONE = 0,
    MHG_AUTH_SMS_ERROR_INPUT = 1,
    MHG_AUTH_SMS_ERROR_CONFLICT = 2,
    MHG_AUTH_SMS_ERROR_RATE_LIMIT = 3,
    MHG_AUTH_SMS_ERROR_CODE_INVALID_OR_EXPIRED = 4,
    MHG_AUTH_SMS_ERROR_UNSUPPORTED_CHALLENGE = 5,
    MHG_AUTH_SMS_ERROR_PROVIDER = 6,
    MHG_AUTH_SMS_ERROR_NETWORK = 7,
    MHG_AUTH_SMS_ERROR_PROTOCOL = 8,
    MHG_AUTH_SMS_ERROR_INTERNAL = 9,
    MHG_AUTH_SMS_ERROR_STORAGE = 10,
    MHG_AUTH_SMS_ERROR_EXPIRED = 11,
    MHG_AUTH_SMS_ERROR_CANCELED = 12,
    MHG_AUTH_SMS_ERROR_HTTP = 13,
};

enum mhg_auth_sms_provider_scope {
    MHG_AUTH_SMS_PROVIDER_SCOPE_NONE = 0,
    MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT = 1,
    MHG_AUTH_SMS_PROVIDER_SCOPE_TOKEN_LOGIN = 2,
};

enum mhg_auth_sms_provider_class {
    MHG_AUTH_SMS_PROVIDER_NONE = 0,
    MHG_AUTH_SMS_PROVIDER_SMS_SEND_LIMIT_TOMORROW = 1,
    MHG_AUTH_SMS_PROVIDER_SMS_CODE_INVALID_OR_EXPIRED = 2,
    MHG_AUTH_SMS_PROVIDER_ADDITIONAL_VERIFICATION_REQUIRED = 3,
    MHG_AUTH_SMS_PROVIDER_CREDENTIAL_REJECTED = 4,
    MHG_AUTH_SMS_PROVIDER_OTHER = 5,
};

/* Fixed, nonsecret diagnostic metadata. Provider response text is excluded. */
struct mhg_auth_sms_provider_diagnostic {
    enum mhg_auth_sms_provider_scope scope;
    enum mhg_auth_sms_provider_class provider_class;
    int provider_code;
};

/* Stable message keys shared with MHCamera's phone-only authorization: the same
 * condition must carry the same key in both plugins so the frontend can map one
 * toast table (§10.1). Provider-class keys live in the provider table; this one
 * is the local "you must wait" throttle (retry_after_seconds above). */
#define MHG_AUTH_SMS_KEY_RETRY_LATER "sms_retry_later"

#define MHG_AUTH_SMS_PROVIDER_DIAGNOSTIC_INIT \
    {MHG_AUTH_SMS_PROVIDER_SCOPE_NONE, MHG_AUTH_SMS_PROVIDER_NONE, 0}

enum mhg_auth_sms_result {
    MHG_AUTH_SMS_ACCEPTED = 0,
    MHG_AUTH_SMS_DUPLICATE = 1,
    MHG_AUTH_SMS_REJECTED_INPUT = -1,
    MHG_AUTH_SMS_REJECTED_CONFLICT = -2,
    MHG_AUTH_SMS_REJECTED_STALE = -3,
    MHG_AUTH_SMS_REJECTED_RATE_LIMIT = -4,
    MHG_AUTH_SMS_REJECTED_STORAGE = -5,
};

enum mhg_auth_sms_work_kind {
    MHG_AUTH_SMS_WORK_NONE = 0,
    MHG_AUTH_SMS_WORK_PASSPORT = 1,
    MHG_AUTH_SMS_WORK_TOKEN_ROTATE = 2,
};

struct mhg_auth_sms_work {
    enum mhg_auth_sms_work_kind kind;
    enum mhg_passport_step passport_step;
    uint64_t challenge_generation;
    uint64_t owner_generation;
    uint64_t operation_id;
    char calling_code[5];
    char policy_name[32];
    struct mhg_secret_buf passport_user;
    struct mhg_secret_buf ticket;
    struct mhg_secret_buf device_id;
    struct mhg_secret_buf user_id;
    struct mhg_secret_buf pass_token;
};

#define MHG_AUTH_SMS_WORK_INIT \
    {.kind = MHG_AUTH_SMS_WORK_NONE, \
     .passport_user = MHG_SECRET_BUF_INIT, .ticket = MHG_SECRET_BUF_INIT, \
     .device_id = MHG_SECRET_BUF_INIT, .user_id = MHG_SECRET_BUF_INIT, \
     .pass_token = MHG_SECRET_BUF_INIT}

/* Every work/next output passed to a public API must start with
 * MHG_AUTH_SMS_WORK_INIT and must be cleared before leaving its owner. */

struct mhg_auth_sms_status {
    enum mhg_auth_sms_state state;
    enum mhg_auth_sms_phase phase;
    enum mhg_auth_sms_error error;
    bool has_account;
    uint64_t account_generation;
    uint64_t challenge_generation;
    uint64_t owner_generation;
    uint64_t operation_id;
    uint64_t last_accepted_operation_id;
    uint64_t pending_account_generation;
    enum mhg_auth_sms_pending_store_outcome pending_store_outcome;
    unsigned int code_length;
    unsigned int retry_after_seconds;
    enum mhg_auth_sms_provider_scope provider_scope;
    enum mhg_auth_sms_provider_class provider_class;
    int provider_code;
};

struct mhg_auth_sms_store_ops {
    int (*load)(void *userdata, struct mhg_account_record *record);
    /* commit/clear return an mhg_account_store_commit_result. */
    int (*commit)(void *userdata, const struct mhg_account_record *record);
    int (*clear)(void *userdata, uint64_t cleared_generation);
};

struct mhg_auth_sms_store {
    const struct mhg_auth_sms_store_ops *ops;
    void *userdata;
};

struct mhg_auth_sms;

/* One service owner serializes calls. Network workers may only return through
 * the completion APIs with the exact immutable work identity they received. */
int mhg_auth_sms_create(struct mhg_auth_sms **auth_out,
                        const struct mhg_auth_sms_store *store);
void mhg_auth_sms_destroy(struct mhg_auth_sms *auth);

/* Restore is deliberately passive: it reads the private account record and
 * never starts a Passport request or sends an SMS. */
int mhg_auth_sms_restore(struct mhg_auth_sms *auth);
/* Copies the complete durable base credential for a later typed service-login
 * owner. output must begin at MHG_ACCOUNT_RECORD_INIT; the caller owns and
 * must clear it. No pair-only view exists. */
int mhg_auth_sms_copy_account(const struct mhg_auth_sms *auth,
                              struct mhg_account_record *output);

/* A restored or newly committed account makes START a conflict until an
 * explicit clear succeeds. Rejection leaves work empty and does not advance
 * the operation or challenge generations. */
enum mhg_auth_sms_result mhg_auth_sms_start(
    struct mhg_auth_sms *auth, const char *calling_code,
    const char *national_number, uint64_t operation_id,
    struct mhg_auth_sms_work *work);
enum mhg_auth_sms_result mhg_auth_sms_resend(
    struct mhg_auth_sms *auth, uint64_t operation_id, uint64_t now_ms,
    struct mhg_auth_sms_work *work);
/* Retries the last transport-failed step, or the next step whose work could
 * not be published after a successful response. A not-yet-published
 * SEND_TICKET may be retried here; SEND_UNKNOWN is excluded because that work
 * was published and repeating it may send a second SMS. */
enum mhg_auth_sms_result mhg_auth_sms_retry(
    struct mhg_auth_sms *auth, uint64_t operation_id,
    struct mhg_auth_sms_work *work);
enum mhg_auth_sms_result mhg_auth_sms_verify(
    struct mhg_auth_sms *auth, const char *code, uint64_t operation_id,
    struct mhg_auth_sms_work *work);
enum mhg_auth_sms_result mhg_auth_sms_cancel(
    struct mhg_auth_sms *auth, uint64_t operation_id);
/* Expires only an in-progress provider challenge. Once token rotation has
 * produced PERSIST_PENDING, automatic expiry is rejected so a transient store
 * failure cannot discard the completed authorization. */
enum mhg_auth_sms_result mhg_auth_sms_expire(
    struct mhg_auth_sms *auth, uint64_t challenge_generation);
enum mhg_auth_sms_result mhg_auth_sms_clear(
    struct mhg_auth_sms *auth, uint64_t operation_id);
/* Retries only the private-store transaction retained after a validated token
 * rotation or clear. It never produces Passport work or sends an SMS. Both
 * identifiers must match the pending operation reported by status. A
 * COMMITTED_NOT_DURABLE pending outcome freezes every other state-changing
 * operation until this call reaches a durable decision. */
enum mhg_auth_sms_result mhg_auth_sms_retry_persist(
    struct mhg_auth_sms *auth, uint64_t challenge_generation,
    uint64_t operation_id);

/* completed identifies the exact challenge and single async owner. Late or
 * mismatched completions are rejected without changing current state.
 * response is required only for MHG_CLOUD_OK and MHG_CLOUD_SERVICE; every
 * other worker failure class may pass NULL. */
enum mhg_auth_sms_result mhg_auth_sms_complete_passport(
    struct mhg_auth_sms *auth,
    const struct mhg_auth_sms_work *completed,
    enum mhg_cloud_error cloud_error,
    const struct mhg_passport_response *response,
    const char *passport_device_id,
    uint64_t now_ms,
    struct mhg_auth_sms_work *next);

/* TOKEN_ROTATE means a complete native Xiaomi token-login/redirect cycle.
 * The returned device id and user id must equal the ticket-auth candidate.
 * The rotated credential triple is committed and strictly reread by the configured store before the
 * state can become AUTHENTICATED. On non-OK worker outcomes both rotated
 * strings may be NULL. provider may describe a nonzero token-login provider
 * response using fixed nonsecret fields; it must be NULL for outcomes without
 * such a response. */
enum mhg_auth_sms_result mhg_auth_sms_complete_rotation(
    struct mhg_auth_sms *auth,
    const struct mhg_auth_sms_work *completed,
    enum mhg_cloud_error cloud_error,
    const char *rotated_device_id,
    const char *rotated_user_id,
    const char *rotated_pass_token,
    const struct mhg_auth_sms_provider_diagnostic *provider,
    struct mhg_auth_sms_work *next);

void mhg_auth_sms_get_status(const struct mhg_auth_sms *auth,
                             uint64_t now_ms,
                             struct mhg_auth_sms_status *status);
/* Read-only owner check used immediately before an executor starts I/O. */
bool mhg_auth_sms_work_is_current(const struct mhg_auth_sms *auth,
                                  const struct mhg_auth_sms_work *work);
void mhg_auth_sms_work_clear(struct mhg_auth_sms_work *work);

const char *mhg_auth_sms_state_name(enum mhg_auth_sms_state state);
const char *mhg_auth_sms_phase_name(enum mhg_auth_sms_phase phase);
const char *mhg_auth_sms_error_name(enum mhg_auth_sms_error error);
const char *mhg_auth_sms_provider_scope_name(
    enum mhg_auth_sms_provider_scope scope);
/* Presentation key for actual rejection only; resend cooldown is not an error. */
const char *mhg_auth_sms_status_message_key(const struct mhg_auth_sms_status *status);
const char *mhg_auth_sms_provider_class_name(
    enum mhg_auth_sms_provider_class provider_class);

#ifdef MHG_AUTH_SMS_TESTING
/* Fails the next work construction before it can publish state or an owner. */
void mhg_auth_sms_test_fail_work_once(void);
#endif

#endif
