#include "auth_sms.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "passport_device_id.h"

struct mhg_auth_sms {
    struct mhg_auth_sms_store store;
    struct mhg_account_record account;
    struct mhg_account_record pending_account;
    enum mhg_auth_sms_phase phase;
    enum mhg_auth_sms_error error;
    bool has_account;
    uint64_t challenge_generation;
    uint64_t owner_generation;
    uint64_t operation_id;
    uint64_t last_accepted_operation_id;
    unsigned int code_length;
    uint64_t resend_not_before_ms;
    enum mhg_auth_sms_provider_scope provider_scope;
    enum mhg_auth_sms_provider_class provider_class;
    int provider_code;
    char calling_code[5];
    char policy_name[32];
    struct mhg_secret_buf passport_user;
    struct mhg_secret_buf ticket;
    struct mhg_secret_buf candidate_device_id;
    struct mhg_secret_buf candidate_user_id;
    struct mhg_secret_buf candidate_pass_token;
    bool pending_clear;
    enum mhg_auth_sms_pending_store_outcome pending_store_outcome;
    enum mhg_auth_sms_work_kind retry_kind;
    enum mhg_passport_step retry_step;
};

#ifdef MHG_AUTH_SMS_TESTING
static bool fail_next_work;

void mhg_auth_sms_test_fail_work_once(void)
{
    fail_next_work = true;
}

static int work_checkpoint(void)
{
    if (!fail_next_work) return 0;
    fail_next_work = false;
    errno = ENOMEM;
    return -1;
}
#else
#define work_checkpoint() (0)
#endif

static uint64_t next_generation(uint64_t value)
{
    return value == UINT64_MAX ? 0u : value + 1u;
}

static void clear_provider_diagnostic(struct mhg_auth_sms *auth)
{
    if (!auth) return;
    auth->provider_scope = MHG_AUTH_SMS_PROVIDER_SCOPE_NONE;
    auth->provider_class = MHG_AUTH_SMS_PROVIDER_NONE;
    auth->provider_code = 0;
}

static void set_provider_diagnostic(
    struct mhg_auth_sms *auth, enum mhg_auth_sms_provider_scope scope,
    enum mhg_auth_sms_provider_class provider_class, int provider_code)
{
    if (!auth) return;
    auth->provider_scope = scope;
    auth->provider_class = provider_class;
    auth->provider_code = provider_code;
}

static enum mhg_auth_sms_provider_class passport_provider_class(
    enum mhg_passport_provider_class provider_class)
{
    switch (provider_class) {
    case MHG_PASSPORT_PROVIDER_NONE:
        return MHG_AUTH_SMS_PROVIDER_NONE;
    case MHG_PASSPORT_SMS_SEND_LIMIT_TOMORROW:
        return MHG_AUTH_SMS_PROVIDER_SMS_SEND_LIMIT_TOMORROW;
    case MHG_PASSPORT_SMS_CODE_INVALID_OR_EXPIRED:
        return MHG_AUTH_SMS_PROVIDER_SMS_CODE_INVALID_OR_EXPIRED;
    case MHG_PASSPORT_ADDITIONAL_VERIFICATION_REQUIRED:
        return MHG_AUTH_SMS_PROVIDER_ADDITIONAL_VERIFICATION_REQUIRED;
    case MHG_PASSPORT_PROVIDER_OTHER:
        return MHG_AUTH_SMS_PROVIDER_OTHER;
    }
    return MHG_AUTH_SMS_PROVIDER_OTHER;
}

void mhg_auth_sms_work_clear(struct mhg_auth_sms_work *work)
{
    if (!work) return;
    mhg_secret_buf_clear(&work->passport_user);
    mhg_secret_buf_clear(&work->ticket);
    mhg_secret_buf_clear(&work->device_id);
    mhg_secret_buf_clear(&work->user_id);
    mhg_secret_buf_clear(&work->pass_token);
    mhg_secure_clear(work, sizeof(*work));
}

static void clear_flow_secrets(struct mhg_auth_sms *auth)
{
    if (!auth) return;
    mhg_secret_buf_clear(&auth->passport_user);
    mhg_secret_buf_clear(&auth->ticket);
    mhg_secret_buf_clear(&auth->candidate_device_id);
    mhg_secret_buf_clear(&auth->candidate_user_id);
    mhg_secret_buf_clear(&auth->candidate_pass_token);
    auth->retry_kind = MHG_AUTH_SMS_WORK_NONE;
    auth->retry_step = 0;
    mhg_secure_clear(auth->calling_code, sizeof(auth->calling_code));
    mhg_secure_clear(auth->policy_name, sizeof(auth->policy_name));
    auth->code_length = 0u;
    auth->resend_not_before_ms = 0u;
    clear_provider_diagnostic(auth);
}

static void clear_challenge(struct mhg_auth_sms *auth, bool invalidate)
{
    if (!auth) return;
    clear_flow_secrets(auth);
    mhg_account_record_clear(&auth->pending_account);
    auth->pending_clear = false;
    auth->pending_store_outcome = MHG_AUTH_SMS_PENDING_STORE_NONE;
    auth->operation_id = 0u;
    auth->phase = MHG_AUTH_SMS_PHASE_IDLE;
    if (invalidate && auth->challenge_generation != UINT64_MAX)
        auth->challenge_generation++;
}

static int persist_is_uncertain(const struct mhg_auth_sms *auth)
{
    return auth && auth->phase == MHG_AUTH_SMS_PHASE_PERSIST &&
           auth->pending_store_outcome ==
               MHG_AUTH_SMS_PENDING_STORE_COMMITTED_NOT_DURABLE;
}

static void enter_work_retry(struct mhg_auth_sms *auth,
                             enum mhg_auth_sms_work_kind kind,
                             enum mhg_passport_step step,
                             enum mhg_auth_sms_error error)
{
    auth->phase = MHG_AUTH_SMS_PHASE_RETRY;
    auth->operation_id = 0u;
    auth->retry_kind = kind;
    auth->retry_step = step;
    auth->error = error;
}

static int copy_secret(struct mhg_secret_buf *output,
                       const struct mhg_secret_buf *input)
{
    if (!input || !input->data || input->len == 0u) return -1;
    return mhg_secret_buf_set(output, input->data, input->len);
}

int mhg_auth_sms_create(struct mhg_auth_sms **auth_out,
                        const struct mhg_auth_sms_store *store)
{
    struct mhg_auth_sms *auth;

    if (!auth_out || !store || !store->ops || !store->ops->load ||
        !store->ops->commit || !store->ops->clear) {
        errno = EINVAL;
        return -1;
    }
    *auth_out = NULL;
    auth = calloc(1u, sizeof(*auth));
    if (!auth) return -1;
    auth->store = *store;
    auth->account = (struct mhg_account_record)MHG_ACCOUNT_RECORD_INIT;
    auth->pending_account =
        (struct mhg_account_record)MHG_ACCOUNT_RECORD_INIT;
    *auth_out = auth;
    return 0;
}

void mhg_auth_sms_destroy(struct mhg_auth_sms *auth)
{
    if (!auth) return;
    clear_challenge(auth, false);
    mhg_account_record_clear(&auth->account);
    mhg_secure_clear(auth, sizeof(*auth));
    free(auth);
}

int mhg_auth_sms_restore(struct mhg_auth_sms *auth)
{
    struct mhg_account_record loaded = MHG_ACCOUNT_RECORD_INIT;
    int result;

    if (!auth || auth->phase != MHG_AUTH_SMS_PHASE_IDLE) {
        errno = EINVAL;
        return -1;
    }
    result = auth->store.ops->load(auth->store.userdata, &loaded);
    if (result == MHG_ACCOUNT_STORE_ERROR) {
        auth->error = MHG_AUTH_SMS_ERROR_STORAGE;
        return -1;
    }
    if (result == MHG_ACCOUNT_STORE_ABSENT) {
        mhg_account_record_clear(&auth->account);
        auth->account.generation = loaded.generation;
        loaded.generation = 0u;
        mhg_account_record_clear(&loaded);
        auth->has_account = false;
        auth->error = MHG_AUTH_SMS_ERROR_NONE;
        return 0;
    }
    mhg_account_record_clear(&auth->account);
    auth->account = loaded;
    auth->has_account = true;
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    return 0;
}

int mhg_auth_sms_copy_account(const struct mhg_auth_sms *auth,
                              struct mhg_account_record *output)
{
    struct mhg_account_record copy = MHG_ACCOUNT_RECORD_INIT;

    if (!auth || !output || !auth->has_account ||
        !mhg_passport_device_id_is_valid(auth->account.device_id.data,
                                         auth->account.device_id.len) ||
        copy_secret(&copy.device_id, &auth->account.device_id) != 0 ||
        copy_secret(&copy.user_id, &auth->account.user_id) != 0 ||
        copy_secret(&copy.pass_token, &auth->account.pass_token) != 0) {
        mhg_account_record_clear(&copy);
        errno = EINVAL;
        return -1;
    }
    copy.generation = auth->account.generation;
    mhg_account_record_clear(output);
    *output = copy;
    return 0;
}

static int only_digits(const char *value, size_t length)
{
    size_t index;
    if (!value || length == 0u) return 0;
    for (index = 0u; index < length; ++index)
        if (value[index] < '0' || value[index] > '9') return 0;
    return 1;
}

static int normalize_phone(const char *calling_code,
                           const char *national_number,
                           struct mhg_secret_buf *passport_user)
{
    size_t calling_len;
    size_t national_len;
    size_t full_len;
    unsigned char full[17];
    const char *source;
    size_t source_len;

    mhg_secret_buf_clear(passport_user);
    if (!calling_code || !national_number) return -1;
    calling_len = strlen(calling_code);
    national_len = strlen(national_number);
    if (calling_len < 2u || calling_len > 4u || calling_code[0] != '+' ||
        calling_code[1] < '1' || calling_code[1] > '9' ||
        !only_digits(calling_code + 1u, calling_len - 1u) ||
        !only_digits(national_number, national_len) ||
        calling_len - 1u + national_len > 15u)
        return -1;
    if (strcmp(calling_code, "+86") == 0) {
        source = national_number;
        source_len = national_len;
    } else {
        full_len = calling_len + national_len;
        if (full_len >= sizeof(full)) return -1;
        memcpy(full, calling_code, calling_len);
        memcpy(full + calling_len, national_number, national_len);
        source = (const char *)full;
        source_len = full_len;
    }
    if (mhg_secret_buf_set(passport_user, source, source_len) != 0) {
        mhg_secure_clear(full, sizeof(full));
        return -1;
    }
    mhg_secure_clear(full, sizeof(full));
    return 0;
}

static int work_secret(struct mhg_secret_buf *output,
                       const struct mhg_secret_buf *input)
{
    return !input || !input->data ? 0 :
        mhg_secret_buf_set(output, input->data, input->len);
}

static int build_work(enum mhg_auth_sms_work_kind kind,
                      enum mhg_passport_step step,
                      uint64_t challenge_generation,
                      uint64_t owner_generation,
                      uint64_t operation_id,
                      const char calling_code[5],
                      const char policy_name[32],
                      const struct mhg_secret_buf *passport_user,
                      const struct mhg_secret_buf *ticket,
                      const struct mhg_secret_buf *device_id,
                      const struct mhg_secret_buf *user_id,
                      const struct mhg_secret_buf *pass_token,
                      struct mhg_auth_sms_work *work)
{
    struct mhg_auth_sms_work output = MHG_AUTH_SMS_WORK_INIT;

    mhg_auth_sms_work_clear(work);
    if (owner_generation == 0u) {
        errno = EOVERFLOW;
        return -1;
    }
    if (work_checkpoint() != 0) return -1;
    output.kind = kind;
    output.passport_step = step;
    output.challenge_generation = challenge_generation;
    output.owner_generation = owner_generation;
    output.operation_id = operation_id;
    if (calling_code)
        memcpy(output.calling_code, calling_code,
               strlen(calling_code) + 1u);
    if (policy_name)
        memcpy(output.policy_name, policy_name, sizeof(output.policy_name));
    if ((kind == MHG_AUTH_SMS_WORK_PASSPORT &&
         (work_secret(&output.passport_user, passport_user) != 0 ||
          work_secret(&output.ticket, ticket) != 0)) ||
        (kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE &&
         (work_secret(&output.device_id, device_id) != 0 ||
          work_secret(&output.user_id, user_id) != 0 ||
          work_secret(&output.pass_token, pass_token) != 0)) ||
        (kind != MHG_AUTH_SMS_WORK_PASSPORT &&
         kind != MHG_AUTH_SMS_WORK_TOKEN_ROTATE)) {
        mhg_auth_sms_work_clear(&output);
        return -1;
    }
    *work = output;
    return 0;
}

static enum mhg_auth_sms_result check_operation(
    struct mhg_auth_sms *auth, uint64_t operation_id)
{
    if (!operation_id) {
        auth->error = MHG_AUTH_SMS_ERROR_INPUT;
        return MHG_AUTH_SMS_REJECTED_INPUT;
    }
    if (operation_id <= auth->last_accepted_operation_id ||
        (auth->phase == MHG_AUTH_SMS_PHASE_PERSIST &&
         operation_id <= auth->operation_id))
        return MHG_AUTH_SMS_DUPLICATE;
    return MHG_AUTH_SMS_ACCEPTED;
}

static int prepare_auth_work(const struct mhg_auth_sms *auth,
                             enum mhg_auth_sms_work_kind kind,
                             enum mhg_passport_step step,
                             uint64_t operation_id,
                             const char policy_name[32],
                             const struct mhg_secret_buf *ticket,
                             const struct mhg_secret_buf *device_id,
                             const struct mhg_secret_buf *user_id,
                             const struct mhg_secret_buf *pass_token,
                             uint64_t *owner_generation,
                             struct mhg_auth_sms_work *work)
{
    uint64_t owner = next_generation(auth->owner_generation);

    if (!owner || build_work(kind, step, auth->challenge_generation,
                             owner, operation_id,
                             auth->calling_code,
                             policy_name ? policy_name : auth->policy_name,
                             &auth->passport_user,
                             ticket ? ticket : &auth->ticket,
                             device_id, user_id, pass_token, work) != 0)
        return -1;
    *owner_generation = owner;
    return 0;
}

enum mhg_auth_sms_result mhg_auth_sms_start(
    struct mhg_auth_sms *auth, const char *calling_code,
    const char *national_number, uint64_t operation_id,
    struct mhg_auth_sms_work *work)
{
    struct mhg_secret_buf normalized = MHG_SECRET_BUF_INIT;
    enum mhg_auth_sms_result checked;
    uint64_t challenge_generation;
    uint64_t owner_generation;

    if (!auth || !work) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(work);
    if (auth->has_account)
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    if (auth->challenge_generation == UINT64_MAX) {
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    if (normalize_phone(calling_code, national_number, &normalized) != 0) {
        auth->error = MHG_AUTH_SMS_ERROR_INPUT;
        return MHG_AUTH_SMS_REJECTED_INPUT;
    }
    challenge_generation = next_generation(auth->challenge_generation);
    owner_generation = next_generation(auth->owner_generation);
    if (challenge_generation == 0u || owner_generation == 0u ||
        build_work(MHG_AUTH_SMS_WORK_PASSPORT, MHG_PASSPORT_POLICY,
                   challenge_generation, owner_generation, operation_id,
                   calling_code, NULL, &normalized, NULL, NULL, NULL, NULL,
                   work) != 0) {
        mhg_secret_buf_clear(&normalized);
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    clear_challenge(auth, false);
    auth->challenge_generation = challenge_generation;
    auth->owner_generation = owner_generation;
    auth->passport_user = normalized;
    memcpy(auth->calling_code, calling_code,
           strlen(calling_code) + 1u);
    auth->operation_id = operation_id;
    auth->last_accepted_operation_id = operation_id;
    auth->phase = MHG_AUTH_SMS_PHASE_POLICY;
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    return MHG_AUTH_SMS_ACCEPTED;
}

static int valid_completion(const struct mhg_auth_sms *auth,
                            const struct mhg_auth_sms_work *completed,
                            enum mhg_auth_sms_work_kind kind,
                            enum mhg_passport_step step)
{
    return auth && completed && completed->kind == kind &&
           completed->passport_step == step &&
           completed->challenge_generation == auth->challenge_generation &&
           completed->owner_generation == auth->owner_generation &&
           completed->operation_id == auth->operation_id;
}

bool mhg_auth_sms_work_is_current(const struct mhg_auth_sms *auth,
                                  const struct mhg_auth_sms_work *work)
{
    enum mhg_auth_sms_work_kind kind;
    enum mhg_passport_step step = 0;
    if (!auth || !work) return false;
    switch (auth->phase) {
    case MHG_AUTH_SMS_PHASE_POLICY: step = MHG_PASSPORT_POLICY; break;
    case MHG_AUTH_SMS_PHASE_PREFERENCE: step = MHG_PASSPORT_PREFERENCE; break;
    case MHG_AUTH_SMS_PHASE_SEND: step = MHG_PASSPORT_SEND_TICKET; break;
    case MHG_AUTH_SMS_PHASE_PHONE_INFO: step = MHG_PASSPORT_PHONE_INFO; break;
    case MHG_AUTH_SMS_PHASE_TICKET_AUTH: step = MHG_PASSPORT_TICKET_AUTH; break;
    case MHG_AUTH_SMS_PHASE_TOKEN_ROTATE:
        kind = MHG_AUTH_SMS_WORK_TOKEN_ROTATE;
        return valid_completion(auth, work, kind, 0);
    default: return false;
    }
    kind = MHG_AUTH_SMS_WORK_PASSPORT;
    return valid_completion(auth, work, kind, step);
}

static enum mhg_auth_sms_error cloud_error_map(enum mhg_cloud_error error)
{
    switch (error) {
    case MHG_CLOUD_NETWORK: return MHG_AUTH_SMS_ERROR_NETWORK;
    case MHG_CLOUD_HTTP: return MHG_AUTH_SMS_ERROR_HTTP;
    case MHG_CLOUD_MALFORMED:
    case MHG_CLOUD_SID_MISMATCH:
    case MHG_CLOUD_TARGET_MISMATCH:
    case MHG_CLOUD_DECRYPT:
    case MHG_CLOUD_CRYPTO: return MHG_AUTH_SMS_ERROR_PROTOCOL;
    case MHG_CLOUD_INTERNAL: return MHG_AUTH_SMS_ERROR_INTERNAL;
    case MHG_CLOUD_NOT_DISPATCHED: return MHG_AUTH_SMS_ERROR_INTERNAL;
    case MHG_CLOUD_AUTH_REJECTED:
    case MHG_CLOUD_SERVICE: return MHG_AUTH_SMS_ERROR_PROVIDER;
    case MHG_CLOUD_INPUT:
    case MHG_CLOUD_OK: break;
    }
    return MHG_AUTH_SMS_ERROR_PROTOCOL;
}

static bool cloud_failure_can_retry_without_sms(enum mhg_cloud_error error)
{
    return error != MHG_CLOUD_OK && error != MHG_CLOUD_INPUT;
}

static enum mhg_auth_sms_result passport_failure(
    struct mhg_auth_sms *auth,
    enum mhg_cloud_error cloud_error,
    const struct mhg_passport_response *response,
    enum mhg_passport_step failed_step)
{
    enum mhg_passport_provider_class provider = response ?
        response->provider_class : MHG_PASSPORT_PROVIDER_NONE;
    enum mhg_auth_sms_provider_class auth_provider =
        passport_provider_class(provider);
    int provider_code = response ? response->provider_code : 0;

    if (response && (provider_code != 0 ||
                     provider != MHG_PASSPORT_PROVIDER_NONE))
        set_provider_diagnostic(auth, MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT,
                                auth_provider, provider_code);
    else
        clear_provider_diagnostic(auth);
    if (cloud_error == MHG_CLOUD_NOT_DISPATCHED) {
        auth->operation_id = 0u;
        auth->phase = MHG_AUTH_SMS_PHASE_RETRY;
        auth->retry_kind = MHG_AUTH_SMS_WORK_PASSPORT;
        auth->retry_step = failed_step;
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (cloud_failure_can_retry_without_sms(cloud_error) &&
        cloud_error != MHG_CLOUD_SERVICE) {
        auth->operation_id = 0u;
        auth->error = cloud_error_map(cloud_error);
        if (failed_step == MHG_PASSPORT_SEND_TICKET) {
            auth->phase = MHG_AUTH_SMS_PHASE_SEND_UNKNOWN;
            auth->retry_kind = MHG_AUTH_SMS_WORK_NONE;
            auth->retry_step = 0;
        } else {
            auth->phase = MHG_AUTH_SMS_PHASE_RETRY;
            auth->retry_kind = MHG_AUTH_SMS_WORK_PASSPORT;
            auth->retry_step = failed_step;
        }
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (cloud_error == MHG_CLOUD_SERVICE &&
        provider == MHG_PASSPORT_SMS_CODE_INVALID_OR_EXPIRED &&
        (auth->phase == MHG_AUTH_SMS_PHASE_PHONE_INFO ||
         auth->phase == MHG_AUTH_SMS_PHASE_TICKET_AUTH)) {
        mhg_secret_buf_clear(&auth->ticket);
        mhg_secret_buf_clear(&auth->candidate_device_id);
        mhg_secret_buf_clear(&auth->candidate_user_id);
        mhg_secret_buf_clear(&auth->candidate_pass_token);
        auth->phase = MHG_AUTH_SMS_PHASE_CODE;
        auth->operation_id = 0u;
        auth->error = MHG_AUTH_SMS_ERROR_CODE_INVALID_OR_EXPIRED;
        return MHG_AUTH_SMS_REJECTED_INPUT;
    }
    if (cloud_error == MHG_CLOUD_SERVICE &&
        provider == MHG_PASSPORT_ADDITIONAL_VERIFICATION_REQUIRED) {
        clear_challenge(auth, true);
        set_provider_diagnostic(auth, MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT,
                                auth_provider, provider_code);
        auth->error = MHG_AUTH_SMS_ERROR_UNSUPPORTED_CHALLENGE;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (cloud_error == MHG_CLOUD_SERVICE &&
        provider == MHG_PASSPORT_SMS_SEND_LIMIT_TOMORROW) {
        clear_challenge(auth, true);
        set_provider_diagnostic(auth, MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT,
                                auth_provider, provider_code);
        auth->error = MHG_AUTH_SMS_ERROR_RATE_LIMIT;
        return MHG_AUTH_SMS_REJECTED_RATE_LIMIT;
    }
    clear_challenge(auth, true);
    if (response && (provider_code != 0 ||
                     provider != MHG_PASSPORT_PROVIDER_NONE))
        set_provider_diagnostic(auth, MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT,
                                auth_provider, provider_code);
    auth->error = cloud_error_map(cloud_error);
    return MHG_AUTH_SMS_REJECTED_CONFLICT;
}

enum mhg_auth_sms_result mhg_auth_sms_complete_passport(
    struct mhg_auth_sms *auth,
    const struct mhg_auth_sms_work *completed,
    enum mhg_cloud_error cloud_error,
    const struct mhg_passport_response *response,
    const char *passport_device_id,
    uint64_t now_ms,
    struct mhg_auth_sms_work *next)
{
    enum mhg_passport_step expected;
    uint64_t owner_generation;

    if (!next) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(next);
    if (!auth || !completed)
        return MHG_AUTH_SMS_REJECTED_INPUT;
    switch (auth->phase) {
    case MHG_AUTH_SMS_PHASE_POLICY: expected = MHG_PASSPORT_POLICY; break;
    case MHG_AUTH_SMS_PHASE_PREFERENCE: expected = MHG_PASSPORT_PREFERENCE; break;
    case MHG_AUTH_SMS_PHASE_SEND: expected = MHG_PASSPORT_SEND_TICKET; break;
    case MHG_AUTH_SMS_PHASE_PHONE_INFO: expected = MHG_PASSPORT_PHONE_INFO; break;
    case MHG_AUTH_SMS_PHASE_TICKET_AUTH: expected = MHG_PASSPORT_TICKET_AUTH; break;
    default: return MHG_AUTH_SMS_REJECTED_STALE;
    }
    if (!valid_completion(auth, completed, MHG_AUTH_SMS_WORK_PASSPORT,
                          expected))
        return MHG_AUTH_SMS_REJECTED_STALE;
    if (cloud_error != MHG_CLOUD_OK) {
        if (cloud_error == MHG_CLOUD_SERVICE && !response) {
            clear_challenge(auth, true);
            auth->error = MHG_AUTH_SMS_ERROR_PROTOCOL;
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        return passport_failure(auth, cloud_error, response, expected);
    }
    if (!response) {
        clear_challenge(auth, true);
        auth->error = MHG_AUTH_SMS_ERROR_PROTOCOL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    if (expected == MHG_PASSPORT_POLICY) {
        if (!response->policy_name[0]) goto protocol;
        memcpy(auth->policy_name, response->policy_name,
               sizeof(auth->policy_name));
        if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                              MHG_PASSPORT_PREFERENCE,
                              auth->operation_id, response->policy_name,
                              NULL, NULL, NULL, NULL, &owner_generation,
                              next) != 0) {
            enter_work_retry(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                             MHG_PASSPORT_PREFERENCE,
                             MHG_AUTH_SMS_ERROR_INTERNAL);
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        auth->owner_generation = owner_generation;
        auth->phase = MHG_AUTH_SMS_PHASE_PREFERENCE;
        clear_provider_diagnostic(auth);
        return MHG_AUTH_SMS_ACCEPTED;
    }
    if (expected == MHG_PASSPORT_PREFERENCE) {
        if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                              MHG_PASSPORT_SEND_TICKET,
                              auth->operation_id, NULL, NULL, NULL, NULL, NULL,
                              &owner_generation, next) != 0) {
            enter_work_retry(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                             MHG_PASSPORT_SEND_TICKET,
                             MHG_AUTH_SMS_ERROR_INTERNAL);
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        auth->owner_generation = owner_generation;
        auth->phase = MHG_AUTH_SMS_PHASE_SEND;
        clear_provider_diagnostic(auth);
        return MHG_AUTH_SMS_ACCEPTED;
    }
    if (expected == MHG_PASSPORT_SEND_TICKET) {
        uint64_t wait_ms;
        if (response->code_length == 0u) goto protocol;
        wait_ms = (uint64_t)response->retry_after_seconds * 1000u;
        if (now_ms > UINT64_MAX - wait_ms) goto protocol;
        auth->code_length = response->code_length;
        auth->resend_not_before_ms = now_ms + wait_ms;
        auth->phase = MHG_AUTH_SMS_PHASE_CODE;
        auth->operation_id = 0u;
        clear_provider_diagnostic(auth);
        return MHG_AUTH_SMS_ACCEPTED;
    }
    if (expected == MHG_PASSPORT_PHONE_INFO) {
        if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                              MHG_PASSPORT_TICKET_AUTH,
                              auth->operation_id, NULL, NULL, NULL, NULL, NULL,
                              &owner_generation, next) != 0) {
            enter_work_retry(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                             MHG_PASSPORT_TICKET_AUTH,
                             MHG_AUTH_SMS_ERROR_INTERNAL);
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        auth->owner_generation = owner_generation;
        auth->phase = MHG_AUTH_SMS_PHASE_TICKET_AUTH;
        clear_provider_diagnostic(auth);
        return MHG_AUTH_SMS_ACCEPTED;
    }
    {
        struct mhg_secret_buf candidate_device_id = MHG_SECRET_BUF_INIT;
        struct mhg_secret_buf candidate_user_id = MHG_SECRET_BUF_INIT;
        struct mhg_secret_buf candidate_pass_token = MHG_SECRET_BUF_INIT;

        if (!passport_device_id ||
            !mhg_passport_device_id_is_valid(
                (const unsigned char *)passport_device_id,
                strlen(passport_device_id)) ||
            !response->user_id.data || !response->pass_token.data ||
            mhg_secret_buf_set(&candidate_device_id, passport_device_id,
                               strlen(passport_device_id)) != 0 ||
            copy_secret(&candidate_user_id, &response->user_id) != 0 ||
            copy_secret(&candidate_pass_token, &response->pass_token) != 0) {
            mhg_secret_buf_clear(&candidate_device_id);
            mhg_secret_buf_clear(&candidate_user_id);
            mhg_secret_buf_clear(&candidate_pass_token);
            goto internal;
        }
        mhg_secret_buf_clear(&auth->candidate_device_id);
        mhg_secret_buf_clear(&auth->candidate_user_id);
        mhg_secret_buf_clear(&auth->candidate_pass_token);
        auth->candidate_device_id = candidate_device_id;
        auth->candidate_user_id = candidate_user_id;
        auth->candidate_pass_token = candidate_pass_token;
        if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_TOKEN_ROTATE, 0,
                              auth->operation_id, NULL, NULL,
                              &auth->candidate_device_id,
                              &auth->candidate_user_id,
                              &auth->candidate_pass_token,
                              &owner_generation, next) != 0) {
            enter_work_retry(auth, MHG_AUTH_SMS_WORK_TOKEN_ROTATE, 0,
                             MHG_AUTH_SMS_ERROR_INTERNAL);
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        auth->owner_generation = owner_generation;
        auth->phase = MHG_AUTH_SMS_PHASE_TOKEN_ROTATE;
        clear_provider_diagnostic(auth);
        return MHG_AUTH_SMS_ACCEPTED;
    }
internal:
    clear_challenge(auth, true);
    auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
    return MHG_AUTH_SMS_REJECTED_CONFLICT;
protocol:
    clear_challenge(auth, true);
    auth->error = MHG_AUTH_SMS_ERROR_PROTOCOL;
    return MHG_AUTH_SMS_REJECTED_CONFLICT;
}

enum mhg_auth_sms_result mhg_auth_sms_resend(
    struct mhg_auth_sms *auth, uint64_t operation_id, uint64_t now_ms,
    struct mhg_auth_sms_work *work)
{
    enum mhg_auth_sms_result checked;
    uint64_t owner_generation;

    if (!auth || !work) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(work);
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    if (auth->phase != MHG_AUTH_SMS_PHASE_CODE &&
        auth->phase != MHG_AUTH_SMS_PHASE_SEND_UNKNOWN) {
        auth->error = MHG_AUTH_SMS_ERROR_CONFLICT;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (auth->phase == MHG_AUTH_SMS_PHASE_CODE &&
        now_ms < auth->resend_not_before_ms) {
        auth->error = MHG_AUTH_SMS_ERROR_RATE_LIMIT;
        return MHG_AUTH_SMS_REJECTED_RATE_LIMIT;
    }
    if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                          MHG_PASSPORT_SEND_TICKET, operation_id,
                          NULL, NULL, NULL, NULL, NULL, &owner_generation,
                          work) != 0) {
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    auth->owner_generation = owner_generation;
    auth->operation_id = operation_id;
    auth->last_accepted_operation_id = operation_id;
    auth->phase = MHG_AUTH_SMS_PHASE_SEND;
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    clear_provider_diagnostic(auth);
    return MHG_AUTH_SMS_ACCEPTED;
}

enum mhg_auth_sms_result mhg_auth_sms_retry(
    struct mhg_auth_sms *auth, uint64_t operation_id,
    struct mhg_auth_sms_work *work)
{
    enum mhg_auth_sms_result checked;
    enum mhg_auth_sms_phase phase;
    uint64_t owner_generation;

    if (!auth || !work) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(work);
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    if (auth->phase != MHG_AUTH_SMS_PHASE_RETRY ||
        auth->retry_kind == MHG_AUTH_SMS_WORK_NONE) {
        auth->error = MHG_AUTH_SMS_ERROR_CONFLICT;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (auth->retry_kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE) {
        phase = MHG_AUTH_SMS_PHASE_TOKEN_ROTATE;
    } else {
        switch (auth->retry_step) {
        case MHG_PASSPORT_POLICY: phase = MHG_AUTH_SMS_PHASE_POLICY; break;
        case MHG_PASSPORT_PREFERENCE:
            phase = MHG_AUTH_SMS_PHASE_PREFERENCE;
            break;
        case MHG_PASSPORT_PHONE_INFO:
            phase = MHG_AUTH_SMS_PHASE_PHONE_INFO;
            break;
        case MHG_PASSPORT_TICKET_AUTH:
            phase = MHG_AUTH_SMS_PHASE_TICKET_AUTH;
            break;
        case MHG_PASSPORT_SEND_TICKET:
            phase = MHG_AUTH_SMS_PHASE_SEND;
            break;
        default:
            auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
    }
    if (prepare_auth_work(
            auth, auth->retry_kind, auth->retry_step, operation_id,
            NULL, NULL,
            auth->retry_kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE ?
                &auth->candidate_device_id : NULL,
            auth->retry_kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE ?
                &auth->candidate_user_id : NULL,
            auth->retry_kind == MHG_AUTH_SMS_WORK_TOKEN_ROTATE ?
                &auth->candidate_pass_token : NULL,
            &owner_generation, work) != 0) {
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    auth->owner_generation = owner_generation;
    auth->operation_id = operation_id;
    auth->last_accepted_operation_id = operation_id;
    auth->phase = phase;
    auth->retry_kind = MHG_AUTH_SMS_WORK_NONE;
    auth->retry_step = 0;
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    clear_provider_diagnostic(auth);
    return MHG_AUTH_SMS_ACCEPTED;
}

enum mhg_auth_sms_result mhg_auth_sms_verify(
    struct mhg_auth_sms *auth, const char *code, uint64_t operation_id,
    struct mhg_auth_sms_work *work)
{
    enum mhg_auth_sms_result checked;
    struct mhg_secret_buf ticket = MHG_SECRET_BUF_INIT;
    uint64_t owner_generation;
    size_t length;

    if (!auth || !work || !code) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(work);
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    length = strlen(code);
    if (auth->phase != MHG_AUTH_SMS_PHASE_CODE) {
        auth->error = MHG_AUTH_SMS_ERROR_CONFLICT;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (length != auth->code_length || !only_digits(code, length) ||
        mhg_secret_buf_set(&ticket, code, length) != 0) {
        auth->error = MHG_AUTH_SMS_ERROR_INPUT;
        return MHG_AUTH_SMS_REJECTED_INPUT;
    }
    if (prepare_auth_work(auth, MHG_AUTH_SMS_WORK_PASSPORT,
                          MHG_PASSPORT_PHONE_INFO, operation_id,
                          NULL, &ticket, NULL, NULL, NULL, &owner_generation,
                          work) != 0) {
        mhg_secret_buf_clear(&ticket);
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    mhg_secret_buf_clear(&auth->ticket);
    auth->ticket = ticket;
    auth->owner_generation = owner_generation;
    auth->operation_id = operation_id;
    auth->last_accepted_operation_id = operation_id;
    auth->phase = MHG_AUTH_SMS_PHASE_PHONE_INFO;
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    clear_provider_diagnostic(auth);
    return MHG_AUTH_SMS_ACCEPTED;
}

enum mhg_auth_sms_result mhg_auth_sms_cancel(
    struct mhg_auth_sms *auth, uint64_t operation_id)
{
    enum mhg_auth_sms_result checked;

    if (!auth) return MHG_AUTH_SMS_REJECTED_INPUT;
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    auth->last_accepted_operation_id = operation_id;
    clear_challenge(auth, true);
    auth->error = MHG_AUTH_SMS_ERROR_CANCELED;
    return MHG_AUTH_SMS_ACCEPTED;
}

enum mhg_auth_sms_result mhg_auth_sms_expire(
    struct mhg_auth_sms *auth, uint64_t challenge_generation)
{
    if (!auth || auth->phase == MHG_AUTH_SMS_PHASE_IDLE ||
        challenge_generation != auth->challenge_generation)
        return MHG_AUTH_SMS_REJECTED_STALE;
    if (auth->phase == MHG_AUTH_SMS_PHASE_PERSIST)
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    clear_challenge(auth, true);
    auth->error = MHG_AUTH_SMS_ERROR_EXPIRED;
    return MHG_AUTH_SMS_ACCEPTED;
}

static enum mhg_auth_sms_result persist_pending(struct mhg_auth_sms *auth)
{
    int stored;

    if (auth->pending_clear)
        stored = auth->store.ops->clear(
            auth->store.userdata, auth->pending_account.generation);
    else
        stored = auth->store.ops->commit(auth->store.userdata,
                                         &auth->pending_account);
    if (stored != MHG_ACCOUNT_STORE_COMMITTED_DURABLE) {
        if (stored == MHG_ACCOUNT_STORE_COMMITTED_NOT_DURABLE ||
            auth->pending_store_outcome ==
                MHG_AUTH_SMS_PENDING_STORE_COMMITTED_NOT_DURABLE)
            auth->pending_store_outcome =
                MHG_AUTH_SMS_PENDING_STORE_COMMITTED_NOT_DURABLE;
        else
            auth->pending_store_outcome =
                MHG_AUTH_SMS_PENDING_STORE_FAILED_OLD_AUTHORITATIVE;
        if (auth->pending_clear && auth->pending_store_outcome ==
                MHG_AUTH_SMS_PENDING_STORE_COMMITTED_NOT_DURABLE) {
            uint64_t generation = auth->account.generation;
            mhg_account_record_clear(&auth->account);
            auth->account.generation = generation;
            auth->has_account = false;
        }
        auth->phase = MHG_AUTH_SMS_PHASE_PERSIST;
        auth->retry_kind = MHG_AUTH_SMS_WORK_NONE;
        auth->retry_step = 0;
        auth->error = MHG_AUTH_SMS_ERROR_STORAGE;
        return MHG_AUTH_SMS_REJECTED_STORAGE;
    }
    if (auth->pending_clear) {
        uint64_t generation = auth->pending_account.generation;
        mhg_account_record_clear(&auth->account);
        auth->account.generation = generation;
        auth->has_account = false;
    } else {
        mhg_account_record_clear(&auth->account);
        auth->account = auth->pending_account;
        auth->pending_account =
            (struct mhg_account_record)MHG_ACCOUNT_RECORD_INIT;
        auth->has_account = true;
    }
    if (auth->operation_id > auth->last_accepted_operation_id)
        auth->last_accepted_operation_id = auth->operation_id;
    clear_challenge(auth, true);
    auth->error = MHG_AUTH_SMS_ERROR_NONE;
    return MHG_AUTH_SMS_ACCEPTED;
}

enum mhg_auth_sms_result mhg_auth_sms_clear(
    struct mhg_auth_sms *auth, uint64_t operation_id)
{
    enum mhg_auth_sms_result checked;
    uint64_t generation;

    if (!auth) return MHG_AUTH_SMS_REJECTED_INPUT;
    if (persist_is_uncertain(auth))
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    checked = check_operation(auth, operation_id);
    if (checked != MHG_AUTH_SMS_ACCEPTED) return checked;
    generation = next_generation(auth->account.generation);
    if (generation == 0u) {
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    clear_challenge(auth, false);
    auth->pending_account.generation = generation;
    auth->pending_clear = true;
    auth->pending_store_outcome = MHG_AUTH_SMS_PENDING_STORE_NONE;
    auth->operation_id = operation_id;
    return persist_pending(auth);
}

enum mhg_auth_sms_result mhg_auth_sms_retry_persist(
    struct mhg_auth_sms *auth, uint64_t challenge_generation,
    uint64_t operation_id)
{
    if (!auth || auth->phase != MHG_AUTH_SMS_PHASE_PERSIST ||
        auth->challenge_generation != challenge_generation ||
        auth->operation_id != operation_id)
        return MHG_AUTH_SMS_REJECTED_STALE;
    return persist_pending(auth);
}

enum mhg_auth_sms_result mhg_auth_sms_complete_rotation(
    struct mhg_auth_sms *auth,
    const struct mhg_auth_sms_work *completed,
    enum mhg_cloud_error cloud_error,
    const char *rotated_device_id,
    const char *rotated_user_id,
    const char *rotated_pass_token,
    const struct mhg_auth_sms_provider_diagnostic *provider,
    struct mhg_auth_sms_work *next)
{
    struct mhg_account_record candidate = MHG_ACCOUNT_RECORD_INIT;
    size_t user_len;
    size_t token_len;
    size_t device_len;

    if (!next) return MHG_AUTH_SMS_REJECTED_INPUT;
    mhg_auth_sms_work_clear(next);
    if (!auth || !completed || auth->phase != MHG_AUTH_SMS_PHASE_TOKEN_ROTATE ||
        !valid_completion(auth, completed, MHG_AUTH_SMS_WORK_TOKEN_ROTATE, 0))
        return MHG_AUTH_SMS_REJECTED_STALE;
    if (provider &&
        (provider->scope != MHG_AUTH_SMS_PROVIDER_SCOPE_TOKEN_LOGIN ||
         provider->provider_code == 0 ||
         (provider->provider_class ==
              MHG_AUTH_SMS_PROVIDER_CREDENTIAL_REJECTED &&
          cloud_error != MHG_CLOUD_AUTH_REJECTED) ||
         (provider->provider_class == MHG_AUTH_SMS_PROVIDER_OTHER &&
          cloud_error != MHG_CLOUD_SERVICE) ||
         (provider->provider_class !=
              MHG_AUTH_SMS_PROVIDER_CREDENTIAL_REJECTED &&
          provider->provider_class != MHG_AUTH_SMS_PROVIDER_OTHER))) {
        provider = NULL;
        cloud_error = MHG_CLOUD_MALFORMED;
    }
    if (cloud_error != MHG_CLOUD_OK) {
        if (provider)
            set_provider_diagnostic(auth, provider->scope,
                                    provider->provider_class,
                                    provider->provider_code);
        else
            clear_provider_diagnostic(auth);
        if (cloud_failure_can_retry_without_sms(cloud_error)) {
            auth->phase = MHG_AUTH_SMS_PHASE_RETRY;
            auth->retry_kind = MHG_AUTH_SMS_WORK_TOKEN_ROTATE;
            auth->retry_step = 0;
            auth->operation_id = 0u;
            auth->error = cloud_error_map(cloud_error);
            return MHG_AUTH_SMS_REJECTED_CONFLICT;
        }
        clear_challenge(auth, true);
        if (provider)
            set_provider_diagnostic(auth, provider->scope,
                                    provider->provider_class,
                                    provider->provider_code);
        auth->error = cloud_error_map(cloud_error);
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    clear_provider_diagnostic(auth);
    device_len = rotated_device_id ? strlen(rotated_device_id) : 0u;
    user_len = rotated_user_id ? strlen(rotated_user_id) : 0u;
    token_len = rotated_pass_token ? strlen(rotated_pass_token) : 0u;
    if (!rotated_device_id || !rotated_user_id || !rotated_pass_token ||
        !mhg_passport_device_id_is_valid(
            (const unsigned char *)rotated_device_id, device_len) ||
        auth->candidate_device_id.len != device_len ||
        memcmp(auth->candidate_device_id.data, rotated_device_id,
               device_len) != 0 || user_len == 0u ||
        token_len == 0u || !only_digits(rotated_user_id, user_len) ||
        auth->candidate_user_id.len != user_len ||
        memcmp(auth->candidate_user_id.data, rotated_user_id, user_len) != 0) {
        clear_challenge(auth, true);
        auth->error = MHG_AUTH_SMS_ERROR_PROTOCOL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    candidate.generation = next_generation(auth->account.generation);
    if (candidate.generation == 0u) {
        clear_challenge(auth, true);
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    if (mhg_secret_buf_set(&candidate.device_id, rotated_device_id,
                           device_len) != 0 ||
        mhg_secret_buf_set(&candidate.user_id, rotated_user_id, user_len) != 0 ||
        mhg_secret_buf_set(&candidate.pass_token, rotated_pass_token,
                           token_len) != 0) {
        mhg_account_record_clear(&candidate);
        clear_challenge(auth, true);
        auth->error = MHG_AUTH_SMS_ERROR_INTERNAL;
        return MHG_AUTH_SMS_REJECTED_CONFLICT;
    }
    mhg_account_record_clear(&auth->pending_account);
    auth->pending_account = candidate;
    auth->pending_clear = false;
    auth->pending_store_outcome = MHG_AUTH_SMS_PENDING_STORE_NONE;
    clear_flow_secrets(auth);
    return persist_pending(auth);
}

void mhg_auth_sms_get_status(const struct mhg_auth_sms *auth,
                             uint64_t now_ms,
                             struct mhg_auth_sms_status *status)
{
    uint64_t remaining = 0u;

    if (!status) return;
    memset(status, 0, sizeof(*status));
    if (!auth) return;
    status->phase = auth->phase;
    status->error = auth->error;
    status->has_account = auth->has_account;
    status->account_generation = auth->account.generation;
    status->challenge_generation = auth->challenge_generation;
    status->owner_generation = auth->owner_generation;
    status->operation_id = auth->operation_id;
    status->last_accepted_operation_id =
        auth->last_accepted_operation_id;
    status->pending_account_generation =
        auth->pending_account.generation;
    status->pending_store_outcome = auth->pending_store_outcome;
    status->code_length = auth->code_length;
    status->provider_scope = auth->provider_scope;
    status->provider_class = auth->provider_class;
    status->provider_code = auth->provider_code;
    if (auth->resend_not_before_ms > now_ms)
        remaining = auth->resend_not_before_ms - now_ms;
    status->retry_after_seconds = remaining >
        (uint64_t)UINT_MAX * 1000u ? UINT_MAX :
        (unsigned int)((remaining + 999u) / 1000u);
    if (auth->phase == MHG_AUTH_SMS_PHASE_PERSIST)
        status->state = MHG_AUTH_SMS_PERSIST_PENDING;
    else if (auth->phase == MHG_AUTH_SMS_PHASE_RETRY)
        status->state = MHG_AUTH_SMS_RETRY_REQUIRED;
    else if (auth->phase == MHG_AUTH_SMS_PHASE_SEND_UNKNOWN)
        status->state = MHG_AUTH_SMS_SEND_UNKNOWN;
    else if (auth->phase == MHG_AUTH_SMS_PHASE_CODE)
        status->state = MHG_AUTH_SMS_CODE_REQUIRED;
    else if (auth->phase != MHG_AUTH_SMS_PHASE_IDLE)
        status->state = MHG_AUTH_SMS_WORKING;
    else
        status->state = auth->has_account ? MHG_AUTH_SMS_AUTHENTICATED :
                                           MHG_AUTH_SMS_NEEDS_AUTHORIZATION;
}

/* Stable state and phase names for the Bridge (§10.1): the frontend never
 * parses localized text to decide a flow. */
const char *mhg_auth_sms_state_name(enum mhg_auth_sms_state state)
{
    switch (state) {
    case MHG_AUTH_SMS_NEEDS_AUTHORIZATION: return "needs_authorization";
    case MHG_AUTH_SMS_WORKING: return "working";
    case MHG_AUTH_SMS_CODE_REQUIRED: return "code_required";
    case MHG_AUTH_SMS_AUTHENTICATED: return "authenticated";
    case MHG_AUTH_SMS_PERSIST_PENDING: return "persist_pending";
    case MHG_AUTH_SMS_RETRY_REQUIRED: return "retry_required";
    case MHG_AUTH_SMS_SEND_UNKNOWN: return "send_unknown";
    }
    return "unknown";
}

const char *mhg_auth_sms_phase_name(enum mhg_auth_sms_phase phase)
{
    switch (phase) {
    case MHG_AUTH_SMS_PHASE_IDLE: return "idle";
    case MHG_AUTH_SMS_PHASE_POLICY: return "policy";
    case MHG_AUTH_SMS_PHASE_PREFERENCE: return "preference";
    case MHG_AUTH_SMS_PHASE_SEND: return "send";
    case MHG_AUTH_SMS_PHASE_CODE: return "code";
    case MHG_AUTH_SMS_PHASE_PHONE_INFO: return "phone_info";
    case MHG_AUTH_SMS_PHASE_TICKET_AUTH: return "ticket_auth";
    case MHG_AUTH_SMS_PHASE_TOKEN_ROTATE: return "token_rotate";
    case MHG_AUTH_SMS_PHASE_PERSIST: return "persist";
    case MHG_AUTH_SMS_PHASE_RETRY: return "retry";
    case MHG_AUTH_SMS_PHASE_SEND_UNKNOWN: return "send_unknown";
    }
    return "unknown";
}

const char *mhg_auth_sms_error_name(enum mhg_auth_sms_error error)
{
    switch (error) {
    case MHG_AUTH_SMS_ERROR_NONE: return "none";
    case MHG_AUTH_SMS_ERROR_INPUT: return "input";
    case MHG_AUTH_SMS_ERROR_CONFLICT: return "conflict";
    case MHG_AUTH_SMS_ERROR_RATE_LIMIT: return "rate_limit";
    case MHG_AUTH_SMS_ERROR_CODE_INVALID_OR_EXPIRED:
        return "sms_code_invalid_or_expired";
    case MHG_AUTH_SMS_ERROR_UNSUPPORTED_CHALLENGE:
        return "unsupported_challenge";
    case MHG_AUTH_SMS_ERROR_PROVIDER: return "provider";
    case MHG_AUTH_SMS_ERROR_NETWORK: return "network";
    case MHG_AUTH_SMS_ERROR_PROTOCOL: return "protocol";
    case MHG_AUTH_SMS_ERROR_INTERNAL: return "internal";
    case MHG_AUTH_SMS_ERROR_STORAGE: return "storage";
    case MHG_AUTH_SMS_ERROR_EXPIRED: return "expired";
    case MHG_AUTH_SMS_ERROR_CANCELED: return "canceled";
    case MHG_AUTH_SMS_ERROR_HTTP: return "http";
    }
    return NULL;
}

const char *mhg_auth_sms_provider_scope_name(
    enum mhg_auth_sms_provider_scope scope)
{
    switch (scope) {
    case MHG_AUTH_SMS_PROVIDER_SCOPE_NONE: return "none";
    case MHG_AUTH_SMS_PROVIDER_SCOPE_PASSPORT: return "passport";
    case MHG_AUTH_SMS_PROVIDER_SCOPE_TOKEN_LOGIN: return "token_login";
    }
    return "unknown";
}

const char *mhg_auth_sms_provider_class_name(
    enum mhg_auth_sms_provider_class provider_class)
{
    switch (provider_class) {
    case MHG_AUTH_SMS_PROVIDER_NONE: return "none";
    case MHG_AUTH_SMS_PROVIDER_SMS_SEND_LIMIT_TOMORROW:
        return "sms_send_limit_tomorrow";
    case MHG_AUTH_SMS_PROVIDER_SMS_CODE_INVALID_OR_EXPIRED:
        return "sms_code_invalid_or_expired";
    case MHG_AUTH_SMS_PROVIDER_ADDITIONAL_VERIFICATION_REQUIRED:
        return "additional_verification_required";
    case MHG_AUTH_SMS_PROVIDER_CREDENTIAL_REJECTED:
        return "credential_rejected";
    case MHG_AUTH_SMS_PROVIDER_OTHER: return "other";
    }
    return "unknown";
}

const char *mhg_auth_sms_status_message_key(const struct mhg_auth_sms_status *status)
{
    if (!status) return "";
    if (status->provider_class != MHG_AUTH_SMS_PROVIDER_NONE)
        return mhg_auth_sms_provider_class_name(status->provider_class);
    if (status->error == MHG_AUTH_SMS_ERROR_RATE_LIMIT)
        return MHG_AUTH_SMS_KEY_RETRY_LATER;
    return "";
}
