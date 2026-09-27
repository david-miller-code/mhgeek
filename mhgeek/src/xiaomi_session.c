#include "xiaomi_session.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "https_client.h"
#include "passport_wire.h"
#include "xiaomi_account_url.h"

struct selected_cookie {
    const char *name;
    struct mhg_secret_buf value;
    size_t path_length;
    bool found;
};

struct mhg_xiaomi_session {
    struct mhg_https_client *client;
    enum mhg_xiaomi_sid sid;
    struct mhg_xiaomi_session_config config;
    pthread_mutex_t lock;
    struct mhg_service_session session;
    bool has_session;
    enum mhg_xiaomi_session_state state;
    struct mhg_xiaomi_session_stats stats;
};

struct mhg_xiaomi_sessions {
    struct mhg_xiaomi_session *sessions[2];
};

static int sid_index(enum mhg_xiaomi_sid sid)
{
    if (sid == MHG_XIAOMI_SID_XIAOMIIO) return 0;
    if (sid == MHG_XIAOMI_SID_MIJIA) return 1;
    return -1;
}

static void selected_cookies_clear(struct selected_cookie *selected,
                                   size_t count)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        mhg_secret_buf_clear(&selected[index].value);
        selected[index].path_length = 0u;
        selected[index].found = false;
    }
}

static int merge_selected_cookies(struct selected_cookie *destination,
                                  const struct selected_cookie *source,
                                  size_t count)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        if (!source[index].found) continue;
        if (mhg_secret_buf_set(&destination[index].value,
                               source[index].value.data,
                               source[index].value.len) != 0)
            return -1;
        destination[index].found = true;
        destination[index].path_length = source[index].path_length;
    }
    return 0;
}

static int session_url_is_trusted(const void *context, const char *url)
{
    return mhg_service_redirect_is_trusted(*(const enum mhg_xiaomi_sid *)context,
                                           url);
}

static int append_text(struct mhg_secret_buf *buffer, const void *data,
                       size_t length)
{
    unsigned char *grown;
    size_t total;
    if (!buffer || (!data && length != 0u) ||
        length > SIZE_MAX - buffer->len - 1u)
        return -1;
    total = buffer->len + length;
    grown = OPENSSL_realloc(buffer->data, total + 1u);
    if (!grown) return -1;
    buffer->data = grown;
    if (length) memcpy(buffer->data + buffer->len, data, length);
    buffer->len = total;
    buffer->data[total] = '\0';
    return 0;
}

static int append_cstr(struct mhg_secret_buf *buffer, const char *text)
{
    return append_text(buffer, text, strlen(text));
}

static int append_pair(struct mhg_secret_buf *output, const char *name,
                       const char *value)
{
    if (append_cstr(output, name) != 0 || append_cstr(output, "=") != 0 ||
        append_cstr(output, value) != 0)
        return -1;
    return 0;
}

static enum mhg_cloud_error collect_sts_cookies(
    struct mhg_xiaomi_session *owner, const char *url,
    struct selected_cookie *selected, size_t selected_count)
{
    struct curl_slist *cookies = NULL;
    struct curl_slist *item;
    const char *request_path = NULL;
    size_t request_path_length = 0u;
    enum mhg_cloud_error result;
    size_t index;

    if (!owner || !selected || selected_count == 0u ||
        mhg_service_sts_request_path(owner->sid, url, &request_path,
                                     &request_path_length) != 0)
        return MHG_CLOUD_INPUT;
    selected_cookies_clear(selected, selected_count);
    result = mhg_https_client_cookie_list(owner->client, &cookies);
    if (result != MHG_CLOUD_OK) return result;
    result = MHG_CLOUD_OK;
    for (item = cookies; item; item = item->next) {
        const char *fields[7];
        size_t lengths[7];
        const char *cursor = item->data;
        unsigned int field;

        if (!cursor) continue;
        for (field = 0u; field < 6u; ++field) {
            const char *tab;
            fields[field] = cursor;
            tab = strchr(cursor, '\t');
            if (!tab) break;
            lengths[field] = (size_t)(tab - cursor);
            cursor = tab + 1u;
        }
        if (field != 6u) continue;
        fields[6] = cursor;
        lengths[6] = strlen(cursor);
        if (!mhg_service_cookie_domain_matches(owner->sid, fields[0],
                                               lengths[0]) ||
            !mhg_service_cookie_path_matches(fields[2], lengths[2],
                                             request_path,
                                             request_path_length))
            continue;
        for (index = 0u; index < selected_count; ++index) {
            if (!selected[index].name ||
                strlen(selected[index].name) != lengths[5] ||
                memcmp(fields[5], selected[index].name, lengths[5]) != 0)
                continue;
            /* An empty Set-Cookie value never overrides a typed non-empty
             * candidate; the typed parser rejects the result when a required
             * cookie has no non-empty value left. */
            if (lengths[6] == 0u) break;
            if (selected[index].found &&
                selected[index].path_length == lengths[2]) {
                if (selected[index].value.len != lengths[6] ||
                    memcmp(selected[index].value.data, fields[6],
                           lengths[6]) != 0)
                    result = MHG_CLOUD_MALFORMED;
                break;
            }
            if (!selected[index].found ||
                lengths[2] > selected[index].path_length) {
                if (mhg_secret_buf_set(&selected[index].value, fields[6],
                                       lengths[6]) != 0)
                    result = MHG_CLOUD_INTERNAL;
                else {
                    selected[index].found = true;
                    selected[index].path_length = lengths[2];
                }
            }
            break;
        }
        if (result != MHG_CLOUD_OK) break;
    }
    mhg_https_client_free_cookie_list(cookies);
    if (result != MHG_CLOUD_OK)
        selected_cookies_clear(selected, selected_count);
    return result;
}

static enum mhg_cloud_error build_token_login_url(
    const struct mhg_xiaomi_session *owner, struct mhg_secret_buf *url)
{
    const struct mhg_service_login_request_contract *contract =
        mhg_service_login_request_contract();
    const char *sid_name = mhg_xiaomi_sid_name(owner->sid);

    if (!contract || !sid_name ||
        append_cstr(url, owner->config.service_base_url ?
                         owner->config.service_base_url :
                         mhg_service_login_base_url()) != 0 ||
        append_cstr(url, contract->path) != 0 ||
        append_cstr(url, "?") != 0)
        return MHG_CLOUD_INTERNAL;
    if (append_pair(url, contract->json_query_name,
                    contract->json_query_value) != 0 ||
        append_cstr(url, "&") != 0 ||
        append_pair(url, contract->sid_query_name, sid_name) != 0)
        return MHG_CLOUD_INTERNAL;
    return MHG_CLOUD_OK;
}

/* Follows the token-login location chain with the SID's own STS host as the
 * only accepted redirect target, then publishes the resulting session. */
static enum mhg_cloud_error finish_redirect_chain(
    struct mhg_xiaomi_session *owner, const struct mhg_service_login *login,
    const char *user_id, struct curl_slist *headers, uint64_t deadline,
    struct mhg_service_session *published)
{
    struct selected_cookie selected[] = {
        {"userId", MHG_SECRET_BUF_INIT, 0u, false},
        {"cUserId", MHG_SECRET_BUF_INIT, 0u, false},
        {"serviceToken", MHG_SECRET_BUF_INIT, 0u, false},
        {"passToken", MHG_SECRET_BUF_INIT, 0u, false},
    };
    struct mhg_cookie_pair pairs[] = {
        {"userId", NULL}, {"cUserId", NULL}, {"serviceToken", NULL},
        {"passToken", NULL},
    };
    struct mhg_secret_buf current_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf next_url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf extension_pragma = MHG_SECRET_BUF_INIT;
    struct mhg_https_response response = MHG_HTTPS_RESPONSE_INIT;
    struct mhg_service_session session = MHG_SERVICE_SESSION_INIT;
    unsigned int redirects = 0u;
    enum mhg_cloud_error result;
    size_t index;

    result = mhg_secret_buf_set(&current_url, login->location.data,
                                login->location.len) == 0 ?
        MHG_CLOUD_OK : MHG_CLOUD_INTERNAL;
    if (result != MHG_CLOUD_OK) goto out;
    for (;;) {
        struct selected_cookie hop[] = {
            {"userId", MHG_SECRET_BUF_INIT, 0u, false},
            {"cUserId", MHG_SECRET_BUF_INIT, 0u, false},
            {"serviceToken", MHG_SECRET_BUF_INIT, 0u, false},
            {"passToken", MHG_SECRET_BUF_INIT, 0u, false},
        };
        struct mhg_https_request request = MHG_HTTPS_REQUEST_INIT;
        long status = 0;

        request.url = (const char *)current_url.data;
        request.method = "GET";
        request.headers = headers;
        request.accept_redirect = true;
        request.reject_auth_status = true;
        request.deadline = deadline;
        owner->stats.redirect_requests++;
        result = mhg_https_client_perform(owner->client, &request, &response,
                                          &status);
        owner->stats.last_http_status = status;
        if (result == MHG_CLOUD_OK)
            result = collect_sts_cookies(owner, (const char *)current_url.data,
                                         hop, sizeof(hop) / sizeof(hop[0]));
        if (result == MHG_CLOUD_OK &&
            merge_selected_cookies(selected, hop,
                                   sizeof(hop) / sizeof(hop[0])) != 0)
            result = MHG_CLOUD_INTERNAL;
        selected_cookies_clear(hop, sizeof(hop) / sizeof(hop[0]));
        if (result != MHG_CLOUD_OK) goto out;
        if (response.extension_pragma.len != 0u &&
            mhg_secret_buf_set(&extension_pragma,
                               response.extension_pragma.data,
                               response.extension_pragma.len) != 0) {
            result = MHG_CLOUD_INTERNAL;
            goto out;
        }
        if (mhg_https_client_clear_jar(owner->client) != 0) {
            result = MHG_CLOUD_NOT_DISPATCHED;
            goto out;
        }
        if (status >= 200 && status < 300) break;
        if (status < 300 || status >= 400 ||
            redirects >= MHG_SERVICE_MAX_REDIRECT_HOPS ||
            !response.location.data) {
            result = MHG_CLOUD_MALFORMED;
            goto out;
        }
        result = mhg_https_resolve_redirect(
            (const char *)current_url.data,
            (const char *)response.location.data, &owner->sid,
            session_url_is_trusted, &next_url);
        if (result != MHG_CLOUD_OK) goto out;
        mhg_secret_buf_clear(&current_url);
        current_url = next_url;
        next_url = (struct mhg_secret_buf)MHG_SECRET_BUF_INIT;
        ++redirects;
        mhg_https_response_clear(&response);
    }
    for (index = 0u; index < sizeof(pairs) / sizeof(pairs[0]); ++index)
        if (selected[index].found)
            pairs[index].value = (const char *)selected[index].value.data;
    result = mhg_service_finish_redirect(
        login, user_id, pairs, sizeof(pairs) / sizeof(pairs[0]),
        MHG_BYTES_VIEW(extension_pragma.data, extension_pragma.len), &session);
    if (result != MHG_CLOUD_OK) goto out;
    mhg_service_session_clear(published);
    *published = session;
    session = (struct mhg_service_session)MHG_SERVICE_SESSION_INIT;

out:
    selected_cookies_clear(selected, sizeof(selected) / sizeof(selected[0]));
    mhg_https_response_clear(&response);
    mhg_service_session_clear(&session);
    mhg_secret_buf_clear(&current_url);
    mhg_secret_buf_clear(&next_url);
    mhg_secret_buf_clear(&extension_pragma);
    return result;
}

int mhg_xiaomi_session_create(struct mhg_xiaomi_session **owner_out,
                              enum mhg_xiaomi_sid sid,
                              const struct mhg_xiaomi_session_config *config)
{
    struct mhg_xiaomi_session *owner;
    struct mhg_https_client_config http = MHG_HTTPS_CLIENT_CONFIG_INIT;

    if (owner_out) *owner_out = NULL;
    if (!owner_out || !config || !mhg_xiaomi_sid_name(sid)) return -1;
    if (!mhg_https_url_is_trusted_for_exact_host(
            config->service_base_url ? config->service_base_url :
                                       mhg_service_login_base_url(),
            "account.xiaomi.com"))
        return -1;
    owner = calloc(1u, sizeof(*owner));
    if (!owner) return -1;
    owner->sid = sid;
    owner->config = *config;
    owner->state = MHG_XIAOMI_SESSION_EMPTY;
    owner->session = (struct mhg_service_session)MHG_SERVICE_SESSION_INIT;
    owner->stats.last_error = MHG_CLOUD_OK;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return -1;
    }
    http.ca_info = config->ca_info;
    http.connect_timeout_ms = config->connect_timeout_ms;
    http.total_timeout_ms = config->total_timeout_ms;
    http.response_limit = config->response_limit;
    http.allow_system_proxy = config->allow_system_proxy;
    for (size_t index = 0u; index < 4u; ++index)
        http.connect_to[index] = config->connect_to[index];
    if (mhg_https_client_create(&owner->client, &http) != 0) {
        pthread_mutex_destroy(&owner->lock);
        free(owner);
        return -1;
    }
    *owner_out = owner;
    return 0;
}

void mhg_xiaomi_session_destroy(struct mhg_xiaomi_session *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    mhg_https_client_destroy(owner->client);
    mhg_service_session_clear(&owner->session);
    pthread_mutex_unlock(&owner->lock);
    pthread_mutex_destroy(&owner->lock);
    mhg_secure_clear(owner, sizeof(*owner));
    free(owner);
}

enum mhg_xiaomi_sid mhg_xiaomi_session_sid(
    const struct mhg_xiaomi_session *owner)
{
    return owner ? owner->sid : (enum mhg_xiaomi_sid)0;
}

enum mhg_cloud_error mhg_xiaomi_session_establish(
    struct mhg_xiaomi_session *owner, const char *user_id,
    const char *pass_token)
{
    const struct mhg_service_login_request_contract *contract;
    struct mhg_service_login login = MHG_SERVICE_LOGIN_INIT;
    struct mhg_service_provider_diagnostic diagnostic =
        MHG_SERVICE_PROVIDER_DIAGNOSTIC_INIT;
    struct mhg_service_session session = MHG_SERVICE_SESSION_INIT;
    struct mhg_secret_buf url = MHG_SECRET_BUF_INIT;
    struct mhg_secret_buf cookie = MHG_SECRET_BUF_INIT;
    struct mhg_https_response response = MHG_HTTPS_RESPONSE_INIT;
    struct mhg_https_request request = MHG_HTTPS_REQUEST_INIT;
    struct curl_slist *headers = NULL;
    uint64_t deadline;
    long status = 0;
    enum mhg_cloud_error result;

    if (!owner || !user_id || !pass_token || !pass_token[0])
        return MHG_CLOUD_INPUT;
    contract = mhg_service_login_request_contract();
    if (!contract) return MHG_CLOUD_INTERNAL;
    pthread_mutex_lock(&owner->lock);
    owner->stats.last_error = MHG_CLOUD_OK;
    owner->stats.provider_class = MHG_SERVICE_PROVIDER_NONE;
    owner->stats.provider_code = 0;
    owner->stats.last_http_status = 0;
    owner->stats.establishes++;
    result = build_token_login_url(owner, &url);
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_service_login_cookie_header(user_id, pass_token, &cookie);
    if (result != MHG_CLOUD_OK) goto out;
    headers = mhg_https_client_append_header(headers, "User-Agent",
                                             mhg_passport_client_user_agent());
    if (!headers) {
        result = MHG_CLOUD_INTERNAL;
        goto out;
    }
    if (mhg_https_client_clear_jar(owner->client) != 0) {
        result = MHG_CLOUD_NOT_DISPATCHED;
        goto out;
    }
    deadline = mhg_https_now_ms() + owner->config.total_timeout_ms;
    request.url = (const char *)url.data;
    request.method = contract->method;
    request.headers = headers;
    request.cookie = (const char *)cookie.data;
    request.reject_auth_status = true;
    request.deadline = deadline;
    owner->stats.token_login_requests++;
    result = mhg_https_client_perform(owner->client, &request, &response,
                                      &status);
    owner->stats.last_http_status = status;
    if (result != MHG_CLOUD_OK) goto out;
    result = mhg_service_parse_token_login(
        owner->sid, MHG_BYTES_VIEW(response.data, response.len), &login,
        &diagnostic);
    owner->stats.provider_class = diagnostic.provider_class;
    owner->stats.provider_code = diagnostic.provider_code;
    if (result != MHG_CLOUD_OK) goto out;
    /* The candidate pair must not survive into the redirect chain. */
    if (mhg_https_client_clear_jar(owner->client) != 0) {
        result = MHG_CLOUD_NOT_DISPATCHED;
        goto out;
    }
    result = finish_redirect_chain(owner, &login, user_id, headers, deadline,
                                   &session);
    if (result != MHG_CLOUD_OK) goto out;
    mhg_service_session_clear(&owner->session);
    owner->session = session;
    session = (struct mhg_service_session)MHG_SERVICE_SESSION_INIT;
    owner->has_session = true;
    owner->state = MHG_XIAOMI_SESSION_ACTIVE;
    owner->stats.session_generation++;
    owner->stats.consecutive_rejections = 0u;

out:
    if (result == MHG_CLOUD_AUTH_REJECTED) {
        mhg_service_session_clear(&owner->session);
        owner->has_session = false;
        if (owner->stats.consecutive_rejections < UINT64_MAX)
            owner->stats.consecutive_rejections++;
        owner->state = owner->stats.consecutive_rejections >= 2u ?
            MHG_XIAOMI_SESSION_CREDENTIALS_SUSPECT :
            MHG_XIAOMI_SESSION_EMPTY;
    }
    owner->stats.last_error = result;
    mhg_https_response_clear(&response);
    mhg_https_client_free_headers(headers);
    mhg_secret_buf_clear(&url);
    mhg_secret_buf_clear(&cookie);
    mhg_service_login_clear(&login);
    mhg_service_session_clear(&session);
    pthread_mutex_unlock(&owner->lock);
    return result;
}

const struct mhg_service_session *mhg_xiaomi_session_current(
    const struct mhg_xiaomi_session *owner)
{
    return owner && owner->has_session ? &owner->session : NULL;
}

enum mhg_xiaomi_session_state mhg_xiaomi_session_state(
    const struct mhg_xiaomi_session *owner)
{
    return owner ? owner->state : MHG_XIAOMI_SESSION_EMPTY;
}

const char *mhg_xiaomi_session_state_name(enum mhg_xiaomi_session_state state)
{
    switch (state) {
    case MHG_XIAOMI_SESSION_EMPTY: return "empty";
    case MHG_XIAOMI_SESSION_ACTIVE: return "active";
    case MHG_XIAOMI_SESSION_CREDENTIALS_SUSPECT:
        return "credentials_suspect";
    }
    return NULL;
}

void mhg_xiaomi_session_invalidate(struct mhg_xiaomi_session *owner)
{
    if (!owner) return;
    pthread_mutex_lock(&owner->lock);
    mhg_service_session_clear(&owner->session);
    owner->has_session = false;
    if (owner->state == MHG_XIAOMI_SESSION_ACTIVE)
        owner->state = MHG_XIAOMI_SESSION_EMPTY;
    pthread_mutex_unlock(&owner->lock);
}

void mhg_xiaomi_session_stats_get(const struct mhg_xiaomi_session *owner,
                                  struct mhg_xiaomi_session_stats *stats)
{
    if (!stats) return;
    *stats = owner ? owner->stats : (struct mhg_xiaomi_session_stats)
        MHG_XIAOMI_SESSION_STATS_INIT;
}

int mhg_xiaomi_sessions_create(struct mhg_xiaomi_sessions **sessions_out,
                               const struct mhg_xiaomi_session_config *config)
{
    static const enum mhg_xiaomi_sid sids[2] = {
        MHG_XIAOMI_SID_XIAOMIIO, MHG_XIAOMI_SID_MIJIA,
    };
    struct mhg_xiaomi_sessions *sessions;
    size_t index;

    if (sessions_out) *sessions_out = NULL;
    if (!sessions_out || !config) return -1;
    sessions = calloc(1u, sizeof(*sessions));
    if (!sessions) return -1;
    for (index = 0u; index < 2u; ++index) {
        if (mhg_xiaomi_session_create(&sessions->sessions[index], sids[index],
                                      config) != 0)
            goto failed;
    }
    *sessions_out = sessions;
    return 0;

failed:
    mhg_xiaomi_sessions_destroy(sessions);
    return -1;
}

void mhg_xiaomi_sessions_destroy(struct mhg_xiaomi_sessions *sessions)
{
    size_t index;
    if (!sessions) return;
    for (index = 0u; index < 2u; ++index)
        mhg_xiaomi_session_destroy(sessions->sessions[index]);
    mhg_secure_clear(sessions, sizeof(*sessions));
    free(sessions);
}

struct mhg_xiaomi_session *mhg_xiaomi_sessions_owner(
    struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid)
{
    int slot = sid_index(sid);
    if (!sessions || slot < 0) return NULL;
    return sessions->sessions[slot];
}

enum mhg_cloud_error mhg_xiaomi_sessions_establish_both(
    struct mhg_xiaomi_sessions *sessions, const char *user_id,
    const char *pass_token)
{
    static const enum mhg_xiaomi_sid sids[2] = {
        MHG_XIAOMI_SID_XIAOMIIO, MHG_XIAOMI_SID_MIJIA,
    };
    enum mhg_cloud_error first = MHG_CLOUD_OK;
    size_t index;

    if (!sessions) return MHG_CLOUD_INPUT;
    for (index = 0u; index < 2u; ++index) {
        int slot = sid_index(sids[index]);
        enum mhg_cloud_error result;
        if (slot < 0) return MHG_CLOUD_INTERNAL;
        result = mhg_xiaomi_session_establish(sessions->sessions[slot],
                                              user_id, pass_token);
        if (result != MHG_CLOUD_OK && first == MHG_CLOUD_OK) first = result;
    }
    return first;
}

enum mhg_cloud_error mhg_xiaomi_sessions_rebuild(
    struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid,
    const char *user_id, const char *pass_token)
{
    int slot = sid_index(sid);
    if (!sessions || slot < 0) return MHG_CLOUD_INPUT;
    mhg_xiaomi_session_invalidate(sessions->sessions[slot]);
    return mhg_xiaomi_session_establish(sessions->sessions[slot], user_id,
                                        pass_token);
}

void mhg_xiaomi_sessions_invalidate(struct mhg_xiaomi_sessions *sessions,
                                    enum mhg_xiaomi_sid sid)
{
    int slot = sid_index(sid);
    if (!sessions || slot < 0) return;
    mhg_xiaomi_session_invalidate(sessions->sessions[slot]);
}

const struct mhg_service_session *mhg_xiaomi_sessions_current(
    const struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid)
{
    int slot = sid_index(sid);
    if (!sessions || slot < 0) return NULL;
    return mhg_xiaomi_session_current(sessions->sessions[slot]);
}

enum mhg_xiaomi_session_state mhg_xiaomi_sessions_state(
    const struct mhg_xiaomi_sessions *sessions, enum mhg_xiaomi_sid sid)
{
    int slot = sid_index(sid);
    if (!sessions || slot < 0) return MHG_XIAOMI_SESSION_EMPTY;
    return mhg_xiaomi_session_state(sessions->sessions[slot]);
}

bool mhg_xiaomi_sessions_bootstrap_ready(
    const struct mhg_xiaomi_sessions *sessions)
{
    size_t index;
    if (!sessions) return false;
    for (index = 0u; index < 2u; ++index) {
        const struct mhg_xiaomi_session *owner = sessions->sessions[index];
        if (!owner || owner->state != MHG_XIAOMI_SESSION_ACTIVE ||
            !owner->has_session)
            return false;
    }
    return true;
}
