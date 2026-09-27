#include "app.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ainice/protocol_error_codes.h"
#include "checked_json.h"
#include "json_strict.h"

int mhg_app_set_json(ainice_bridge_response_t *response, cJSON *root)
{
    char *text;
    int result;

    if (!root) root = mhg_app_error(AINICE_PROTOCOL_ERROR_INTERNAL_ERROR,
                                    "out of memory");
    if (!root) return -1;
    text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) return -1;
    if (strlen(text) > MHG_APP_RESPONSE_MAX) {
        cJSON_free(text);
        return mhg_app_set_json(
            response, mhg_app_error(AINICE_PROTOCOL_ERROR_INTERNAL_ERROR,
                                    "bridge response is too large"));
    }
    result = ainice_bridge_response_json(response, text);
    cJSON_free(text);
    return result;
}

static int set_error(ainice_bridge_response_t *response, int code,
                     const char *message)
{
    return mhg_app_set_json(response, mhg_app_error(code, message));
}

/* `{module, method, params}`; the routes live behind `route`. */
int mhg_app_bridge_request(const char *request_json,
                           ainice_bridge_response_t *response, void *userdata)
{
    struct mhg_bridge_context *context = userdata;
    cJSON *request = NULL;
    cJSON *params = NULL;
    const char *method;
    uint64_t deadline_ms = 0u;
    int saved;
    int result;

    if (subsys_json_deadline_after_ms(MHG_APP_BRIDGE_JSON_TIMEOUT_MS,
                                      &deadline_ms) != 0)
        return set_error(response, AINICE_PROTOCOL_ERROR_INTERNAL_ERROR,
                         "JSON deadline unavailable");
    request = subsys_json_parse_strict_deadline(request_json, deadline_ms);
    if (!request || !cJSON_IsObject(request)) {
        saved = errno;
        cJSON_Delete(request);
        return set_error(response,
                         saved == ENOMEM ?
                             AINICE_PROTOCOL_ERROR_NO_MEMORY :
                         saved == ETIMEDOUT ?
                             AINICE_PROTOCOL_ERROR_TIMEOUT :
                             AINICE_PROTOCOL_ERROR_BAD_REQUEST,
                         "invalid bridge request");
    }
    method = cJSON_GetStringValue(
        cJSON_GetObjectItemCaseSensitive(request, "method"));
    params = cJSON_GetObjectItemCaseSensitive(request, "params");
    if (!method || !method[0]) {
        cJSON_Delete(request);
        return set_error(response,
                         AINICE_PROTOCOL_ERROR_BRIDGE_METHOD_REQUIRED,
                         "bridge method is required");
    }
    if (params && !cJSON_IsObject(params)) {
        cJSON_Delete(request);
        return set_error(response, AINICE_PROTOCOL_ERROR_BRIDGE_PARAMS_INVALID,
                         "bridge params must be an object");
    }
    if (strcmp(method, "health.get") == 0) {
        cJSON *root = cJSON_CreateObject();

        if (!root ||
            subsys_json_add_string(root, "status", "ok") != 0 ||
            subsys_json_add_string(root, "module", MHG_APP_MODULE) != 0) {
            cJSON_Delete(root);
            cJSON_Delete(request);
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_INTERNAL_ERROR,
                             "out of memory");
        }
        cJSON_Delete(request);
        return mhg_app_set_json(response, root);
    }
    if (strcmp(method, "route") == 0) {
        const char *path = params ?
            cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(params,
                                                                 "path")) : NULL;
        const char *http_method = params ?
            cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(
                params, "http_method")) : NULL;
        cJSON *query = params ?
            cJSON_GetObjectItemCaseSensitive(params, "query") : NULL;
        cJSON *body = params ?
            cJSON_GetObjectItemCaseSensitive(params, "body") : NULL;
        cJSON *root;

        if (!path || path[0] != '/') {
            cJSON_Delete(request);
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_ROUTE_PATH_INVALID,
                             "route path must be an absolute path");
        }
        if (!http_method || !http_method[0]) {
            cJSON_Delete(request);
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_ROUTE_METHOD_REQUIRED,
                             "route http_method is required");
        }
        if (query && !cJSON_IsObject(query)) {
            cJSON_Delete(request);
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_ROUTE_QUERY_INVALID,
                             "route query must be an object");
        }
        if (body && !cJSON_IsObject(body)) {
            cJSON_Delete(request);
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_ROUTE_BODY_INVALID,
                             "route body must be an object");
        }
        root = mhg_app_route(context, http_method, path, query, body);
        cJSON_Delete(request);
        if (!root)
            return set_error(response,
                             AINICE_PROTOCOL_ERROR_ROUTE_NOT_FOUND,
                             "route not found");
        result = mhg_app_set_json(response, root);
        return result;
    }
    cJSON_Delete(request);
    return set_error(response, AINICE_PROTOCOL_ERROR_UNSUPPORTED_BRIDGE_METHOD,
                     "unsupported bridge method");
}
