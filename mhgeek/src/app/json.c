/* Stable Bridge error envelope. Kept free of SDK symbols so the route
 * layer is exercised offline without libainice. */
#include "app.h"

#include <errno.h>

#include "ainice/protocol_error_codes.h"
#include "checked_json.h"

cJSON *mhg_app_error(int code, const char *message)
{
    const char *key = "invalid_request";
    switch (code) {
    case AINICE_PROTOCOL_ERROR_UNAUTHORIZED: key = "unauthorized"; break;
    case AINICE_PROTOCOL_ERROR_BUSY: key = "busy"; break;
    case AINICE_PROTOCOL_ERROR_NOT_AVAILABLE: key = "unavailable"; break;
    case AINICE_PROTOCOL_ERROR_CONFLICT: key = "target_locked"; break;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *error = cJSON_CreateObject();
    cJSON *details = cJSON_CreateObject();

    if (!root || !error || !details ||
        subsys_json_add_number(error, "code", code) != 0 ||
        subsys_json_add_string(error, "error_code", key) != 0 ||
        subsys_json_add_string(error, "message",
                               message ? message : "error") != 0 ||
        subsys_json_add_string(details, "reason",
                               message ? message : "error") != 0 ||
        subsys_json_attach_object(error, "details", &details) != 0 ||
        subsys_json_attach_object(root, "error", &error) != 0) {
        cJSON_Delete(details);
        cJSON_Delete(error);
        cJSON_Delete(root);
        errno = ENOMEM;
        return NULL;
    }
    return root;
}
