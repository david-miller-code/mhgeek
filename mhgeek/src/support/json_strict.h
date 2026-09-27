#ifndef AINICE_JSON_STRICT_H
#define AINICE_JSON_STRICT_H

#include <stdint.h>

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parses one complete JSON value and rejects duplicate object keys at depth. */
cJSON *subsys_json_parse_strict(const char *text);
cJSON *subsys_json_parse_strict_deadline(const char *text,
                                         uint64_t deadline_ms);

int subsys_json_deadline_after_ms(unsigned int timeout_ms,
                                  uint64_t *deadline_ms);

/* Validates recursively that every object in an already parsed value has unique keys. */
int subsys_json_value_has_unique_keys(const cJSON *value);
int subsys_json_value_has_unique_keys_deadline(const cJSON *value,
                                               uint64_t deadline_ms);

#ifdef SUBSYS_JSON_STRICT_TESTING
/* Forces the next parse to fail as an allocator would, with errno=ENOMEM. */
void subsys_json_strict_test_fail_next_parse_allocation(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
