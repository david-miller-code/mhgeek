#ifndef MHGEEK_SECRET_JSON_H
#define MHGEEK_SECRET_JSON_H

#include <cjson/cJSON.h>

#include <stddef.h>

/* Secret-bearing JSON forbids raw embedded NUL bytes and JSON string
 * escapes that decode to NUL. This keeps C string length and secure clearing
 * aligned with the complete decoded value. */
cJSON *mhg_secret_json_parse(const char *text);
cJSON *mhg_secret_json_parse_len(const unsigned char *text, size_t length);

/* Clears string keys and values before releasing a tree that may contain
 * account, catalog, core, or decrypted response material. */
void mhg_secret_json_delete(cJSON *value);

#endif
