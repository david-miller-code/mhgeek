#ifndef MHGEEK_PASSPORT_DEVICE_ID_H
#define MHGEEK_PASSPORT_DEVICE_ID_H

#include <stdbool.h>
#include <stddef.h>

#define MHG_PASSPORT_DEVICE_ID_LENGTH 39u
#define MHG_PASSPORT_DEVICE_ID_SIZE (MHG_PASSPORT_DEVICE_ID_LENGTH + 1u)

/* Xiaomi Passport web device identity: wb_ followed by a lower-case UUIDv4.
 * The value is credential material and must be cleared with the other account
 * secrets after use. */
bool mhg_passport_device_id_is_valid(const unsigned char *value,
                                     size_t length);
int mhg_passport_device_id_generate(
    char output[MHG_PASSPORT_DEVICE_ID_SIZE]);

#endif
