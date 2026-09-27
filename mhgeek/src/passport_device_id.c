#include "passport_device_id.h"

#include <openssl/rand.h>

#include <errno.h>
#include <string.h>

static int lower_hex(unsigned char value)
{
    return value >= (unsigned char)'0' && value <= (unsigned char)'9' ? 1 :
           value >= (unsigned char)'a' && value <= (unsigned char)'f';
}

bool mhg_passport_device_id_is_valid(const unsigned char *value,
                                     size_t length)
{
    size_t index;

    if (!value || length != MHG_PASSPORT_DEVICE_ID_LENGTH ||
        memcmp(value, "wb_", 3u) != 0 || value[11] != '-' ||
        value[16] != '-' || value[21] != '-' || value[26] != '-' ||
        value[17] != '4' ||
        (value[22] != '8' && value[22] != '9' &&
         value[22] != 'a' && value[22] != 'b'))
        return false;
    for (index = 3u; index < length; ++index) {
        if (index == 11u || index == 16u || index == 21u || index == 26u)
            continue;
        if (!lower_hex(value[index])) return false;
    }
    return true;
}

int mhg_passport_device_id_generate(
    char output[MHG_PASSPORT_DEVICE_ID_SIZE])
{
    static const char hex[] = "0123456789abcdef";
    static const size_t groups[] = {4u, 2u, 2u, 2u, 6u};
    unsigned char bytes[16];
    size_t byte_index = 0u;
    size_t output_index = 3u;
    size_t group;

    if (!output) {
        errno = EINVAL;
        return -1;
    }
    memset(output, 0, MHG_PASSPORT_DEVICE_ID_SIZE);
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) {
        OPENSSL_cleanse(bytes, sizeof(bytes));
        OPENSSL_cleanse(output, MHG_PASSPORT_DEVICE_ID_SIZE);
        errno = EIO;
        return -1;
    }
    bytes[6] = (unsigned char)((bytes[6] & 0x0fu) | 0x40u);
    bytes[8] = (unsigned char)((bytes[8] & 0x3fu) | 0x80u);
    memcpy(output, "wb_", 3u);
    for (group = 0u; group < sizeof(groups) / sizeof(groups[0]); ++group) {
        size_t count;
        if (group != 0u) output[output_index++] = '-';
        for (count = 0u; count < groups[group]; ++count) {
            unsigned char byte = bytes[byte_index++];
            output[output_index++] = hex[byte >> 4u];
            output[output_index++] = hex[byte & 0x0fu];
        }
    }
    output[output_index] = '\0';
    OPENSSL_cleanse(bytes, sizeof(bytes));
    if (!mhg_passport_device_id_is_valid((const unsigned char *)output,
                                         output_index)) {
        OPENSSL_cleanse(output, MHG_PASSPORT_DEVICE_ID_SIZE);
        errno = EIO;
        return -1;
    }
    return 0;
}
