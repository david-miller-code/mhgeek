#include "rc4_drop1024.h"

#include <errno.h>
#include <stdint.h>

static void secure_clear(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;

    while (size-- > 0u) *bytes++ = 0u;
}

int mhg_rc4_drop1024(const unsigned char *key, size_t key_len,
                     const unsigned char *input, size_t input_len,
                     unsigned char *output)
{
    unsigned char state[256];
    unsigned int i;
    unsigned int j = 0u;
    size_t offset;

    if (!key || key_len == 0u || key_len > 256u ||
        (input_len != 0u && (!input || !output))) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0u; i < 256u; ++i) state[i] = (unsigned char)i;
    for (i = 0u; i < 256u; ++i) {
        unsigned char swap;

        j = (j + state[i] + key[i % key_len]) & 0xffu;
        swap = state[i];
        state[i] = state[j];
        state[j] = swap;
    }

    i = 0u;
    j = 0u;
    for (offset = 0u; offset < 1024u; ++offset) {
        unsigned char swap;

        i = (i + 1u) & 0xffu;
        j = (j + state[i]) & 0xffu;
        swap = state[i];
        state[i] = state[j];
        state[j] = swap;
        (void)state[(state[i] + state[j]) & 0xffu];
    }

    for (offset = 0u; offset < input_len; ++offset) {
        unsigned char swap;
        unsigned char stream;

        i = (i + 1u) & 0xffu;
        j = (j + state[i]) & 0xffu;
        swap = state[i];
        state[i] = state[j];
        state[j] = swap;
        stream = state[(state[i] + state[j]) & 0xffu];
        output[offset] = input[offset] ^ stream;
    }

    secure_clear(state, sizeof(state));
    return 0;
}
