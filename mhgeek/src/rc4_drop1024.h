#ifndef MHGEEK_RC4_DROP1024_H
#define MHGEEK_RC4_DROP1024_H

#include <stddef.h>

/*
 * Applies RC4 after discarding exactly the first 1024 keystream bytes.
 * Input and output may point to the same buffer. This primitive deliberately
 * does not own Xiaomi key derivation, base64, signing, or HTTP framing.
 */
int mhg_rc4_drop1024(const unsigned char *key, size_t key_len,
                     const unsigned char *input, size_t input_len,
                     unsigned char *output);

#endif
