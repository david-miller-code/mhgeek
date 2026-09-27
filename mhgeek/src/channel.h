#ifndef MHGEEK_CHANNEL_H
#define MHGEEK_CHANNEL_H

#include "common.h"

/* One instance per direction, replaced after the 24-byte key exchange. */
struct mhg_cipher {
    unsigned char key[16];
    unsigned char salt[8];
    uint32_t counter;
};

void mhg_cipher_init(struct mhg_cipher *cipher, const unsigned char material[24]);
void mhg_cipher_clear(struct mhg_cipher *cipher);
int mhg_encrypt(struct mhg_cipher *cipher, const void *plain, size_t length,
                struct mhg_buf *out, struct mhg_error *error);
int mhg_decrypt(struct mhg_cipher *cipher, const void *wire, size_t length,
                struct mhg_buf *out, struct mhg_error *error);
int mhg_pack_json(const char *json, size_t length, size_t budget,
                  struct mhg_buf *out, struct mhg_error *error);
/* Unpacked output includes a terminating NUL; len includes that NUL. */
int mhg_unpack_json(const void *wire, size_t length, size_t budget,
                    struct mhg_buf *out, struct mhg_error *error);

#endif
