#ifndef MHGEEK_JPAKE_H
#define MHGEEK_JPAKE_H

#include "common.h"

struct mhg_jpake;

/* Client-only, single-use exchange. All operations return 0 or -1.
 * Output buffers must be zero-initialized and cleared with mhg_buf_clear().
 * Input/output round payloads exclude the outer protocol type byte.
 * Invalid peer data permanently invalidates the exchange. After secret() the
 * caller owns the 32-byte secret and must cleanse it when no longer needed.
 * The caller retains responsibility for cleansing its passcode input.
 */
struct mhg_jpake *mhg_jpake_new(const char *passcode, struct mhg_error *error);
void mhg_jpake_free(struct mhg_jpake *party);
int mhg_jpake_round_one(struct mhg_jpake *party, struct mhg_buf *out,
                        struct mhg_error *error);
int mhg_jpake_read_round_one(struct mhg_jpake *party, const unsigned char *data,
                             size_t length, struct mhg_error *error);
int mhg_jpake_round_two(struct mhg_jpake *party, struct mhg_buf *out,
                        struct mhg_error *error);
int mhg_jpake_read_round_two(struct mhg_jpake *party, const unsigned char *data,
                             size_t length, struct mhg_error *error);
int mhg_jpake_secret(struct mhg_jpake *party, unsigned char out[32],
                     struct mhg_error *error);

#endif
