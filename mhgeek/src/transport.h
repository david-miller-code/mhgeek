#ifndef MHGEEK_TRANSPORT_H
#define MHGEEK_TRANSPORT_H

#include "common.h"

struct mhg_transport;

/* The process owns curl_global_init/cleanup. A transport has one serial owner.
 * HTTP(S) and WS(S) base URLs map to the fixed /centrallinkws/ endpoint.
 * The caller explicitly supplies the maximum complete binary message size.
 * Any I/O failure invalidates the connection; close it before opening another.
 */
struct mhg_transport *mhg_transport_open(
    const char *base_url, size_t max_message, uint64_t deadline,
    const volatile sig_atomic_t *stop, struct mhg_error *error);
int mhg_transport_send(struct mhg_transport *transport, const void *data,
                       size_t length, uint64_t deadline,
                       struct mhg_error *error);
/* Nonblocking receive pump. It consumes currently available control/data
 * frames, preserving partial binary messages across calls. On success,
 * *complete is 1 only when out was replaced with one whole binary message;
 * CURLE_AGAIN and control-only input return *complete == 0. The caller must
 * pass an empty out buffer so ownership remains unambiguous on no-data. */
int mhg_transport_pump(struct mhg_transport *transport, struct mhg_buf *out,
                       int *complete, struct mhg_error *error);
/* Success replaces any previous out buffer with one whole message. */
int mhg_transport_receive(struct mhg_transport *transport, struct mhg_buf *out,
                          uint64_t deadline, struct mhg_error *error);
void mhg_transport_close(struct mhg_transport *transport);

#endif
