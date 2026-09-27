#ifndef MHGEEK_SESSION_H
#define MHGEEK_SESSION_H

#include "transport.h"
#include <cjson/cJSON.h>

struct mhg_session;

/* A session borrows transport and has one serial owner. The caller must free
 * the session before closing transport. No passcode or session key is saved.
 * deadline is an absolute monotonic deadline in milliseconds; phase points to
 * a static diagnostic string, including on failure. */
struct mhg_session *mhg_session_open(struct mhg_transport *transport,
                                      const char *passcode, size_t budget,
                                      uint64_t deadline, const char **phase,
                                      struct mhg_error *error);
void mhg_session_free(struct mhg_session *session);

/* params is a borrowed JSON object/array, or NULL for an empty object.
 * On success, *reply is an owned complete JSON-RPC response; the caller uses
 * cJSON_Delete. A JSON-RPC error response is also success and keeps the session
 * usable. A protocol, transport or timeout failure permanently invalidates it.
 * Notifications are validated and ignored while awaiting the matching response.
 * The caller supplies a fresh deadline for each call and initializes *reply to
 * NULL. Requests use consecutive numeric ids starting at 1. */
int mhg_session_call(struct mhg_session *session, const char *method,
                       const cJSON *params, uint64_t deadline, cJSON **reply,
                       struct mhg_error *error);

/* Asynchronous pair used by the long-lived LAN owner (§6.7), so a scheduler
 * step never blocks on a round trip. send() returns the request id without
 * waiting; poll() consumes only frames that are already available and reports
 * the matching reply exactly once through *ready. The caller must keep polling
 * (or close the connection) until the reply arrives: a request that was sent
 * and then abandoned leaves its result unknown, and a session whose
 * conversation may still be in flight must not be reused for a new request.
 * Any protocol, crypto or envelope failure invalidates the session. */
int mhg_session_send(struct mhg_session *session, const char *method,
                     const cJSON *params, uint64_t *id_out, uint64_t deadline,
                     struct mhg_error *error);
int mhg_session_poll(struct mhg_session *session, uint64_t id, cJSON **reply,
                     int *ready, uint64_t deadline, struct mhg_error *error);

/* Nonblocking idle service. It pumps control frames and consumes only strict,
 * id-less JSON-RPC notifications. Partial WebSocket messages remain buffered
 * in the transport. Any close, transport, crypto, or envelope error invalidates
 * the session. */
int mhg_session_service_idle(struct mhg_session *session, uint64_t deadline,
                             struct mhg_error *error);

/* Strict complete JSON with unique object keys and no decoded NUL strings.
 * The returned JSON is owned by the caller. Input need not be NUL terminated. */
cJSON *mhg_session_parse_json(const unsigned char *data, size_t length,
                              uint64_t deadline, struct mhg_error *error);

/* Authenticates once and issues only /api/getDevList. No state-changing RPC.
 * phase points to a static diagnostic string, including on failure. */
int mhg_probe_devices(struct mhg_transport *transport, const char *passcode,
                       size_t budget, uint64_t deadline, size_t *device_count,
                       const char **phase, struct mhg_error *error);

#endif
