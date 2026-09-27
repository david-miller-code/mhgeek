#ifndef MHGEEK_EVENT_CONFIG_STORE_H
#define MHGEEK_EVENT_CONFIG_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "cloud_wire_types.h"
#include "presence_delivery.h"

/* The persisted event configuration (§7.3/§9.1): one trimmed global prefix and
 * one present/absent text per slot. The value written to the hub is the direct
 * concatenation `prefix + text`; no separator is inserted. */
#define MHG_EVENT_PREFIX_LIMIT 32u
#define MHG_EVENT_TEXT_LIMIT 64u
#define MHG_EVENT_CONFIG_LIMIT 8192u

struct mhg_event_config {
    uint64_t generation;
    double absent_seconds[MHG_PRESENCE_SLOT_COUNT];
    struct mhg_secret_buf prefix;
    /* Index slot * 2 + (present ? 0 : 1). */
    struct mhg_secret_buf texts[MHG_PRESENCE_SLOT_COUNT * 2u];
};

#define MHG_EVENT_CONFIG_INIT                                                          \
    {                                                                                  \
        0u, {1, 1, 1, 1, 1, 1, 1, 1, 1}, MHG_SECRET_BUF_INIT,                          \
        {                                                                              \
            MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT,             \
                MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT,         \
                MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT,         \
                MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT,         \
                MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT,         \
                MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT, MHG_SECRET_BUF_INIT          \
        }                                                                              \
    }

enum mhg_event_config_load_result {
    MHG_EVENT_CONFIG_ERROR = -1,
    MHG_EVENT_CONFIG_ABSENT = 0,
    MHG_EVENT_CONFIG_PRESENT = 1,
    /* Numeric legacy durations were repaired in memory; persist before use. */
    MHG_EVENT_CONFIG_NEEDS_REPAIR = 2,
};

enum mhg_event_config_commit_result {
    MHG_EVENT_CONFIG_FAILED = -1,
    MHG_EVENT_CONFIG_COMMITTED_DURABLE = 0,
    MHG_EVENT_CONFIG_COMMITTED_NOT_DURABLE = 1,
};

/* One text must be printable UTF-8 without control characters, bounded in
 * bytes; the same predicate guards the Bridge input and the persisted file. */
/* Whole seconds >= 1; protocol milliseconds must remain JSON safe integers. */
int mhg_event_config_seconds_valid(double seconds);

int mhg_event_config_text_is_valid(const char *text, size_t limit);

/* `<data_root>/events.json`; the private directory itself is prepared by the
 * account/target/resource stores of the same data root. */
int mhg_event_config_prepare(const char *data_root, char *path, size_t path_size);
int mhg_event_config_load(const char *path, struct mhg_event_config *config);
int mhg_event_config_commit(const char *path, const struct mhg_event_config *config);
int mhg_event_config_clear(const char *path);
void mhg_event_config_dispose(struct mhg_event_config *config);

/* Deep copy: the destination owns its own buffers. A §7.4 request only carries
 * the fields the frontend sent, so the transaction applies it onto a copy of
 * the running configuration and can still roll back to the original. */
int mhg_event_config_clone(struct mhg_event_config *destination,
                           const struct mhg_event_config *source);

/* Builds the 18 final texts (prefix + text) the hub and the emitter use. The
 * output buffers must hold MHG_EVENT_PREFIX_LIMIT + MHG_EVENT_TEXT_LIMIT + 1
 * bytes each. */
int mhg_event_config_final_texts(
    const struct mhg_event_config *config,
    char (*final)[MHG_EVENT_PREFIX_LIMIT + MHG_EVENT_TEXT_LIMIT + 1u],
    const char **pointers, size_t count);
#ifdef MHG_EVENT_CONFIG_TESTING
void mhg_event_config_test_fail_parent_sync_once(void);
#endif

#endif
