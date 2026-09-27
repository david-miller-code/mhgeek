#ifndef MHGEEK_EMIT_LAN_H
#define MHGEEK_EMIT_LAN_H

#include <cjson/cJSON.h>

#include "cloud_wire_types.h"
#include "common.h"
#include "presence_delivery.h"
#include "resource_store.h"

/* One v3 state submission is two ordered writes to the same graph-local
 * number variable: neutral=2, then present=1 or absent=0. The second
 * setVarValue business ACK is the delivery boundary. No Action log or value
 * readback participates in the product path. */
struct mhg_emit_lan_ops {
    int (*call)(void *userdata, const char *method, const cJSON *params,
                cJSON **reply, struct mhg_error *error);
};

struct mhg_emit_lan_config {
    struct mhg_emit_lan_ops ops;
    void *userdata;
    const struct mhg_resource_record *record;
};

#define MHG_EMIT_LAN_CONFIG_INIT {{NULL}, NULL, NULL}

struct mhg_emit_lan;

int mhg_emit_lan_create(struct mhg_emit_lan **owner_out,
                        const struct mhg_emit_lan_config *config);
void mhg_emit_lan_destroy(struct mhg_emit_lan *owner);
int mhg_emit_lan_replace_record(struct mhg_emit_lan *owner,
                                const struct mhg_resource_record *record);
int mhg_emit_lan_send(void *userdata, enum mhg_presence_slot slot,
                      bool present, struct mhg_error *error);

#endif
