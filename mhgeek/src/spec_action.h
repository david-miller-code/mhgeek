#ifndef MHGEEK_SPEC_ACTION_H
#define MHGEEK_SPEC_ACTION_H

#include "common.h"

/* The Action parameters are never taken from a table: they are derived from the
 * target's own Spec, exactly like the hub's own page does
 * (`miot-spec.org/miot-spec-v2/instance?type=<urn>`), and the digest step
 * binds the resource set to that Spec generation. */
struct mhg_spec_action {
    int siid;
    int aiid;
    int piid;
};

int mhg_spec_action_derive(const char *urn, const char *ca_info,
                           struct mhg_spec_action *action,
                           struct mhg_error *error);

/* Exposed for offline tests: turns one Spec document into the single
 * string-input Action, or fails when the Spec does not have exactly one. */
int mhg_spec_action_from_json(const char *spec_json, size_t length,
                              struct mhg_spec_action *action,
                              struct mhg_error *error);

#endif
