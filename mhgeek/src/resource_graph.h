#ifndef MHGEEK_RESOURCE_GRAPH_H
#define MHGEEK_RESOURCE_GRAPH_H
#include "resource_lan.h"
#define MHG_GRAPH_LEFT 480.0
/* Pure generation and comparison. No remote values enter configuration. */
cJSON *mhg_resource_graph_build(const struct mhg_resource_lan_config *config,
                                const struct mhg_resource_record *record, bool enabled,
                                struct mhg_error *error);
bool mhg_resource_graph_nodes_match(const cJSON *desired, const cJSON *actual,
                                    bool functional_only);
int mhg_resource_graph_digest(const cJSON *nodes, char digest[33]);
#endif
