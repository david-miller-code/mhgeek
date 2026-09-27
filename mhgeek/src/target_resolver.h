#ifndef MHGEEK_TARGET_RESOLVER_H
#define MHGEEK_TARGET_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core_bootstrap.h"
#include "xiaomi_service.h"
#include "xiaomiio_catalog.h"
#include "target_store.h"

/* The user-directed target decision. A submission is resolved exactly once —
 * directory lookup, online-prioritized capability probes — and then the
 * binding is persisted and locked. Nothing here re-queries, backs off or polls;
 * changing the address starts with an explicit clear. */
enum mhg_target_state {
    /* No usable target: nothing submitted yet, unusable input, or a binding
     * that names a different directory entry than the address. */
    MHG_TARGET_STATE_DECISION_REQUIRED = 0,
    /* Submitted, but this attempt did not confirm a target. */
    MHG_TARGET_STATE_UNRESOLVED = 1,
    /* Verified and persisted; every further run uses this identity only. */
    MHG_TARGET_STATE_LOCKED = 2,
};

enum mhg_target_outcome {
    MHG_TARGET_OUTCOME_NONE = 0,
    MHG_TARGET_OUTCOME_CATALOG = 1,
    MHG_TARGET_OUTCOME_NOT_FOUND = 2,
    MHG_TARGET_OUTCOME_AMBIGUOUS = 3,
    MHG_TARGET_OUTCOME_CONFLICT = 4,
    MHG_TARGET_OUTCOME_PROBE = 5,
    MHG_TARGET_OUTCOME_STORE = 6,
    /* A refreshed directory no longer confirms the persisted identity. */
    MHG_TARGET_OUTCOME_DRIFTED = 7,
    MHG_TARGET_OUTCOME_INPUT = 8,
};

/* Observable work: the directory is queried only for an accepted submission,
 * and probes run only for entries matching the submitted address. */
struct mhg_target_resolver_stats {
    uint64_t submissions;
    uint64_t catalog_queries;
    uint64_t probes;
    uint64_t locked_rejections;
};

#define MHG_TARGET_RESOLVER_STATS_INIT {0u, 0u, 0u, 0u}

struct mhg_target_resolver_config {
    struct mhg_catalog_config catalog;
    struct mhg_bootstrap_config bootstrap;
    /* `<data root>/target.json`, built by mhg_target_store_prepare. */
    const char *target_path;
    /* Overall candidate capability phase budget, including in-flight RPCs. */
    unsigned long probe_timeout_ms;
};

#define MHG_TARGET_RESOLVER_CONFIG_INIT \
    {MHG_CATALOG_CONFIG_INIT, MHG_BOOTSTRAP_CONFIG_INIT, NULL, 30000ul}

struct mhg_target_resolver;

int mhg_target_resolver_create(struct mhg_target_resolver **owner_out,
                               const struct mhg_target_resolver_config *config);
void mhg_target_resolver_destroy(struct mhg_target_resolver *owner);

/* Loads the persisted binding: LOCKED when one was stored, otherwise
 * DECISION_REQUIRED. A record that cannot be read is reported as an error and
 * leaves the resolver at DECISION_REQUIRED with MHG_TARGET_OUTCOME_STORE. */
enum mhg_cloud_error mhg_target_resolver_begin(
    struct mhg_target_resolver *owner);

/* Recover an uncertain target-store install or clear. A surviving record is
 * re-committed durably; a clear that left no file is completed with another
 * directory fsync before returning to DECISION_REQUIRED. No LAN or Spec
 * request is made here. */
enum mhg_cloud_error mhg_target_resolver_recover_store(
    struct mhg_target_resolver *owner);

/* Resolves one submission. Sessions that do not own their leg are refused
 * before any work or state change, and a locked resolver refuses the write
 * before any I/O. MHG_CLOUD_OK means the target is now LOCKED; every other
 * return leaves the state and outcome describing why the attempt stopped. */
enum mhg_cloud_error mhg_target_resolver_submit(
    struct mhg_target_resolver *owner,
    const struct mhg_service_session *xiaomiio_session,
    const struct mhg_service_session *mijia_session, const char *ip,
    const char *did);

/* Confirms the persisted identity against a freshly refreshed snapshot: the
 * stored DID must exist with the same model and the same address. On failure
 * the target stays locked and the caller stops for the user to clear it. */
enum mhg_cloud_error mhg_target_resolver_verify(
    struct mhg_target_resolver *owner,
    const struct mhg_catalog_snapshot *snapshot,
    const struct mhg_catalog_device **matched_out);

/* Under the resolver lock, promote the currently selected DID/model to a
 * verified Action using the LAN URN and strictly derived online Spec tuple.
 * Repeated identical verification is idempotent; a different verified tuple
 * is drift, never a silent replacement. */
enum mhg_cloud_error mhg_target_resolver_commit_action(
    struct mhg_target_resolver *owner, const char *did, const char *model,
    const char *urn, int siid, int aiid, int piid);

/* Refreshes the directory snapshot for startup guidance or the reconnect path.
 * The directory is still queried only at these allowed moments, never on a
 * timer; a failure stops the caller with a CATALOG outcome. */
enum mhg_cloud_error mhg_target_resolver_refresh_catalog(
    struct mhg_target_resolver *owner,
    const struct mhg_service_session *xiaomiio_session);

/* Re-runs the cloud bootstrap for the persisted identity (§5.6 reconnect):
 * the target's accessKey comes from the refreshed snapshot, and a fresh
 * URL/passcode pair replaces the in-memory evidence of the previous bootstrap
 * generation. The binding itself is untouched, and a snapshot that no longer
 * confirms it reports DRIFTED without any probe. */
enum mhg_cloud_error mhg_target_resolver_refresh_bootstrap(
    struct mhg_target_resolver *owner,
    const struct mhg_catalog_snapshot *snapshot,
    const struct mhg_service_session *mijia_session);

/* Ends the binding: the address may be submitted again and nothing else is
 * touched. The account, both sessions and the catalog snapshot survive. */
/* Drop account-bound memory after the authorization store revokes binding.
 * The authorization transaction owns persistence and crash recovery. */
void mhg_target_resolver_forget_authorization(struct mhg_target_resolver *owner);
enum mhg_cloud_error mhg_target_resolver_clear(
    struct mhg_target_resolver *owner);

enum mhg_target_state mhg_target_resolver_state(
    const struct mhg_target_resolver *owner);
enum mhg_target_outcome mhg_target_resolver_outcome(
    const struct mhg_target_resolver *owner);
enum mhg_cloud_error mhg_target_resolver_last_error(
    const struct mhg_target_resolver *owner);
/* The persisted identity of a locked target, or NULL. */
const struct mhg_target_record *mhg_target_resolver_record(
    const struct mhg_target_resolver *owner);
/* The directory snapshot published by the last successful query, or NULL when
 * no query has been published. Borrowed: it stays readable until the next
 * submit, and its `accessKey` values live in memory only. */
const struct mhg_catalog_snapshot *mhg_target_resolver_snapshot(
    const struct mhg_target_resolver *owner);
/* Directory and probe measurements of this owner, for the status surface.
 * Both writers zero the output for a NULL owner. */
void mhg_target_resolver_catalog_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_catalog_stats *stats);
void mhg_target_resolver_bootstrap_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_bootstrap_stats *stats);
/* The memory-only URL and passcode of the accepted probe, or NULL when there
 * is nothing to hand to the LAN stage. */
const struct mhg_bootstrap_evidence *mhg_target_resolver_evidence(
    const struct mhg_target_resolver *owner);
void mhg_target_resolver_stats_get(
    const struct mhg_target_resolver *owner,
    struct mhg_target_resolver_stats *stats);

const char *mhg_target_outcome_name(enum mhg_target_outcome outcome);
const char *mhg_target_state_name(enum mhg_target_state state);

#endif
