/* Explicit wire vocabulary shared by page projections and operation tracking. */
export const AUTH = Object.freeze({
  needs_authorization: { pane: "unauthorized", label: "unauthorized" },
  authenticated: { pane: "authenticated", label: "authorized" },
  code_required: { pane: "unauthorized", label: "authCodeRequired" },
  working: { pane: "pending", label: "authWorking", hint: "working" },
  persist_pending: { pane: "pending", label: "authPersistPending", hint: "persistPending" },
  retry_required: { pane: "pending", label: "authRetryRequired", hint: "retryRequired" },
  send_unknown: { pane: "pending", label: "authSendUnknown", hint: "sendUnknown" }
});
export const GATEWAY_LABEL = Object.freeze({
  credentials_required: "stateCredentialsRequired", target_required: "stateTargetRequired",
  offline: "stateOffline", cloud_required: "stateCloudRequired", connecting: "stateConnecting",
  resources: "stateResources", ready: "stateReady", delivery_paused: "stateDeliveryPaused",
  stopped: "stateStopped"
});
export const ERROR_LABEL = Object.freeze({
  other: "providerRejected",
  invalid_absent_seconds: "invalidAbsentSeconds",
  superseded: "operationSuperseded",
  cancelled: "operationCancelled",
  target_catalog_failed: "targetCatalogError", target_not_found: "targetNotFoundError",
  target_ambiguous: "targetAmbiguousError", target_conflict: "targetConflictError",
  target_probe_failed: "targetProbeError",
  cloud_failed: "cloudFailed", target_failed: "targetFailed", store_failed: "storeFailed",
  sync_failed: "syncFailed", auth_failed: "authFailed",
  unauthorized: "authorizationRequired",
  target_locked: "targetLocked",
  sms_send_limit_tomorrow: "sms_send_limit_tomorrow",
  sms_code_invalid_or_expired: "sms_code_invalid_or_expired",
  additional_verification_required: "additional_verification_required",
  credential_rejected: "credential_rejected", sms_retry_later: "sms_retry_later",
  rate_limit: "rate_limit", phone_account_not_found: "phone_account_not_found"
});
export const OPERATION_LABEL = Object.freeze({
  queued: "operationQueued", running: "operationRunning", waiting_sync: "operationSyncing",
  succeeded: "operationSucceeded", failed: "operationFailed", superseded: "operationSuperseded"
});
export function mayConfigure(auth, pending) {
  return !pending && auth.has_account === true && auth.state_name === "authenticated";
}
export function authView(state) {
  return AUTH[state] || { pane: "pending", label: "stateUnknown", hint: "stateUnknown" };
}
export function gatewayLabel(status) {
  if (status.resources?.state_name === "presentation_pending") return "statePresentationPending";
  return status.resources?.state_name === "drifted" ? "stateResourceDrift" :
    GATEWAY_LABEL[status.state_name] || "stateUnknown";
}
export function validAbsentSeconds(value) {
  return Number.isSafeInteger(value) && value >= 1 &&
    Number.isSafeInteger(value * 1000);
}

const TARGET_ERROR_LABEL = Object.freeze({
  catalog: "targetCatalogError", not_found: "targetNotFoundError",
  ambiguous: "targetAmbiguousError", conflict: "targetConflictError",
  drifted: "targetConflictError", probe: "targetProbeError",
  store: "storeFailed", input: "invalidTargetIp"
});
export function targetErrorLabel(outcome) {
  return TARGET_ERROR_LABEL[outcome] || "targetFailed";
}

export function validTargetIp(value) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/.test(value);
}

/* Only stable business vocabulary belongs in the page, never wire diagnostics. */
export function visibleErrorLabel(code) {
  if (["invalid_response", "invalid_request", "unavailable", "busy", "conflict",
       "result_pending"].includes(code)) return "";
  return ERROR_LABEL[code] || "";
}
