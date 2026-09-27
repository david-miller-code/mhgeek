import { ref, renderMeta, setText, t, toastError, toastForKey, toastOk }
  from "../app/index.js";
import { validTargetIp, targetErrorLabel, authView, visibleErrorLabel, gatewayLabel, mayConfigure, OPERATION_LABEL, validAbsentSeconds } from "./contracts.js";
import { completeOperation, readWithRetry } from "../bridge/operations.js";
import {
  COUNTRY_CALLING_CODES,
  DEFAULT_COUNTRY_KEY,
  callingCodeForCountryKey,
  countryKey
} from "../countries.js";

const SLOT_COUNT = 9;
const POLL_MS = 3000;

let auth = { state_name: "needs_authorization" };
let lastAuthToast = null;
let eventsDirty = false;
let targetDirty = false;
let resendDeadline = 0;
let countdownTimer = null;
let pendingAction = false;
let activeSubmission = null;
let latestOperation = 0;
let eventsRevision = 0;
let refreshInFlight = null;
let authReadPending = false;
let authEpoch = 0;
let countryPickerOpen = false;
let countryPickerRendered = false;

function applyAuthorizationGate() {
  const blocked = !mayConfigure(auth, pendingAction);
  document.querySelectorAll(
    '[aria-labelledby="target-panel-title"] input, ' +
    '[aria-labelledby="target-panel-title"] button, ' +
    '[aria-labelledby="events-panel-title"] input, ' +
    '[aria-labelledby="events-panel-title"] button'
  ).forEach((control) => {
    control.disabled = blocked ||
      ((control === ref("targetIp") || control === ref("targetSave")) &&
        Boolean(ref("targetSave")?.hidden));
  });
}

function setActionBusy(busy) {
  document.querySelectorAll("[data-mhg-panel] button").forEach((button) => {
    button.disabled = busy;
  });
  const challengeActive = auth.state_name === "code_required";
  const callingCode = ref("callingCodeTrigger");
  const nationalNumberInput = ref("nationalNumber");
  if (callingCode) callingCode.disabled = busy || challengeActive;
  if (nationalNumberInput)
    nationalNumberInput.disabled = busy || challengeActive;
  if (!busy) {
    const targetSave = ref("targetSave");
    if (targetSave) targetSave.disabled = Boolean(ref("targetIp")?.disabled);
    tickCountdown();
  }
  applyAuthorizationGate();
}

function slotLabel(index) {
  if (index === 0) return t("global");
  return t("zone", String.fromCharCode(64 + index));
}

function describe(error) {
  const label = visibleErrorLabel(error?.errorCode);
  return label ? t(label) : "";
}

async function operate(path, method, body) {
  const submission = activeSubmission;
  const authOperation = /^\/auth\//.test(path);
  const epoch = authOperation ? ++authEpoch : authEpoch;
  if (authOperation) authReadPending = true;
  const sequence = ++latestOperation;
  const notice = ref("operationNotice");
  if (notice) notice.hidden = false;
  try {
    return await completeOperation(path, method, body, operation => {
      if (operation.state === "waiting_sync") releaseSubmission(submission);
      if (sequence === latestOperation)
        setText(ref("operationText"), t(OPERATION_LABEL[operation.state]));
    });
  } catch (error) {
    if (sequence !== latestOperation) throw error;
    console.warn("MHGeek operation", { errorCode: error?.errorCode || "transport" });
    const message = describe(error);
    setText(ref("operationText"), message);
    if (notice) notice.hidden = !message;
    throw error;
  } finally {
    if (authOperation) {
      try { renderAuth(await readWithRetry("/auth/status"), epoch); }
      catch (error) { showRefreshError(error); }
    }
  }
}

function showRefreshError(error) {
  // Preserve the last complete view; the regular poll recovers it automatically.
  console.warn("MHGeek refresh", { errorCode: error?.errorCode || "transport" });
  const panel = document.querySelector("[data-mhg-panel]");
  if (panel) panel.setAttribute("aria-busy", "false");
}

function releaseSubmission(submission) {
  if (submission.released) return;
  submission.released = true;
  if (submission.button) {
    delete submission.button.dataset.loading;
    submission.button.removeAttribute("aria-busy");
  }
  if (activeSubmission !== submission) return;
  activeSubmission = null;
  pendingAction = false;
  setActionBusy(false);
}

async function submit(action, button) {
  if (pendingAction) return;
  const submission = { button };
  activeSubmission = submission;
  pendingAction = true;
  setActionBusy(true);
  if (button) {
    button.dataset.loading = "true";
    button.setAttribute("aria-busy", "true");
  }
  try {
    await action();
  } catch (error) {
    const message = describe(error);
    if (message) toastError(message);
  } finally {
    releaseSubmission(submission);
    try {
      if (refreshInFlight) await refreshInFlight.catch(() => {});
      await refresh();
    } catch (error) {
      showRefreshError(error);
    }
  }
}

async function clearAuthorization() {
  await operate("/auth/clear", "POST", {});
  targetDirty = false;
  renderTarget({});
  toastOk("authorizationCleared");
}

/* --- authorization ----------------------------------------------------- */

function selectedCallingCode() {
  return callingCodeForCountryKey(ref("callingCode")?.value) || "+86";
}

function nationalNumber() {
  const input = ref("nationalNumber");
  return input ? input.value.replace(/\D/g, "") : "";
}

function validatePhone() {
  const code = selectedCallingCode();
  const number = nationalNumber();
  if (!/^\+\d{1,4}$/.test(code)) { toastError(t("invalidCallingCode")); return null; }
  if (!/^\d+$/.test(number)) { toastError(t("invalidNationalNumber")); return null; }
  if ((code.length - 1 + number.length) > 15) {
    toastError(t("phoneNumberTooLong"));
    return null;
  }
  return { calling_code: code, national_number: number };
}

function showPane(name) {
  document.querySelectorAll("[data-mhg-pane]").forEach((pane) => {
    pane.hidden = pane.getAttribute("data-mhg-pane") !== name;
  });
}


function tickCountdown() {
  const remaining = Math.max(0, Math.ceil((resendDeadline - Date.now()) / 1000));
  const button = ref("smsStart");
  const waitingForCode = auth.state_name === "code_required";
  const verify = ref("smsVerify");
  if (verify) verify.disabled = pendingAction || authReadPending;
  if (button) {
    setText(button, authReadPending ? t("authChecking") : waitingForCode ?
      (remaining > 0 ? t("resendIn", remaining) : t("resendSms")) :
      t("getSmsCode"));
    button.disabled = pendingAction || authReadPending || (waitingForCode && remaining > 0);
  }
}

function renderAuth(state, epoch = authEpoch) {
  if (epoch !== authEpoch) return;
  authReadPending = false;
  auth = state || { state_name: "needs_authorization" };
  if (auth.has_account === false && auth.state_name === "needs_authorization")
    targetDirty = false;
  const view = authView(auth.state_name);
  const badge = ref("authText");
  setText(badge, t(view.label));
  const authBadge = ref("authBadge");
  if (authBadge) authBadge.dataset.state = auth.state_name;
  showPane(view.pane);
  const authPanel = document.querySelector('[aria-labelledby="auth-panel-title"]');
  if (authPanel) authPanel.dataset.state = auth.state_name;

  const challengeActive = auth.state_name === "code_required";
  const smsPane = ref("smsPane");
  if (smsPane) smsPane.hidden = !challengeActive;
  const callingCode = ref("callingCodeTrigger");
  const phoneInput = ref("nationalNumber");
  if (callingCode) callingCode.disabled = challengeActive || pendingAction;
  if (phoneInput) phoneInput.disabled = challengeActive || pendingAction;
  const smsCode = ref("smsCode");
  if (smsCode) smsCode.maxLength = Math.max(1, auth.code_length || 6);
  const account = ref("authorizedAccount");
  if (account) setText(account, auth.account?.masked_id || "-");

  const pendingHint = ref("pendingHint");
  if (pendingHint) setText(pendingHint, t(view.hint || "stateUnknown"));
  const retryPersist = ref("authRetryPersist");
  if (retryPersist) retryPersist.hidden = auth.state_name !== "persist_pending";
  const retry = ref("authRetry");
  if (retry) retry.hidden = auth.state_name === "working";
  if (auth.state_name === "code_required")
    resendDeadline = Date.now() + (auth.retry_after_seconds || 0) * 1000;
  if (auth.state_name !== "code_required") resendDeadline = 0;
  if (auth.state_name === "authenticated" && countryPickerOpen)
    setCountryPickerOpen(false);
  tickCountdown();
  /* Toast a rejection once per state change; the resend countdown already
   * explains the local throttle while the user is entering the code. */
  const authError = ref("authError");
  const errorKey = visibleErrorLabel(auth.message_key);
  if (authError) authError.hidden = !errorKey;
  setText(authError, errorKey ? t(errorKey) : "");
  smsCode?.setAttribute("aria-invalid", String(auth.message_key === "sms_code_invalid_or_expired"));
  const signature = [auth.state_name, auth.provider_class, auth.error,
                     auth.error_name, auth.message_key].join("|");
  if (signature !== lastAuthToast) {
    lastAuthToast = signature;
    if (errorKey) toastForKey(errorKey);
  }
}

/* --- target ------------------------------------------------------------ */

function renderTarget(target) {
  const state = target.locked ? t("targetLocked") :
    (target.configured ? t("targetUnresolved") : t("targetUnconfigured"));
  setText(ref("targetState"), state);
  const targetState = ref("targetState");
  if (targetState) targetState.dataset.state = target.locked ? "locked" :
    (target.configured ? "unresolved" : "unconfigured");
  renderMeta(ref("targetMeta"), [
    [t("targetDid"), target.did || ""],
    [t("lastError"), target.last_error ? t(targetErrorLabel(target.last_outcome_name)) : ""]
  ]);
  const diagnostic = ref("targetDiagnostic");
  if (diagnostic) diagnostic.hidden = !target.last_error;
  setText(ref("targetDiagnosticText"), target.last_error ?
    `${target.last_outcome_name || "unknown"}: ${target.last_error}` : "");
  const input = ref("targetIp");
  if (target.locked) targetDirty = false;
  if (input && !targetDirty) input.value = target.ip || "";
  if (input) input.disabled = Boolean(target.locked);
  const save = ref("targetSave");
  const clear = ref("targetClear");
  const locked = Boolean(target.locked);
  if (save) {
    save.hidden = locked;
    save.disabled = locked || pendingAction;
  }
  if (clear) {
    clear.hidden = !locked;
    clear.disabled = pendingAction;
  }
}

/* --- virtual events ---------------------------------------------------- */

function buildEventRows() {
  const grid = ref("eventsGrid");
  if (!grid || grid.childElementCount) return;
  for (let index = 0; index < SLOT_COUNT; index += 1) {
    const row = document.createElement("div");
    row.className = "event-row";
    row.setAttribute("role", "group");
    row.setAttribute("aria-label", slotLabel(index));
    const label = document.createElement("span");
    label.className = "event-label";
    label.textContent = slotLabel(index);
    const presentField = document.createElement("label");
    presentField.className = "event-field";
    const presentLabel = document.createElement("span");
    presentLabel.className = "event-state-label";
    presentLabel.textContent = t("present");
    const present = document.createElement("input");
    present.type = "text";
    present.maxLength = 64;
    present.dataset.slot = String(index);
    present.dataset.state = "present";
    present.placeholder = t("present");
    present.setAttribute("aria-label", slotLabel(index) + " · " + t("present"));
    presentField.append(presentLabel, present);
    const absentField = document.createElement("label");
    absentField.className = "event-field";
    const absentLabel = document.createElement("span");
    absentLabel.className = "event-state-label";
    absentLabel.textContent = t("absent");
    const absent = document.createElement("input");
    absent.type = "text";
    absent.maxLength = 64;
    absent.dataset.slot = String(index);
    absent.dataset.state = "absent";
    absent.placeholder = t("absent");
    absent.setAttribute("aria-label", slotLabel(index) + " · " + t("absent"));
    absentField.append(absentLabel, absent);
    const preview = document.createElement("div");
    preview.className = "event-preview";
    preview.dataset.slot = String(index);
    const previewLabel = document.createElement("span");
    previewLabel.className = "event-preview-label";
    previewLabel.textContent = t("sentPreview");
    const previewValue = document.createElement("output");
    const presentValue = document.createElement("span");
    presentValue.className = "event-preview-value present";
    const presentName = document.createElement("span");
    presentName.className = "sr-only";
    presentName.textContent = t("present") + "：";
    const presentText = document.createElement("span");
    presentText.className = "event-preview-text";
    presentValue.append(presentName, presentText);
    const divider = document.createElement("span");
    divider.className = "event-preview-divider";
    divider.setAttribute("aria-hidden", "true");
    const absentValue = document.createElement("span");
    absentValue.className = "event-preview-value absent";
    const absentName = document.createElement("span");
    absentName.className = "sr-only";
    absentName.textContent = t("absent") + "：";
    const absentText = document.createElement("span");
    absentText.className = "event-preview-text";
    absentValue.append(absentName, absentText);
    previewValue.append(presentValue, divider, absentValue);
    preview.append(previewLabel, previewValue);
    const durationField = document.createElement("label");
    durationField.className = "event-field";
    const durationLabel = document.createElement("span");
    durationLabel.className = "event-state-label";
    durationLabel.textContent = t("absentSeconds");
    const duration = document.createElement("input");
    duration.type = "number";
    duration.min = "1";
    duration.step = "1";
    duration.inputMode = "numeric";
    duration.value = "1";
    duration.dataset.slot = String(index);
    duration.dataset.state = "absent_seconds";
    duration.setAttribute("aria-label", slotLabel(index) + " · " + t("absentSeconds"));
    durationField.append(durationLabel, duration);
    row.append(label, presentField, absentField, durationField, preview);
    grid.append(row);
  }
  grid.addEventListener("input", () => {
    eventsDirty = true;
    eventsRevision += 1;
    renderPreview();
  });
}

function eventInput(slot, state) {
  return document.querySelector('[data-mhg-ref="eventsGrid"] input[data-slot="' +
                                slot + '"][data-state="' + state + '"]');
}

function renderPreview() {
  const prefix = ref("eventsPrefix") ? ref("eventsPrefix").value.trim() : "";
  for (let index = 0; index < SLOT_COUNT; index += 1) {
    const preview = document.querySelector(
      '[data-mhg-ref="eventsGrid"] .event-preview[data-slot="' + index + '"]');
    if (!preview) continue;
    const present = eventInput(index, "present");
    const absent = eventInput(index, "absent");
    setText(preview.querySelector(".event-preview-value.present .event-preview-text"),
      prefix + (present ? present.value.trim() : ""));
    setText(preview.querySelector(".event-preview-value.absent .event-preview-text"),
      prefix + (absent ? absent.value.trim() : ""));
  }
}

function renderEvents(config) {
  buildEventRows();
  const prefix = ref("eventsPrefix");
  if (prefix && !eventsDirty) prefix.value = config.prefix || "";
  (config.slots || []).forEach((slot) => {
    if (eventsDirty) return;
    const present = eventInput(slot.slot, "present");
    const absent = eventInput(slot.slot, "absent");
    if (present) present.value = slot.present_text || "";
    if (absent) absent.value = slot.absent_text || "";
    eventInput(slot.slot, "absent_seconds").value = slot.absent_seconds ?? 1;
  });
  renderPreview();
}

function eventsPayload() {
  const slots = [];
  for (let index = 0; index < SLOT_COUNT; index += 1) {
    const present = eventInput(index, "present");
    const absent = eventInput(index, "absent");
    const durationInput = eventInput(index, "absent_seconds");
    const absentSeconds = Number(durationInput.value);
    if (!/^[0-9]+$/.test(durationInput.value.trim()) || !validAbsentSeconds(absentSeconds)) {
      durationInput.setAttribute("aria-invalid", "true");
      durationInput.focus();
      throw Object.assign(new Error(), { errorCode: "invalid_absent_seconds" });
    }
    durationInput.removeAttribute("aria-invalid");
    slots.push({
      slot: index,
      absent_seconds: absentSeconds,
      present_text: present ? present.value.trim() : "",
      absent_text: absent ? absent.value.trim() : ""
    });
  }
  return {
    prefix: ref("eventsPrefix") ? ref("eventsPrefix").value.trim() : "",
    slots
  };
}

/* --- wiring ------------------------------------------------------------ */

async function refresh() {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    const epoch = authEpoch;
    const results = await Promise.allSettled([
      readWithRetry("/gateway/status"),
      readWithRetry("/auth/status"),
      readWithRetry("/gateway/target"),
      readWithRetry("/gateway/virtual-events")
    ]);
    const renderers = [status => {
      const state = status.state_name || "unknown";
      const resourceDrift = status.resources?.state_name === "drifted";
      setText(ref("stateText"), t(gatewayLabel(status)));
      const badge = ref("stateBadge");
      if (badge) badge.dataset.state = resourceDrift ? "resource_drift" : state;
    }, state => renderAuth(state, epoch), renderTarget, renderEvents];
    results.forEach((result, index) => {
      if (result.status === "fulfilled") renderers[index](result.value);
      else showRefreshError(result.reason);
    });
    applyAuthorizationGate();
    const panel = document.querySelector("[data-mhg-panel]");
    if (panel) panel.setAttribute("aria-busy", "false");
  })();
  try {
    return await refreshInFlight;
  } finally {
    refreshInFlight = null;
  }
}

function countryOptions() {
  return Array.from(ref("callingCodeListbox")?.querySelectorAll(
    "[role='option']") || []);
}

function renderCallingCodeOptions() {
  const input = ref("callingCode");
  const trigger = ref("callingCodeTrigger");
  const value = ref("callingCodeValue");
  const listbox = ref("callingCodeListbox");
  if (!input || !trigger || !value || !listbox) return;

  const selectedKey = callingCodeForCountryKey(input.value) ? input.value :
    DEFAULT_COUNTRY_KEY;
  const selectedCountry = COUNTRY_CALLING_CODES.find(
    (country) => countryKey(country) === selectedKey);
  input.value = selectedKey;
  value.textContent = selectedCountry ?
    `${selectedCountry.name_zh} (${selectedCountry.calling_code})` : "-";
  if (!countryPickerRendered) {
    listbox.replaceChildren();
    COUNTRY_CALLING_CODES.forEach((country) => {
      const option = document.createElement("button");
      const name = document.createElement("span");
      const code = document.createElement("span");
      option.type = "button";
      option.className = "country-picker-option";
      option.dataset.countryKey = countryKey(country);
      option.setAttribute("role", "option");
      option.tabIndex = -1;
      name.className = "country-picker-name";
      name.textContent = country.name_zh;
      code.className = "country-picker-code";
      code.textContent = country.calling_code;
      option.append(name, code);
      listbox.append(option);
    });
    countryPickerRendered = true;
  }
  countryOptions().forEach((option) => {
    option.setAttribute("aria-selected",
      String(option.dataset.countryKey === selectedKey));
  });
  trigger.setAttribute("aria-expanded", String(countryPickerOpen));
  listbox.hidden = !countryPickerOpen;
}

function focusCountryOption(position = "selected") {
  const options = countryOptions();
  if (!options.length) return;
  let option = options.find((item) =>
    item.dataset.countryKey === ref("callingCode")?.value);
  if (position === "first") option = options[0];
  else if (position === "last") option = options[options.length - 1];
  (option || options[0]).focus({ preventScroll: true });
  (option || options[0]).scrollIntoView({ block: "nearest" });
}

function setCountryPickerOpen(open, focusPosition = "") {
  const trigger = ref("callingCodeTrigger");
  if (!trigger || (open && trigger.disabled)) return;
  countryPickerOpen = Boolean(open);
  renderCallingCodeOptions();
  if (countryPickerOpen && focusPosition)
    queueMicrotask(() => focusCountryOption(focusPosition));
  else if (!countryPickerOpen && focusPosition === "trigger")
    trigger.focus();
}

function selectCountry(key) {
  if (!callingCodeForCountryKey(key)) return;
  ref("callingCode").value = key;
  countryPickerOpen = false;
  renderCallingCodeOptions();
  ref("callingCodeTrigger").focus();
}

function moveCountryOption(event, delta) {
  const options = countryOptions();
  if (!options.length) return;
  const current = event.target.closest("[role='option']");
  const index = Math.max(0, options.indexOf(current));
  const next = options[(index + delta + options.length) % options.length];
  next.focus({ preventScroll: true });
  next.scrollIntoView({ block: "nearest" });
}

function handleCountryTriggerKeydown(event) {
  switch (event.key) {
  case "ArrowDown":
  case "ArrowUp":
    event.preventDefault();
    setCountryPickerOpen(true, "selected");
    break;
  case "Home":
    event.preventDefault();
    setCountryPickerOpen(true, "first");
    break;
  case "End":
    event.preventDefault();
    setCountryPickerOpen(true, "last");
    break;
  case "Escape":
    if (countryPickerOpen) event.preventDefault();
    setCountryPickerOpen(false);
    break;
  case "Enter":
  case " ":
    event.preventDefault();
    setCountryPickerOpen(!countryPickerOpen,
      countryPickerOpen ? "" : "selected");
    break;
  }
}

function handleCountryListboxKeydown(event) {
  switch (event.key) {
  case "ArrowDown":
    event.preventDefault();
    moveCountryOption(event, 1);
    break;
  case "ArrowUp":
    event.preventDefault();
    moveCountryOption(event, -1);
    break;
  case "Home":
    event.preventDefault();
    focusCountryOption("first");
    break;
  case "End":
    event.preventDefault();
    focusCountryOption("last");
    break;
  case "Escape":
    event.preventDefault();
    setCountryPickerOpen(false, "trigger");
    break;
  case "Enter":
  case " ": {
    const option = event.target.closest("[role='option']");
    if (!option) break;
    event.preventDefault();
    selectCountry(option.dataset.countryKey);
    break;
  }
  case "Tab":
    event.preventDefault();
    setCountryPickerOpen(false);
    (event.shiftKey ? ref("callingCodeTrigger") :
      ref("nationalNumber"))?.focus();
    break;
  }
}

function wire() {
  renderCallingCodeOptions();
  ref("callingCodeTrigger")?.addEventListener("click", () => {
    setCountryPickerOpen(!countryPickerOpen,
      countryPickerOpen ? "" : "selected");
  });
  ref("callingCodeTrigger")?.addEventListener(
    "keydown", handleCountryTriggerKeydown);
  ref("callingCodeListbox")?.addEventListener(
    "keydown", handleCountryListboxKeydown);
  ref("callingCodeListbox")?.addEventListener("click", (event) => {
    const option = event.target.closest("[role='option']");
    if (option) selectCountry(option.dataset.countryKey);
  });
  document.addEventListener("pointerdown", (event) => {
    const picker = ref("countryPicker");
    if (countryPickerOpen && picker && !picker.contains(event.target))
      setCountryPickerOpen(false);
  });
  ref("phoneForm")?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (authReadPending) return;
    if (auth.state_name === "code_required") {
      if (Date.now() < resendDeadline) return;
      submit(async () => {
        await operate("/auth/sms/resend", "POST", {});
        toastOk("smsResent");
        resendDeadline = Date.now() + 60000;
      }, ref("smsStart"));
      return;
    }
    const payload = validatePhone();
    if (payload) submit(async () => {
      await operate("/auth/sms/start", "POST", payload);
      toastOk("smsSent");
    }, ref("smsStart"));
  });
  ref("smsForm")?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (authReadPending) return;
    const code = ref("smsCode") ? ref("smsCode").value.trim() : "";
    const expected = auth.code_length || 6;
    if (!new RegExp("^\\d{" + expected + "}$").test(code)) {
      toastError(t("invalidSmsCode", expected));
      return;
    }
    submit(async () => {
      await operate("/auth/sms/verify", "POST", { code });
      toastOk("authorizationSucceeded");
    }, ref("smsVerify"));
  });
  ref("changePhone")?.addEventListener("click", () => submit(async () => {
    await operate("/auth/cancel", "POST", {});
    toastOk("authorizationRestarted");
  }, ref("changePhone")));
  ref("authRetry")?.addEventListener("click", () => submit(() => operate(
    "/auth/retry", "POST", {}), ref("authRetry")));
  ref("authRetryPersist")?.addEventListener("click", () => submit(() => operate(
    "/auth/retry", "POST", { retry_persist: true }), ref("authRetryPersist")));
  ref("authRestart")?.addEventListener("click", () => submit(clearAuthorization,
    ref("authRestart")));
  ref("authClear")?.addEventListener("click", () => {
    if (!window.confirm(t("clearAuthConfirm"))) return;
    submit(clearAuthorization, ref("authClear"));
  });

  ref("targetIp")?.addEventListener("input", () => { targetDirty = true; });
  ref("targetSave")?.addEventListener("click", () => {
    const ip = ref("targetIp") ? ref("targetIp").value.trim() : "";
    if (!validTargetIp(ip)) {
      toastError(t("invalidTargetIp"));
      return;
    }
    submit(async () => {
      await operate("/gateway/target", "PUT", { ip });
      targetDirty = false;
      toastOk("targetSaved");
    }, ref("targetSave"));
  });
  ref("targetClear")?.addEventListener("click", () => {
    if (!window.confirm(t("clearTargetConfirm"))) return;
    submit(async () => {
      await operate("/gateway/target/clear", "POST", {});
      targetDirty = false;
      toastOk("targetCleared");
    }, ref("targetClear"));
  });

  ref("eventsPrefix")?.addEventListener("input", () => {
    eventsDirty = true;
    eventsRevision += 1;
    renderPreview();
  });
  ref("eventsSave")?.addEventListener("click", () => submit(async () => {
    const revision = eventsRevision;
    await operate("/gateway/virtual-events", "PUT", eventsPayload());
    if (eventsRevision === revision) eventsDirty = false;
    toastOk("eventsSaved");
  }, ref("eventsSave")));
}

async function main() {
  if (!ref("stateText") || !ref("eventsGrid") ||
      !ref("callingCodeTrigger")) {
    if (window.AIniceUI && window.AIniceUI.fail)
      window.AIniceUI.fail("page structure missing");
    return;
  }
  wire();
  applyAuthorizationGate();
  setText(ref("stateText"), t("stateLoading"));
  try {
    await refresh();
  } catch (error) {
    showRefreshError(error);
  }
  countdownTimer = window.setInterval(tickCountdown, 1000);
  window.setInterval(() => {
    if (!pendingAction) refresh().catch(showRefreshError);
  }, POLL_MS);
  /* The platform hides the page until it reports that it is mounted. */
  if (window.AIniceUI && window.AIniceUI.ready) window.AIniceUI.ready();
}

main();
