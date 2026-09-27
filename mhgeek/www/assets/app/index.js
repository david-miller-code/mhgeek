/* Shared page helpers: localization, platform toast, small DOM utilities.
 * The toast wording reuses MHCamera's phone-authorization keys so one frontend
 * table covers both plugins (§10.1). */
import { Locale } from "/platform/sdk/locale.js";
import { Toast } from "/platform/sdk/toast.js";

const L10N = {
  zh: {
    title: "米家极客版",
    subtitle: "将全局与区域状态同步到米家极客版",
    stateLabel: "状态",
    authStatusLabel: "账号",
    stateUnknown: "状态未知",
    stateCredentialsRequired: "等待授权",
    stateTargetRequired: "等待配置中枢",
    stateOffline: "离线",
    stateCloudRequired: "需要公网",
    stateConnecting: "连接中",
    stateResources: "核对资源",
    statePresentationPending: "运行中，自动化展示待修复",
    stateResourceDrift: "自动化资源异常，状态提交已暂停",
    stateReady: "运行中",
    stateDeliveryPaused: "事件投递暂停",
    stateStopped: "已停止",
    stateLoading: "正在加载",
    providerRejected: "小米账号服务未通过本次授权，请稍后重新尝试。",
    authChecking: "正在核对授权状态",
    authPanel: "账号授权",
    authorized: "已授权",
    unauthorized: "未授权",
    authCodeRequired: "待输入验证码",
    authWorking: "授权处理中",
    authPersistPending: "等待保存授权",
    authRetryRequired: "等待重试",
    authSendUnknown: "短信结果待确认",
    callingCode: "国家或地区",
    nationalNumber: "米家手机号",
    nationalNumberPlaceholder: "请输入米家手机号",
    getSmsCode: "获取短信验证码",
    smsCode: "短信验证码",
    verifySms: "验证并授权",
    resendSms: "重新发送",
    changePhone: "更换手机号",
    clearAuthorization: "清除授权",
    authorizedAccount: "当前授权账号",
    retryStep: "重试",
    retryStorage: "只重试存储",
    restartAuthorization: "重新授权",
    resendIn: "{0} 秒后可重新发送",
    working: "正在与小米服务器通信…",
    retryRequired: "上一步未完成，请重试。",
    persistPending: "授权已获取，保存尚未完成，请重试存储。",
    sendUnknown: "短信发送结果未知，请确认手机是否收到验证码；不要重复发送。",
    targetPanel: "极客版",
    targetIp: "主中枢IP",
    targetDid: "设备 DID",
    saveTarget: "绑定",
    clearTarget: "解绑",
    authorizationRequired: "请先完成账号授权",
    diagnosticDetails: "诊断详情",
    targetUnconfigured: "未配置",
    targetLocked: "已锁定",
    targetUnresolved: "未解析",
    lastError: "最近错误",
    eventsPanel: "虚拟事件",
    eventsHint: "全局与八个区域分别设置有人、无人时发送的文本。",
    absentSeconds: "无人持续(秒)",
    invalidAbsentSeconds: "无人持续时间须为不小于 1 的整数秒",
    cloudFailed: "云端请求失败，请检查网络后重试",
    targetFailed: "中枢操作未完成，请查看诊断详情",
    targetCatalogError: "云端设备目录查询未完成，请稍后重试",
    targetNotFoundError: "该 IP 未匹配到可确认的极客版中枢，请核对 IP 和账号",
    targetAmbiguousError: "该 IP 对应多个通过核验的中枢，无法唯一绑定",
    targetConflictError: "中枢设备身份不一致，请核对绑定信息",
    targetProbeError: "极客版接口核验未完成，请确认中枢在线后重试",
    storeFailed: "配置保存失败，请重试",
    syncFailed: "中枢资源同步失败，请检查连接后重试",
    authFailed: "授权操作失败，请检查账号状态后重试",
    operationQueued: "操作已受理，等待执行…",
    operationRunning: "正在执行…",
    operationSyncing: "配置已保存，正在同步中枢…",
    operationSucceeded: "操作已完成",
    operationFailed: "操作失败",
    operationCancelled: "操作已取消",
    eventArea: "区域",
    save: "保存",
    prefixTitle: "统一事件前缀",
    prefixScope: "应用于全部事件",
    prefix: "前缀",
    prefixPlaceholder: "例如：客厅",
    global: "全局",
    zone: "{0}区",
    present: "有人",
    absent: "无人",
    sentPreview: "事件名称",
    invalidCallingCode: "请输入有效的国家或地区区号，例如 +86",
    invalidNationalNumber: "米家手机号只能包含数字",
    phoneNumberTooLong: "国家区号与手机号合计不能超过 15 位数字",
    invalidSmsCode: "请输入 {0} 位短信验证码",
    invalidTargetIp: "请输入有效的中枢 IP 地址",
    requestFailed: "无法确认操作结果，请检查连接并刷新页面",
    smsSent: "短信验证码已发送",
    smsResent: "短信验证码已重新发送",
    authorizationSucceeded: "小米账号授权成功",
    authorizationCleared: "授权与中枢绑定已清除",
    authorizationRestarted: "已结束本次授权，请重新获取验证码",
    targetSaved: "中枢已绑定",
    targetCleared: "已清除中枢绑定",
    operationSuperseded: "此配置已被后续保存替换，请查看当前配置",
    eventsSaved: "虚拟事件已保存并同步",
    clearAuthConfirm: "清除授权将同时清除中枢绑定，之后需重新验证手机号并绑定中枢。确定清除吗？",
    clearTargetConfirm: "清除极客版中枢绑定？授权与中枢上的资源都会保留。",
    /* Stable provider keys shared with MHCamera. */
    sms_send_limit_tomorrow: "验证码发送过多，请明天再试",
    sms_code_invalid_or_expired: "短信验证码无效或已过期",
    additional_verification_required: "需要额外验证，请在米家 App 完成",
    credential_rejected: "小米账号授权已失效，请清除授权后重新验证",
    sms_retry_later: "发送过于频繁，请稍后再试",
    rate_limit: "请求过于频繁，请稍后再试",
    phone_account_not_found: "该手机号未关联小米账号"
  }
};

export { Toast };

let language = "zh";

function lookup(key) {
  const languageTable = L10N[language] || L10N.zh;
  return languageTable[key] ?? L10N.zh[key];
}

export function t(key, ...args) {
  let text = lookup(key);
  if (text === undefined) return key;
  args.forEach((argument, index) => {
    text = text.replace("{" + index + "}", String(argument));
  });
  return text;
}

function i18nText(key) {
  return { zh: L10N.zh[key] ?? key, en: L10N.zh[key] ?? key };
}

export function toastOk(key) { Toast.success(i18nText(key)); }

/* A provider rejection or the local throttle always carries a stable key;
 * showing it as a toast is the product requirement, never a silent failure.
 * The caller dedupes, because the page polls this status every few seconds. */
export function toastForKey(key) {
  if (!key || lookup(key) === undefined) return false;
  Toast.error(i18nText(key));
  return true;
}

export function toastError(message) { Toast.error(message); }

export function ref(name) {
  return document.querySelector('[data-mhg-ref="' + name + '"]');
}

export function setText(element, value) {
  if (element) element.textContent = value == null ? "" : String(value);
}

export function renderMeta(element, rows) {
  if (!element) return;
  element.textContent = "";
  rows.forEach(([label, value]) => {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value == null || value === "" ? "-" : String(value);
    wrapper.append(term, description);
    element.append(wrapper);
  });
}

function applyLocale(state) {
  language = state && state.language === "en" ? "zh" : "zh";
  document.querySelectorAll("[data-l10n]").forEach((element) => {
    const key = element.getAttribute("data-l10n");
    if (key) element.textContent = t(key);
  });
  document.querySelectorAll("[data-l10n-placeholder]").forEach((element) => {
    const key = element.getAttribute("data-l10n-placeholder");
    if (key) element.placeholder = t(key);
  });
}

applyLocale(Locale.get ? Locale.get() : null);
if (Locale.addListener) Locale.addListener(applyLocale);
