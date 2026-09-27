import { getBridgeClient } from "/platform/sdk/bridge.js";
import { ProtocolErrorCode } from "/platform/sdk/protocol-error-codes.js";
import { t } from "../app/index.js";

const MODULE = "mhgeek";

export class RequestError extends Error {
  constructor(code, message, body) {
    super(message || t("requestFailed"));
    this.name = "MHGeekRequestError";
    this.code = Number.isInteger(code) ? code : ProtocolErrorCode.ROUTE_NOT_FOUND;
    this.body = body || {};
    const error = body && typeof body.error === "object" ? body.error : null;
    this.errorCode = error?.details?.error_code || error?.error_code;
    this.diagnostic = error?.details?.reason || error?.message || "";
  }
}

/* One call path for every page request (§10.1):
 *   {module, method:"route", params:{path,http_method,query,body}} */
export async function request(path, method = "GET", body = {}, query = {}) {
  const client = getBridgeClient();
  const data = await client.request({
    module: MODULE,
    method: "route",
    params: {
      path,
      http_method: method,
      query: query || {},
      body: body || {}
    }
  });
  if (data && data.error) {
    const error = typeof data.error === "object" ? data.error : {};
    throw new RequestError(error.code, error.message, data);
  }
  return data;
}
