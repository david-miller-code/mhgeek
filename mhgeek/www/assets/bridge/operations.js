import { request } from "./client.js";
import { OPERATION_LABEL } from "../page/contracts.js";

export class OperationError extends Error {
  constructor(code, diagnostic = "") {
    super(diagnostic);
    this.errorCode = code;
    this.diagnostic = diagnostic;
  }
}

/* Reads may recover from a lost response. Mutations are never replayed. */
export async function readWithRetry(path, query = {}, call = request,
                                    pause = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  for (let attempt = 0; ; attempt++) {
    try { return await call(path, "GET", {}, query); }
    catch (error) {
      if (attempt === 3) throw error;
      await pause(500 * (attempt + 1));
    }
  }
}

/* Acknowledgement only supplies an id. Only the terminal server result succeeds. */
export async function completeOperation(path, method, body, onProgress = () => {},
                                        call = request,
                                        pause = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  const accepted = await call(path, method, body);
  if (accepted?.accepted !== true || !Number.isSafeInteger(accepted.operation_id) ||
      typeof accepted.instance_id !== "string" || !accepted.instance_id)
    throw new OperationError("invalid_response");
  for (;;) {
    const operation = await readWithRetry("/operations", { id: String(accepted.operation_id), instance_id: accepted.instance_id }, call, pause);
    if (!operation || operation.operation_id !== accepted.operation_id ||
        operation.instance_id !== accepted.instance_id ||
        !Object.hasOwn(OPERATION_LABEL, operation.state))
      throw new OperationError("invalid_response");
    onProgress(operation);
    if (operation.state === "superseded")
      throw new OperationError("superseded", operation.diagnostic);
    if (operation.state === "failed")
      throw new OperationError(operation.message_key || operation.error_code, operation.diagnostic);
    if (operation.state === "succeeded") return operation;
    await pause(500);
  }
}
