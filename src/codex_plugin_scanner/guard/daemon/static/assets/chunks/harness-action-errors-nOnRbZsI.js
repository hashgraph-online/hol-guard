import { ej as GuardHarnessActionError } from "../guard-dashboard.js";
const APPROVAL_GATE_REQUIRED_CODES = /* @__PURE__ */ new Set([
  "approval_gate_required",
  "approval_gate_password_required",
  "approval_gate_totp_required"
]);
const APPROVAL_GATE_NON_CREDENTIAL_CODES = /* @__PURE__ */ new Set([
  "approval_gate_locked",
  "approval_gate_grant_expired",
  "approval_gate_invalid_password",
  "approval_gate_totp_invalid",
  "approval_gate_recovery_required",
  "approval_gate_weak_password"
]);
const APPROVAL_CREDENTIAL_PROMPT_MESSAGE = /approval(?:\s+gate)?\s+password is required|totp code is required/i;
const SUPPLY_CHAIN_CONNECT_ERROR_CODES = /* @__PURE__ */ new Set([
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required"
]);
const GUARD_FETCH_NETWORK_ERROR_MESSAGE = /failed to fetch|networkerror|load failed/i;
function isGuardHarnessActionError(error) {
  if (error instanceof GuardHarnessActionError) {
    return true;
  }
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error;
  return candidate.name === "GuardHarnessActionError" && typeof candidate.status === "number";
}
function readHarnessActionErrorCode(error) {
  if (!isGuardHarnessActionError(error)) {
    return null;
  }
  const code = error.payload?.error;
  if (typeof code !== "string") {
    return null;
  }
  const trimmed = code.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function readHarnessActionErrorMessage(error) {
  if (!isGuardHarnessActionError(error)) {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }
    return null;
  }
  const message = error.payload?.message ?? error.message;
  if (typeof message !== "string") {
    return null;
  }
  const trimmed = message.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function isApprovalCredentialPromptCode(code) {
  if (code === null) {
    return false;
  }
  if (APPROVAL_GATE_REQUIRED_CODES.has(code)) {
    return true;
  }
  return APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(code);
}
function isPackageFirewallOperationInProgressError(error) {
  return readHarnessActionErrorCode(error) === "operation_in_progress";
}
function isSupplyChainSyncConnectError(error) {
  const code = readHarnessActionErrorCode(error);
  return code !== null && SUPPLY_CHAIN_CONNECT_ERROR_CODES.has(code);
}
function isSupplyChainSyncRetryableError(error) {
  if (!isGuardHarnessActionError(error)) {
    return false;
  }
  if (readHarnessActionErrorCode(error) !== "supply_chain_sync_unavailable") {
    return false;
  }
  return error.payload?.retryable === true;
}
function readHarnessActionUserMessage(error, fallback) {
  if (error instanceof Error && GUARD_FETCH_NETWORK_ERROR_MESSAGE.test(error.message)) {
    return "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.";
  }
  const structuredMessage = readHarnessActionErrorMessage(error);
  if (structuredMessage !== null) {
    return structuredMessage;
  }
  return fallback;
}
function readPackageFirewallActionFailure(error) {
  if (error instanceof Error && GUARD_FETCH_NETWORK_ERROR_MESSAGE.test(error.message)) {
    return "Guard lost connection to the local daemon. Confirm it is still running, then try again.";
  }
  return error instanceof Error ? error.message : "Action failed.";
}
function isApprovalGateRequiredError(error) {
  const code = readHarnessActionErrorCode(error);
  if (code !== null && APPROVAL_GATE_NON_CREDENTIAL_CODES.has(code)) {
    return false;
  }
  if (isApprovalCredentialPromptCode(code)) {
    return true;
  }
  const message = readHarnessActionErrorMessage(error);
  if (message !== null && APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(message)) {
    return true;
  }
  return false;
}
function resolveApprovalGateSyncFailure(error, options) {
  const hasCredentials = options?.hasCredentials === true;
  if (!hasCredentials && isApprovalGateRequiredError(error)) {
    return { kind: "approval_required" };
  }
  return {
    kind: "failed",
    message: readHarnessActionUserMessage(error, "Sync failed.")
  };
}
function setupActionErrorMessage(error) {
  if (error.payload?.error === "confirmation_required") {
    return "Disconnect requires confirmation so accidental clicks cannot remove local protection.";
  }
  if (error.payload?.error === "approval_gate_totp_required") {
    return "Enter a fresh authenticator code to disconnect this app.";
  }
  if (error.payload?.error === "approval_gate_required" || error.payload?.error === "approval_gate_password_required") {
    return "Enter your approval password to disconnect this app.";
  }
  return error.payload?.message ?? error.payload?.error ?? error.message;
}
export {
  isSupplyChainSyncConnectError as a,
  isPackageFirewallOperationInProgressError as b,
  isSupplyChainSyncRetryableError as c,
  readHarnessActionUserMessage as d,
  resolveApprovalGateSyncFailure as e,
  isApprovalGateRequiredError as f,
  readPackageFirewallActionFailure as g,
  isGuardHarnessActionError as i,
  readHarnessActionErrorCode as r,
  setupActionErrorMessage as s
};
