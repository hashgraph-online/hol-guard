import { GuardHarnessActionError } from "./guard-api";

const APPROVAL_GATE_REQUIRED_CODES = new Set([
  "approval_gate_required",
  "approval_gate_password_required",
  "approval_gate_totp_required",
]);

const APPROVAL_GATE_NON_CREDENTIAL_CODES = new Set([
  "approval_gate_locked",
  "approval_gate_invalid_password",
  "approval_gate_totp_invalid",
  "approval_gate_recovery_required",
  "approval_gate_weak_password",
]);

const APPROVAL_CREDENTIAL_PROMPT_MESSAGE =
  /approval(?:\s+gate)?\s+password is required|totp code is required/i;

const SUPPLY_CHAIN_CONNECT_ERROR_CODES = new Set([
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required",
]);

const GUARD_FETCH_NETWORK_ERROR_MESSAGE = /failed to fetch|networkerror|load failed/i;

export function isGuardHarnessActionError(error: unknown): error is GuardHarnessActionError {
  if (error instanceof GuardHarnessActionError) {
    return true;
  }
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error as GuardHarnessActionError;
  return candidate.name === "GuardHarnessActionError" && typeof candidate.status === "number";
}

export function readHarnessActionErrorCode(error: unknown): string | null {
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

export function readHarnessActionErrorMessage(error: unknown): string | null {
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

function isApprovalCredentialPromptCode(code: string | null): boolean {
  if (code === null) {
    return false;
  }
  if (APPROVAL_GATE_REQUIRED_CODES.has(code)) {
    return true;
  }
  return APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(code);
}

export function isSupplyChainSyncConnectError(error: unknown): boolean {
  const code = readHarnessActionErrorCode(error);
  return code !== null && SUPPLY_CHAIN_CONNECT_ERROR_CODES.has(code);
}

export function isSupplyChainSyncRetryableError(error: unknown): boolean {
  if (!isGuardHarnessActionError(error)) {
    return false;
  }
  if (readHarnessActionErrorCode(error) !== "supply_chain_sync_unavailable") {
    return false;
  }
  return error.payload?.retryable === true;
}

export function readHarnessActionUserMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && GUARD_FETCH_NETWORK_ERROR_MESSAGE.test(error.message)) {
    return "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.";
  }
  const structuredMessage = readHarnessActionErrorMessage(error);
  if (structuredMessage !== null) {
    return structuredMessage;
  }
  return fallback;
}

export function isApprovalGateRequiredError(error: unknown): boolean {
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

export type ApprovalGateSyncFailureResolution =
  | { kind: "approval_required" }
  | { kind: "failed"; message: string };

export function resolveApprovalGateSyncFailure(
  error: unknown,
  options?: { hasCredentials?: boolean },
): ApprovalGateSyncFailureResolution {
  const hasCredentials = options?.hasCredentials === true;
  if (!hasCredentials && isApprovalGateRequiredError(error)) {
    return { kind: "approval_required" };
  }
  return {
    kind: "failed",
    message: readHarnessActionUserMessage(error, "Sync failed."),
  };
}
