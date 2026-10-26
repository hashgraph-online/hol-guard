import { fetchGuardApi, GuardHarnessActionError } from "./guard-api";

export const RECOVERY_SOURCE_ERRORS = new Set([
  "native_business_source_installation_incoherent",
  "native_business_source_transaction_not_committed",
  "native_business_source_retention_conflict",
  "native_business_source_recovery_required",
]);

export type BusinessRecoveryInspection = {
  state: "unavailable" | "interrupted" | "installed";
  candidateDigest: string;
  policy?: Record<string, unknown>;
  requestRecovered?: boolean;
};
const RECOVERY_ERROR_MESSAGES: Record<string, string> = {
  policy_import_disabled: "Policy imports are disabled. Enable local policy imports before retrying.",
  mcp_policy_write_disabled: "MCP policy writes are disabled. Enable local policy writes before retrying.",
  approval_gate_invalid_password: "The approval password was not accepted. Enter it again.",
  approval_gate_password_required: "Enter your local approval password before retrying.",
  approval_gate_totp_required: "Enter a fresh authenticator code before retrying.",
  approval_gate_configuration_required: "Set up local approval before recovering this policy.",
  approval_gate_recovery_required: "Restore local approval settings before recovering this policy.",
  approval_gate_grant_expired: "Approval expired during recovery. Review the saved policy and enter fresh proof.",
  approval_gate_locked: "Approval is temporarily locked. Wait before trying again.",
  approval_gate_totp_invalid: "The authenticator code was not accepted. Enter a fresh code.",
  approval_gate_required: "Fresh local approval proof is required.",
  business_source_recovery_candidate_unavailable: "This saved policy is unavailable or changed. Refresh and review the current policy.",
  native_business_source_recovery_identity_mismatch: "The saved installation differs from this request. Refresh before continuing.",
  native_business_source_retention_unavailable: "Retained installation state is unavailable. Restore access before retrying.",
  native_business_source_retention_conflict: "Retained installation state disagrees. Recovery requires checking every copy.",
  policy_authority_busy: "Another policy operation is running. Wait, then refresh.",
  native_business_source_unavailable: "The saved installation could not be verified. Restore its retained state before retrying.",
};
function recoveryError(status: number, payload: unknown): GuardHarnessActionError {
  let code = "business_policy_recovery_failed";
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string" &&
      Object.hasOwn(RECOVERY_ERROR_MESSAGES, payload.error)) code = payload.error;
  return new GuardHarnessActionError(status, { error: code, message: RECOVERY_ERROR_MESSAGES[code] ??
    "The saved policy could not be recovered. Its approval or installation state needs attention." });
}
export async function inspectBusinessPolicy(requestId: string, candidateDigest: string): Promise<BusinessRecoveryInspection> {
  const response = await fetchGuardApi(`/v1/mcp-policy/requests/${encodeURIComponent(requestId)}/decision`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "inspect-recovery", candidateDigest }),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 409 && payload && typeof payload === "object" && "error" in payload &&
        payload.error === "business_source_recovery_candidate_unavailable") return { state: "unavailable", candidateDigest };
    throw recoveryError(response.status, payload);
  }
  if (!payload || typeof payload !== "object" || !("candidateDigest" in payload) || payload.candidateDigest !== candidateDigest ||
      !("state" in payload) || typeof payload.state !== "string" || !["unavailable", "interrupted", "installed"].includes(payload.state)) {
    throw new Error("The saved policy inspection was not confirmed. Refresh before continuing.");
  }
  if (payload.state !== "unavailable" && (!("policy" in payload) || !payload.policy ||
      typeof payload.policy !== "object" || Array.isArray(payload.policy) ||
      !("provenanceRedacted" in payload) || payload.provenanceRedacted !== true)) {
    throw new Error("The saved policy rules were not confirmed. Refresh before continuing.");
  }
  if (!("requestRecovered" in payload) || typeof payload.requestRecovered !== "boolean") {
    throw new Error("The request recovery state was not confirmed. Refresh before continuing.");
  }
  return payload as BusinessRecoveryInspection;
}

export async function recoverBusinessPolicy(input: {
  requestId: string;
  candidateDigest: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<void> {
  const response = await fetchGuardApi(`/v1/mcp-policy/requests/${encodeURIComponent(input.requestId)}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "recover", ...input }),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw recoveryError(response.status, payload);
  }
  if (!payload || typeof payload !== "object" || !("installationRecovered" in payload) ||
      payload.installationRecovered !== true || !("sourceDigest" in payload) || payload.sourceDigest !== input.candidateDigest) {
    throw new Error("Recovery was not confirmed for this policy. Refresh before continuing.");
  }
}
