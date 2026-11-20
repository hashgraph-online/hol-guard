import { defaultUseApprovalCooldown, type BulkGateCredentials } from "./approval-gate-utils";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function isBulkApproveGateReady(
  gate: GuardApprovalGatePublicConfig | null | undefined,
): boolean {
  return gate?.enabled === true && gate?.configured === true;
}

/** Pulse replaces the password and the code: the batch is approved in the YID app. */
export function bulkApproveUsesPulse(gate: GuardApprovalGatePublicConfig | null | undefined): boolean {
  return isBulkApproveGateReady(gate) && gate?.pulse_enabled === true;
}

/**
 * The YID app line for a bulk approval. The batch sent to the phone holds one
 * request per selected group (its first request), so the count here is the
 * number of groups, the same count the YID app shows.
 */
export function bulkPulsePrompt(selectedGroupCount: number): string {
  return selectedGroupCount === 1
    ? "Approve this request in your YID app."
    : `Approve these ${selectedGroupCount} requests in your YID app.`;
}

/** An open cooldown window already proves the password for non-strict approvals. */
export function bulkApproveCooldownOpen(gate: GuardApprovalGatePublicConfig | null | undefined): boolean {
  return (
    isBulkApproveGateReady(gate) &&
    gate?.totp_enabled !== true &&
    gate?.pulse_enabled !== true &&
    gate?.strict_all_decisions !== true &&
    (gate?.cooldown_seconds ?? 0) > 0 &&
    gate?.cooldown_active === true
  );
}

export function validateBulkApproveCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  credentials: { password: string; totpCode: string },
): string | null {
  if (!isBulkApproveGateReady(gate)) {
    return "Set up an approval gate in Settings before bulk approval.";
  }
  if (bulkApproveUsesPulse(gate)) {
    return null;
  }
  if (gate?.totp_enabled === true) {
    return credentials.totpCode.trim() ? null : "Enter your authenticator code to continue.";
  }
  if (!credentials.password.trim() && !bulkApproveCooldownOpen(gate)) {
    return "Enter your approval password to continue.";
  }
  return null;
}

export function buildBulkGateCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  password: string,
  totpCode: string,
) {
  if (!isBulkApproveGateReady(gate)) {
    return undefined;
  }
  if (bulkApproveUsesPulse(gate)) {
    // The resident refuses a password or code sent alongside Pulse.
    return { approval_gate_pulse: true };
  }
  if (gate?.totp_enabled === true) {
    return {
      approval_totp_code: totpCode.trim(),
      approval_gate_use_cooldown: false,
    };
  }
  if (!password.trim() && bulkApproveCooldownOpen(gate)) {
    return { approval_gate_use_cooldown: true };
  }
  return {
    approval_password: password.trim(),
    approval_gate_use_cooldown: defaultUseApprovalCooldown(gate),
  };
}

/**
 * The proof a bulk submit carries: a password or code, a YID approval, an
 * open cooldown window (which the caller rechecks against a fresh gate), or none.
 */
export function bulkApprovalProof(
  credentials: BulkGateCredentials | undefined,
): "secret" | "pulse" | "cooldown" | null {
  if (credentials?.approval_password?.trim() || credentials?.approval_totp_code?.trim()) {
    return "secret";
  }
  if (credentials?.approval_gate_pulse === true) {
    return "pulse";
  }
  return credentials?.approval_gate_use_cooldown === true ? "cooldown" : null;
}
