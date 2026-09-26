import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function isBulkApproveGateReady(
  gate: GuardApprovalGatePublicConfig | null | undefined,
): boolean {
  return gate?.enabled === true && gate?.configured === true;
}

export function validateBulkApproveCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  credentials: { password: string; totpCode: string },
): string | null {
  if (!isBulkApproveGateReady(gate)) {
    return "Set up an approval gate in Settings before bulk approval.";
  }
  if (gate?.totp_enabled === true) {
    return credentials.totpCode.trim() ? null : "Enter your authenticator code to continue.";
  }
  if (!credentials.password.trim()) {
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
  if (gate?.totp_enabled === true) {
    return {
      approval_totp_code: totpCode.trim(),
      approval_gate_use_cooldown: false,
    };
  }
  return {
    approval_password: password.trim(),
    approval_gate_use_cooldown: false,
  };
}
