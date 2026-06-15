export type BulkGateCredentials = {
  approval_password?: string;
  approval_totp_code?: string;
  approval_gate_use_cooldown?: boolean;
};

export function approvalGateCooldownLabel(seconds: number): string {
  if (seconds === 0) return "Every approval";
  if (seconds === 900) return "15 minutes";
  if (seconds === 3600) return "1 hour";
  return `${seconds} seconds`;
}

export function requiresApprovalPasswordPrompt(
  cooldownActive: boolean,
  strictAllDecisions: boolean,
  selectedScope: "artifact" | "workspace" | "publisher" | "harness" | "global"
): boolean {
  if (selectedScope === "global") {
    return true;
  }
  if (!cooldownActive) {
    return true;
  }
  return strictAllDecisions;
}
