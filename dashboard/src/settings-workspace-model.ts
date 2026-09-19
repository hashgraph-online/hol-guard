import { type ApprovalGateWriteProof, type GuardApprovalGateTotpEnrollment } from "./guard-api";
import { resolveProtectionLevelCopy } from "./runtime-overview";
import { RISK_CONTROL_CONSEQUENCES } from "./apps/app-catalog";
import { deriveProtectionPosture, isProtectionPosture, PROTECTION_POSTURE_COPY, type ProtectionPosture } from "./protection-posture-copy";
import { type SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import type { GuardApprovalGatePublicConfig, GuardSettings, GuardSettingsPayload } from "./guard-types";
import { normalizePresentationSettings } from "./settings-presentation";

export const resolveSecurityLevelDescription = resolveProtectionLevelCopy;

export type SettingsSaveScope = "all" | "approval-gate";

export function resolveSecurityLevelCardDescription(level: "relaxed" | "balanced" | "strict" | "custom"): string {
  if (level === "relaxed") return "Warn on dangerous actions. Most safe actions run without a prompt.";
  if (level === "balanced") return "Ask before secret access, hidden execution, exfiltration, and destructive actions.";
  if (level === "strict") return "Ask more often, including new network destinations.";
  return "Use the exact choices below for this machine and connected apps.";
}

export function resolveFineTuningSectionDescription(
  securityLevel: GuardSettings["security_level"],
): string {
  if (securityLevel === "custom") {
    return "Using custom rules on top of this machine's protection posture.";
  }
  const postureLabel = securityLevel === "strict" ? "Extra careful" : "Protected";
  return `These rules follow ${postureLabel}. Switch to Custom to change how Guard handles each action type.`;
}

export function isFineTuningEditable(securityLevel: GuardSettings["security_level"]): boolean {
  return securityLevel === "custom";
}

export function buildClearPolicyPayload(all: boolean): { harness?: string; all?: boolean } {
  return { all };
}

export function buildClearReviewQueuePayload(input: {
  approvalPassword?: string;
  approvalTotpCode?: string;
}): {
  status: "pending";
  approval_password?: string;
  approval_totp_code?: string;
} {
  return {
    status: "pending",
    ...(input.approvalPassword ? { approval_password: input.approvalPassword } : {}),
    ...(input.approvalTotpCode ? { approval_totp_code: input.approvalTotpCode } : {}),
  };
}

export function buildApprovalGateWriteProof(
  credentials?: Pick<SettingsSaveProofCredentials, "currentPassword" | "totpCode">,
): ApprovalGateWriteProof {
  const approvalPassword = credentials?.currentPassword?.trim() ?? "";
  const approvalTotpCode = credentials?.totpCode?.trim() ?? "";
  return {
    ...(approvalPassword.length > 0 ? { approval_password: approvalPassword } : {}),
    ...(approvalTotpCode.length > 0 ? { approval_totp_code: approvalTotpCode } : {}),
  };
}

export type TotpSetupStep = "confirm" | "scan";

export function resolveTotpSetupStep(
  enrollment: GuardApprovalGateTotpEnrollment | null,
): TotpSetupStep {
  return enrollment !== null ? "scan" : "confirm";
}

export function hasApprovalGateSettingsChanged(
  gateConfig: GuardApprovalGatePublicConfig | null,
  enabled: boolean,
  cooldownSeconds: number,
  strictAllDecisions: boolean,
): boolean {
  if (gateConfig === null) {
    return false;
  }
  return (
    enabled !== gateConfig.enabled
    || cooldownSeconds !== gateConfig.cooldown_seconds
    || strictAllDecisions !== gateConfig.strict_all_decisions
  );
}

export function effectiveApprovalGateCooldownSeconds(
  cooldownSeconds: number,
  totpEnabled: boolean,
): number {
  return totpEnabled ? 0 : cooldownSeconds;
}

export function resolveTotpSetupModalTitle(isConfirmStep: boolean): string {
  if (isConfirmStep) {
    return "Confirm your approval password";
  }
  return "Scan and verify";
}

export function resolveTotpSetupModalDescription(isConfirmStep: boolean): string {
  if (isConfirmStep) {
    return "Guard needs your approval password before it can generate a QR code for your authenticator app.";
  }
  return "Open your authenticator app, add an account, scan the code, then enter the live six-digit code.";
}

export type SettingsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; payload: GuardSettingsPayload };

export const actionOptions = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Allow and record" },
  { value: "review", label: "Ask once" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Stop" },
];

export const surfacePolicyOptions = [
  { value: "attention-aware", label: "In the app when possible" },
  { value: "approval-center", label: "Always in Guard" },
  { value: "native-only", label: "Never open a browser" },
];

export const attentionSeverityOptions = [
  { value: "critical", label: "Critical risk" },
  { value: "high", label: "High or critical risk" },
  { value: "medium", label: "Medium risk or higher" },
  { value: "low", label: "Any identified risk" },
];

export const riskControls = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials.", consequence: RISK_CONTROL_CONSEQUENCES["local_secret_read"] },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away.", consequence: RISK_CONTROL_CONSEQUENCES["credential_exfiltration"] },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret is read and its value reaches a network or external sink.", consequence: RISK_CONTROL_CONSEQUENCES["data_flow_exfiltration"] },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files.", consequence: RISK_CONTROL_CONSEQUENCES["destructive_shell"] },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_execution"] },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context.", consequence: RISK_CONTROL_CONSEQUENCES["network_egress"] },
  { key: "prompt_injection", label: "Prompt injection", description: "Prompts that try to override Guard, leak secrets, or weaken review.", consequence: RISK_CONTROL_CONSEQUENCES["prompt_injection"] },
  { key: "mcp_dangerous_tool", label: "Connected tools", description: "Tool calls that can read files, run commands, or reach the network.", consequence: RISK_CONTROL_CONSEQUENCES["mcp_dangerous_tool"] },
  { key: "malicious_skill", label: "Skills", description: "Agent skills from unknown or risky sources.", consequence: RISK_CONTROL_CONSEQUENCES["malicious_skill"] },
  { key: "package_script", label: "Package scripts", description: "Lifecycle scripts such as postinstall, prepare, and prepublish.", consequence: RISK_CONTROL_CONSEQUENCES["package_script"] },
  { key: "persistence", label: "Persistence", description: "Startup files, launch agents, scheduled jobs, and recurring hooks.", consequence: RISK_CONTROL_CONSEQUENCES["persistence"] },
  { key: "guard_bypass", label: "Guard bypass", description: "Attempts to disable Guard hooks, policies, or approval flow.", consequence: RISK_CONTROL_CONSEQUENCES["guard_bypass"] },
  { key: "cloud_advisory", label: "Cloud advisories", description: "Team and Cloud guidance for known risky patterns.", consequence: RISK_CONTROL_CONSEQUENCES["cloud_advisory"] },
  { key: "encoded_exfiltration", label: "Encoded exfiltration", description: "Encoded payloads that hide secret extraction and network transfer.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_exfiltration"] },
] as const;

export type RiskKey = (typeof riskControls)[number]["key"];

export const riskProfileActions: Record<"relaxed" | "balanced" | "strict" | "custom", Record<RiskKey, string>> = {
  relaxed: {
    local_secret_read: "warn",
    credential_exfiltration: "warn",
    data_flow_exfiltration: "warn",
    destructive_shell: "warn",
    encoded_execution: "warn",
    network_egress: "allow",
    prompt_injection: "warn",
    mcp_dangerous_tool: "warn",
    malicious_skill: "warn",
    package_script: "warn",
    persistence: "warn",
    guard_bypass: "warn",
    cloud_advisory: "allow",
    encoded_exfiltration: "warn"
  },
  balanced: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval"
  },
  strict: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "block",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "require-reapproval",
    prompt_injection: "block",
    mcp_dangerous_tool: "block",
    malicious_skill: "block",
    package_script: "require-reapproval",
    persistence: "block",
    guard_bypass: "block",
    cloud_advisory: "require-reapproval",
    encoded_exfiltration: "block"
  },
  custom: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval"
  }
};

export function normalizeSettingsPayload(payload: GuardSettingsPayload): GuardSettingsPayload {
  return { ...payload, settings: normalizeGuardSettings(payload.settings) };
}

export function normalizeGuardSettings(settings: GuardSettings): GuardSettings {
  const securityLevel = settings.security_level === "gentle" ? "relaxed" : settings.security_level;
  const defaults = riskProfileActions[securityLevel];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce<Record<RiskKey, string>>((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {} as Record<RiskKey, string>);
  const posture = isProtectionPosture(settings.protection_posture)
    ? settings.protection_posture
    : deriveProtectionPosture(settings.mode, securityLevel);
  return {
    ...normalizePresentationSettings(settings),
    protection_posture: posture,
    watch_auto_revert_hours: settings.watch_auto_revert_hours ?? 24,
    security_level: securityLevel,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}

export function applyProtectionPosture(settings: GuardSettings, posture: ProtectionPosture): GuardSettings {
  if (posture === "watch") {
    return {
      ...settings,
      protection_posture: "watch",
      protection_posture_explicit: true,
      mode: "observe",
    };
  }
  const securityLevel = posture === "extra_careful" ? "strict" : "balanced";
  return {
    ...settings,
    protection_posture: posture,
    protection_posture_explicit: true,
    mode: "enforce",
    security_level: securityLevel,
    risk_actions: riskProfileActions[securityLevel],
    risk_action_overrides: {},
  };
}

export function currentProtectionPosture(settings: GuardSettings): ProtectionPosture {
  if (isProtectionPosture(settings.protection_posture)) {
    return settings.protection_posture;
  }
  return deriveProtectionPosture(settings.mode, settings.security_level);
}

export function lockedSetting(settings: GuardSettings, key: string): boolean {
  return settings.managed_locked_settings?.includes(key) === true;
}

export function lockedProtectionPostures(settings: GuardSettings): ProtectionPosture[] {
  const allPostures: ProtectionPosture[] = ["protected", "extra_careful", "watch"];
  if (lockedSetting(settings, "protection_posture")) {
    const current = currentProtectionPosture(settings);
    return allPostures.filter((posture) => posture !== current);
  }
  if (lockedSetting(settings, "mode") && settings.mode !== "observe") {
    return ["watch"];
  }
  return [];
}

export function buildConsequenceSummary(settings: GuardSettings): string {
  const posture = currentProtectionPosture(settings);
  if (posture === "watch") {
    return "Protection is off. Guard is only recording.";
  }
  if (posture === "extra_careful") {
    return "Guard will also ask the first time this project talks to a new site or installs a new tool.";
  }
  if (settings.security_level === "custom") {
    const postureLabel = PROTECTION_POSTURE_COPY[posture].label;
    return `Using custom rules on top of ${postureLabel}.`;
  }
  return "Guard stops dangerous actions automatically and asks once about new or unknown work.";
}

export function hasUnsavedChanges(saved: GuardSettings | null, draft: GuardSettings | null): boolean {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
}

export function applyApprovalGateDraft(
  settings: GuardSettings,
  updates: {
    enabled: boolean;
    cooldown_seconds: number;
    strict_all_decisions?: boolean;
  }
): GuardSettings {
  const gate = settings.approval_gate;
  return {
    ...settings,
    approval_gate: {
      enabled: updates.enabled,
      configured: gate?.configured ?? false,
      cooldown_seconds: updates.cooldown_seconds,
      cooldown_active: gate?.cooldown_active ?? false,
      cooldown_expires_at: gate?.cooldown_expires_at ?? null,
      locked_until: gate?.locked_until ?? null,
      fail_closed: gate?.fail_closed ?? false,
      strict_all_decisions: updates.strict_all_decisions ?? gate?.strict_all_decisions ?? false,
      totp_enabled: gate?.totp_enabled ?? false,
      totp_pending: gate?.totp_pending ?? false,
    },
  };
}

export function saveStatusText(saveSuccess: boolean, saveError: string | null): string {
  if (saveSuccess) {
    return "Settings saved successfully.";
  }
  return saveError ?? "";
}

export type SettingsWorkspaceProps = {
  onApprovalGateChange?: (gate: GuardApprovalGatePublicConfig) => void;
};
