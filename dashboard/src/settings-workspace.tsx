import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniCog6Tooth,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniBellAlert,
  HiMiniChevronDown,
  HiMiniMagnifyingGlass,
  HiMiniXMark,
} from "react-icons/hi2";

import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
} from "./approval-center-primitives";
import {
  clearEvidence,
  clearReviewQueue,
  disableApprovalGateTotp,
  enrollApprovalGateTotp,
  exportDiagnostics,
  exportSettings,
  fetchRuntimeSnapshot,
  fetchSettings,
  importSettings,
  resetSettings,
  type ApprovalGateWriteProof,
  type GuardApprovalGateTotpEnrollment,
  updateSettings,
  clearPolicy,
  repairApprovalCenter,
  setupDesktopNotifications,
  verifyApprovalGateTotp,
  revokeApprovalGateCooldown,
} from "./guard-api";
import { approvalGateCooldownLabel } from "./approval-gate-utils";
import { resolveProtectionLevelCopy } from "./runtime-overview";
import { RISK_CONTROL_CONSEQUENCES, filterSettingsBySearch, securityLevelLabel } from "./apps/app-catalog";
import { useFocusTrap } from "./use-focus-trap";
export {
  buildTotpQrImageOptions,
  formatTotpEnrollmentExpiry,
  formatTotpManualKey,
  TotpEnrollmentQrPanel,
} from "./totp-enrollment-qr-panel";
import { TotpEnrollmentQrPanel } from "./totp-enrollment-qr-panel";
import {
  SettingsSaveProofModal,
  resolveSettingsSaveProofKind,
  resolveSettingsSaveProofModalCopy,
  requiresSettingsSaveProof,
  type SettingsSaveProofCredentials,
  type SettingsSaveProofMode,
} from "./settings-save-proof-modal";
import type {
  GuardApprovalGatePublicConfig,
  GuardNotificationSetupResult,
  GuardRuntimeSnapshot,
  GuardSettings,
  GuardSettingsExport,
  GuardSettingsPayload,
} from "./guard-types";
import { SettingsSectionShell } from "./settings/settings-section-shell";
import { SettingsFormSection, SettingsToggleRow } from "./settings/settings-row-primitives";
import { isLocalSettingsTabKey, type LocalSettingsTabKey } from "./settings/settings-ia";

export const resolveSecurityLevelDescription = resolveProtectionLevelCopy;

export function resolveInitialSettingsTab(search: string): LocalSettingsTabKey {
  const section = new URLSearchParams(search).get("section");
  if (section === "risk" || section === "defaults") {
    return "rules";
  }
  return section !== null && isLocalSettingsTabKey(section) ? section : "protection";
}

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
    return "You are overriding the preset for this machine.";
  }
  return `These rules follow the ${securityLevelLabel(securityLevel)} preset. Use Custom fine-tuning to edit each action type here.`;
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

export function resolveApprovalPasswordSectionCopy(wasConfigured: boolean): string {
  if (wasConfigured) {
    return "Guard asks for this password before allow or trust changes stick. Save settings to confirm changes, or change the password when needed.";
  }
  return "Choose a password when you save settings. Guard will ask for it before allow or trust changes stick.";
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

type SettingsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; payload: GuardSettingsPayload };

const actionOptions = [
  { value: "allow", label: "Allow without asking" },
  { value: "warn", label: "Warn only" },
  { value: "review", label: "Ask me first" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Block" },
];

const surfacePolicyOptions = [
  { value: "attention-aware", label: "Smart (recommended)" },
  { value: "approval-center", label: "Open prompts immediately" },
  { value: "native-only", label: "Never open the browser" },
];

const attentionSeverityOptions = [
  { value: "critical", label: "Critical risk" },
  { value: "high", label: "High or critical risk" },
  { value: "medium", label: "Medium risk or higher" },
  { value: "low", label: "Any identified risk" },
];

const protectionModeChoices = [
  { value: "prompt" as const, label: "Ask first" },
  { value: "enforce" as const, label: "Block until approved" },
  { value: "observe" as const, label: "Watch only" },
];

const securityLevels = [
  {
    value: "relaxed" as const,
    label: "Relaxed",
    description: "Warn on dangerous actions. Most safe actions run without a prompt.",
    icon: HiMiniShieldCheck,
    protects: ["Destructive commands", "Credential sharing"],
    tone: "green" as const,
  },
  {
    value: "balanced" as const,
    label: "Balanced",
    description: "Ask before secret access, hidden execution, exfiltration, and destructive actions.",
    icon: HiMiniShieldCheck,
    protects: ["Secret file access", "Credential sharing", "Destructive shell commands", "Hidden scripts"],
    tone: "blue" as const,
  },
  {
    value: "strict" as const,
    label: "Strict",
    description: "Ask more often, including new network destinations.",
    icon: HiMiniLockClosed,
    protects: ["Everything in Balanced", "New network destinations"],
    tone: "purple" as const,
  },
  {
    value: "custom" as const,
    label: "Custom",
    description: "Use the exact choices below for this machine and connected apps.",
    icon: HiMiniCog6Tooth,
    protects: [],
    tone: "slate" as const,
  }
];

const riskControls = [
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

type RiskKey = (typeof riskControls)[number]["key"];

const riskProfileActions: Record<"relaxed" | "balanced" | "strict" | "custom", Record<RiskKey, string>> = {
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

const securityToneClasses = {
  green: {
    icon: "text-emerald-600",
    iconBg: "bg-emerald-50",
    selected: "border-emerald-300 bg-emerald-50"
  },
  blue: {
    icon: "text-brand-blue",
    iconBg: "bg-brand-blue/10",
    selected: "border-brand-blue/30 bg-brand-blue/[0.05]"
  },
  purple: {
    icon: "text-brand-purple",
    iconBg: "bg-brand-purple/10",
    selected: "border-brand-purple/30 bg-brand-purple/[0.04]"
  },
  slate: {
    icon: "text-slate-500",
    iconBg: "bg-slate-100",
    selected: "border-slate-300 bg-slate-50"
  }
} as const;

type SecurityTone = keyof typeof securityToneClasses;

function getSecurityToneClasses(tone: SecurityTone) {
  return securityToneClasses[tone] ?? securityToneClasses.slate;
}

function normalizeSettingsPayload(payload: GuardSettingsPayload): GuardSettingsPayload {
  return { ...payload, settings: normalizeGuardSettings(payload.settings) };
}

function normalizeGuardSettings(settings: GuardSettings): GuardSettings {
  const securityLevel = settings.security_level === "gentle" ? "relaxed" : settings.security_level;
  const defaults = riskProfileActions[securityLevel];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce<Record<RiskKey, string>>((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {} as Record<RiskKey, string>);
  return {
    ...settings,
    security_level: securityLevel,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}

function buildConsequenceSummary(settings: GuardSettings): string {
  const level = settings.security_level;
  const mode = settings.mode;
  if (mode === "observe") return "Guard is watching and recording what your AI apps do, but it will not pause any actions. Switch to Prompt or Enforce when you want Guard to actively protect you.";
  if (level === "relaxed") return "Guard will warn about destructive commands and credential sharing but will not pause for approval. Most safe actions run automatically. Good for trusted environments.";
  if (level === "balanced") return "Guard will ask before secret access, hidden execution, and destructive commands. New network destinations get a warning. This is the recommended setting for most users.";
  if (level === "strict") return "Guard will ask before almost every risky action, including new network destinations. Use this when working with sensitive data or untrusted AI tools.";
  if (level === "custom") return "You have customized individual risk controls. Review the choices below to make sure they match how you want Guard to behave.";
  return "";
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

function protectionModeHelp(mode: GuardSettings["mode"]): string {
  if (mode === "enforce") {
    return "Guard keeps risky actions stopped until you allow them.";
  }
  if (mode === "observe") {
    return "Guard logs what it sees without pausing anything.";
  }
  return "Guard pauses risky actions and asks what to do.";
}

function protectionModeLabel(mode: GuardSettings["mode"]): string {
  const match = protectionModeChoices.find((choice) => choice.value === mode);
  return match?.label ?? mode;
}

function saveStatusText(saveSuccess: boolean, saveError: string | null): string {
  if (saveSuccess) {
    return "Settings saved successfully.";
  }
  return saveError ?? "";
}

type SettingsWorkspaceProps = {
  onApprovalGateChange?: (gate: GuardApprovalGatePublicConfig) => void;
};

export function SettingsWorkspace({ onApprovalGateChange }: SettingsWorkspaceProps) {
  const [state, setState] = useState<SettingsState>({ kind: "loading" });
  const [draft, setDraft] = useState<GuardSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [clearingApprovals, setClearingApprovals] = useState(false);
  const [clearingEvidence, setClearingEvidence] = useState(false);
  const [clearingReviewQueue, setClearingReviewQueue] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [repairing, setRepairing] = useState(false);
  const [settingUpNotifications, setSettingUpNotifications] = useState(false);
  const [notificationSetup, setNotificationSetup] = useState<GuardNotificationSetupResult | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionMessageKind, setActionMessageKind] = useState<"success" | "error">("success");
  const [perfSnapshot, setPerfSnapshot] = useState<GuardRuntimeSnapshot | null>(null);
  const [pendingMode, setPendingMode] = useState<GuardSettings["mode"] | null>(null);
  const [activeTab, setActiveTab] = useState<LocalSettingsTabKey>(() => resolveInitialSettingsTab(window.location.search));
  const [searchQuery, setSearchQuery] = useState("");
  const [importingSettings, setImportingSettings] = useState(false);
  const [resettingSettings, setResettingSettings] = useState(false);
  const [exportingSettings, setExportingSettings] = useState(false);
  const settingsImportInputRef = useRef<HTMLInputElement>(null);
  const saveSuccessTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedSettingsRef = useRef<GuardSettings | null>(null);
  const [approvalGateEnabled, setApprovalGateEnabled] = useState(false);
  const [approvalGateTotpCode, setApprovalGateTotpCode] = useState("");
  const [approvalGateTotpDeviceLabel, setApprovalGateTotpDeviceLabel] = useState("local-device");
  const [approvalGateStrictAllDecisions, setApprovalGateStrictAllDecisions] = useState(false);
  const [approvalGateCooldown, setApprovalGateCooldown] = useState(0);
  const [totpEnrollment, setTotpEnrollment] = useState<GuardApprovalGateTotpEnrollment | null>(null);
  const [totpSetupOpen, setTotpSetupOpen] = useState(false);
  const [totpSetupStep, setTotpSetupStep] = useState<TotpSetupStep>("confirm");
  const [totpActionPassword, setTotpActionPassword] = useState("");
  const [totpActionPending, setTotpActionPending] = useState<"enroll" | "verify" | "disable" | null>(null);
  const [totpActionError, setTotpActionError] = useState<string | null>(null);
  const [proofModalOpen, setProofModalOpen] = useState(false);
  const [proofModalMode, setProofModalMode] = useState<SettingsSaveProofMode>("verify-save");
  const [proofModalError, setProofModalError] = useState<string | null>(null);
  const [proofModalPending, setProofModalPending] = useState(false);
  const [pendingProofAction, setPendingProofAction] = useState<
    | { kind: "save" }
    | {
        kind: "maintenance";
        action:
          | "clear-approvals"
          | "clear-queue"
          | "revoke-cooldown"
          | "disable-totp"
          | "import-settings"
          | "reset-settings";
        importExport?: GuardSettingsExport;
      }
    | null
  >(null);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (!cancelled) {
          const normalizedPayload = normalizeSettingsPayload(payload);
          setState({ kind: "ready", payload: normalizedPayload });
          setDraft(normalizedPayload.settings);
          savedSettingsRef.current = normalizedPayload.settings;
          const gate = normalizedPayload.settings.approval_gate;
          if (gate !== undefined) {
            setApprovalGateEnabled(gate.enabled);
            setApprovalGateCooldown(gate.cooldown_seconds);
            setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
            onApprovalGateChange?.(gate);
          }
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
        }
      });
    return () => { cancelled = true; };
  }, [onApprovalGateChange]);

  useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot()
      .then((snapshot) => { if (!cancelled) setPerfSnapshot(snapshot); })
      .catch((_err: unknown) => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    return () => { if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current); };
  }, []);

  useEffect(() => {
    function handleBeforeUnload(event: BeforeUnloadEvent) {
      if (hasUnsavedChanges(savedSettingsRef.current, draft)) {
        event.preventDefault();
        event.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [draft]);

  const handleTabChange = useCallback((tab: LocalSettingsTabKey) => {
    setActiveTab(tab);
    setActionMessage(null);
    const url = new URL(window.location.href);
    url.searchParams.set("section", tab);
    window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
  }, []);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  }, []);

  const handleStringChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.value });
      setSaveError(null);
    },
    []
  );

  const handleSecurityLevelChange = useCallback((securityLevel: GuardSettings["security_level"]) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") return { ...value, security_level: securityLevel };
      const normalizedLevel = securityLevel === "gentle" ? "relaxed" : securityLevel;
      return {
        ...value,
        security_level: normalizedLevel,
        risk_actions: riskProfileActions[normalizedLevel],
        risk_action_overrides: {},
        harness_risk_actions: {},
      };
    });
    setSaveError(null);
  }, []);

  const handleSwitchToCustomFineTuning = useCallback(() => {
    handleSecurityLevelChange("custom");
  }, [handleSecurityLevelChange]);

  const handleRiskActionChange = useCallback(
    (riskKey: string) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => {
        if (value === null) return value;
        return { ...value, security_level: "custom", risk_actions: { ...value.risk_actions, [riskKey]: event.target.value }, risk_action_overrides: { ...value.risk_action_overrides, [riskKey]: event.target.value } };
      });
      setSaveError(null);
    },
    []
  );

  const handleCodexSecretReadChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setDraft((value) => {
      if (value === null) return value;
      return { ...value, security_level: "custom", harness_risk_actions: { ...value.harness_risk_actions, codex: { ...(value.harness_risk_actions.codex ?? {}), local_secret_read: event.target.value } } };
    });
    setSaveError(null);
  }, []);

  const handleTimeoutChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    const nextTimeout = Number.isNaN(nextValue) ? 0 : nextValue;
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: nextTimeout });
    setSaveError(null);
  }, []);

  const handleNumberChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      const parsed = Number.parseInt(event.target.value, 10);
      const value = Number.isNaN(parsed) ? 0 : parsed;
      setDraft((settings) => settings === null ? settings : { ...settings, [key]: value });
      setSaveError(null);
    },
    [],
  );

  const handleModeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextMode = event.target.value as GuardSettings["mode"];
    if (nextMode === "observe") { setPendingMode(nextMode); return; }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);

  const confirmModeChange = useCallback(() => {
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [pendingMode]);

  const cancelModeChange = useCallback(() => { setPendingMode(null); }, []);

  const handleBooleanChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );

  const handleTelemetryToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, telemetry: checked });
    setSaveError(null);
  }, []);

  const handleSyncToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, sync: checked });
    setSaveError(null);
  }, []);

  const handleBillingToggle = useCallback((checked: boolean) => {
    setDraft((value) => value === null ? value : { ...value, billing: checked });
    setSaveError(null);
  }, []);

  const handleApprovalGateToggle = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const checked = event.target.checked;
    setApprovalGateEnabled(checked);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: checked,
          cooldown_seconds: approvalGateCooldown,
          strict_all_decisions: approvalGateStrictAllDecisions,
        })
    );
    setSaveError(null);
  }, [approvalGateCooldown, approvalGateStrictAllDecisions]);

  const handleApprovalGateTotpCode = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateTotpCode(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleApprovalGateTotpDeviceLabel = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateTotpDeviceLabel(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleTotpActionPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpActionPassword(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleOpenTotpSetup = useCallback(() => {
    setTotpSetupStep(resolveTotpSetupStep(totpEnrollment));
    setTotpActionError(null);
    setTotpSetupOpen(true);
  }, [totpEnrollment]);
  const handleCloseTotpSetup = useCallback(() => {
    setTotpSetupOpen(false);
    setTotpSetupStep("confirm");
    if (totpEnrollment === null) {
      setTotpActionPassword("");
    }
    setTotpActionError(null);
  }, [totpEnrollment]);

  const handleApprovalGateCooldownChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    const next = Number(event.target.value);
    setApprovalGateCooldown(next);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: approvalGateEnabled,
          cooldown_seconds: next,
          strict_all_decisions: approvalGateStrictAllDecisions,
        })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateStrictAllDecisions]);
  const handleApprovalGateStrictAllDecisions = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const strict = event.target.checked;
    setApprovalGateStrictAllDecisions(strict);
    setDraft((value) =>
      value === null
        ? value
        : applyApprovalGateDraft(value, {
          enabled: approvalGateEnabled,
          cooldown_seconds: approvalGateCooldown,
          strict_all_decisions: strict,
        })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateCooldown]);

  const applyLoadedSettingsPayload = useCallback((normalizedPayload: GuardSettingsPayload) => {
    setState({ kind: "ready", payload: normalizedPayload });
    setDraft(normalizedPayload.settings);
    savedSettingsRef.current = normalizedPayload.settings;
    const gate = normalizedPayload.settings.approval_gate;
    if (gate !== undefined) {
      setApprovalGateEnabled(gate.enabled);
      setApprovalGateCooldown(gate.cooldown_seconds);
      setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
      onApprovalGateChange?.(gate);
    }
  }, [onApprovalGateChange]);

  const openProofModal = useCallback((
    mode: SettingsSaveProofMode,
    action: NonNullable<typeof pendingProofAction>,
  ) => {
    setProofModalMode(mode);
    setPendingProofAction(action);
    setProofModalError(null);
    setProofModalOpen(true);
  }, []);

  const closeProofModal = useCallback(() => {
    if (proofModalPending) {
      return;
    }
    setProofModalOpen(false);
    setPendingProofAction(null);
    setProofModalError(null);
  }, [proofModalPending]);

  const executeSave = useCallback(async (proof?: SettingsSaveProofCredentials) => {
    if (draft === null) {
      return;
    }
    const fromModal = proof !== undefined;
    if (!fromModal) {
      setSaving(true);
      setSaveError(null);
      setSaveSuccess(false);
    }
    try {
      const approvalGateUpdate: GuardApprovalGatePublicConfig & {
        current_password?: string;
        new_password?: string;
        confirm_password?: string;
        totp_code?: string;
      } = {
        enabled: approvalGateEnabled,
        configured: draft.approval_gate?.configured ?? false,
        cooldown_seconds: approvalGateCooldown,
        cooldown_active: draft.approval_gate?.cooldown_active ?? false,
        cooldown_expires_at: draft.approval_gate?.cooldown_expires_at ?? null,
        locked_until: draft.approval_gate?.locked_until ?? null,
        fail_closed: draft.approval_gate?.fail_closed ?? false,
        strict_all_decisions: approvalGateStrictAllDecisions,
        totp_enabled: draft.approval_gate?.totp_enabled ?? false,
        totp_pending: draft.approval_gate?.totp_pending ?? false,
        ...(proof?.currentPassword ? { current_password: proof.currentPassword } : {}),
        ...(proof?.newPassword ? { new_password: proof.newPassword } : {}),
        ...(proof?.confirmPassword ? { confirm_password: proof.confirmPassword } : {}),
        ...(proof?.totpCode ? { totp_code: proof.totpCode } : {}),
      };
      const settingsToSave: Partial<GuardSettings> = {
        ...draft,
        risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides,
        approval_gate: approvalGateUpdate,
      };
      const payload = await updateSettings(settingsToSave);
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (normalizedPayload.settings.approval_gate !== undefined) {
        const gate = normalizedPayload.settings.approval_gate;
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      if (!fromModal) {
        setSaveSuccess(true);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2000);
      } else {
        setSaveSuccess(true);
        setSaveError(null);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2000);
      }
    } catch (error) {
      if (fromModal) {
        throw error;
      }
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      if (!fromModal) {
        setSaving(false);
      }
    }
  }, [
    draft,
    approvalGateEnabled,
    approvalGateCooldown,
    approvalGateStrictAllDecisions,
    onApprovalGateChange,
  ]);

  const executeMaintenanceWithProof = useCallback(async (
    action: "clear-approvals" | "clear-queue" | "revoke-cooldown" | "disable-totp",
    proof: SettingsSaveProofCredentials,
  ) => {
    const password = proof.currentPassword?.trim() ?? "";
    const totpCode = proof.totpCode?.trim() ?? "";
    if (action === "clear-approvals") {
      setClearingApprovals(true);
      setActionMessage(null);
      try {
        await clearPolicy({
          all: true,
          approval_password: password || undefined,
          approval_totp_code: totpCode || undefined,
        });
        setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
        setActionMessageKind("success");
      } finally {
        setClearingApprovals(false);
      }
      return;
    }
    if (action === "clear-queue") {
      setClearingReviewQueue(true);
      setActionMessage(null);
      try {
        const result = await clearReviewQueue(buildClearReviewQueuePayload({
          approvalPassword: password,
          approvalTotpCode: totpCode,
        }));
        setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
        setActionMessageKind("success");
      } finally {
        setClearingReviewQueue(false);
      }
      return;
    }
    if (action === "revoke-cooldown") {
      try {
        const payload = await revokeApprovalGateCooldown(
          password,
          totpCode.length > 0 ? totpCode : undefined,
        );
        const normalizedPayload = normalizeSettingsPayload(payload);
        const gate = normalizedPayload.settings.approval_gate;
        setState({ kind: "ready", payload: normalizedPayload });
        setDraft(normalizedPayload.settings);
        savedSettingsRef.current = normalizedPayload.settings;
        if (gate !== undefined) {
          setApprovalGateEnabled(gate.enabled);
          setApprovalGateCooldown(gate.cooldown_seconds);
          setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
          onApprovalGateChange?.(gate);
        }
        setActionMessage("Cooldown revoked successfully.");
        setActionMessageKind("success");
      } catch (error) {
        throw error;
      }
      return;
    }
    setTotpActionPending("disable");
    setTotpActionError(null);
    try {
      const payload = await disableApprovalGateTotp(password, totpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== undefined) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app disconnected.");
      setActionMessageKind("success");
    } finally {
      setTotpActionPending(null);
    }
  }, [onApprovalGateChange]);

  const executeImportSettings = useCallback(async (
    settingsExport: GuardSettingsExport,
    proof?: SettingsSaveProofCredentials,
  ) => {
    setImportingSettings(true);
    setActionMessage(null);
    try {
      const payload = await importSettings(settingsExport, buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings imported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setImportingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);

  const executeResetSettings = useCallback(async (proof?: SettingsSaveProofCredentials) => {
    setResettingSettings(true);
    setActionMessage(null);
    try {
      const payload = await resetSettings(buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings reset to defaults.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to reset settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setResettingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);

  const handleProofModalConfirm = useCallback(async (proof: SettingsSaveProofCredentials) => {
    if (pendingProofAction === null) {
      return;
    }
    setProofModalPending(true);
    setProofModalError(null);
    try {
      if (pendingProofAction.kind === "save") {
        await executeSave(proof);
      } else if (pendingProofAction.action === "import-settings") {
        if (pendingProofAction.importExport === undefined) {
          throw new Error("Missing settings import payload.");
        }
        await executeImportSettings(pendingProofAction.importExport, proof);
      } else if (pendingProofAction.action === "reset-settings") {
        await executeResetSettings(proof);
      } else {
        await executeMaintenanceWithProof(pendingProofAction.action, proof);
      }
      setProofModalOpen(false);
      setPendingProofAction(null);
    } catch (error) {
      setProofModalError(error instanceof Error ? error.message : "Unable to continue.");
    } finally {
      setProofModalPending(false);
    }
  }, [pendingProofAction, executeSave, executeImportSettings, executeResetSettings, executeMaintenanceWithProof]);

  const handleSave = useCallback(() => {
    if (draft === null) {
      return;
    }
    const savedGateConfig = savedSettingsRef.current?.approval_gate ?? null;
    const proofKind = resolveSettingsSaveProofKind({
      savedGateEnabled: savedGateConfig?.enabled === true,
      wasConfigured: savedGateConfig?.configured === true,
      draftGateEnabled: approvalGateEnabled,
      changingPassword: false,
    });
    if (requiresSettingsSaveProof(proofKind)) {
      openProofModal(proofKind!, { kind: "save" });
      return;
    }
    void executeSave();
  }, [approvalGateEnabled, draft, executeSave, openProofModal]);

  const handleOpenPasswordChangeModal = useCallback(() => {
    openProofModal("change-password", { kind: "save" });
  }, [openProofModal]);

  const handleRequestRevokeCooldown = useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "revoke-cooldown" });
  }, [openProofModal]);

  const handleRequestDisableTotp = useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "disable-totp" });
  }, [openProofModal]);

  const handleStartTotpEnrollment = useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    setTotpActionPending("enroll");
    setTotpActionError(null);
    try {
      const payload = await enrollApprovalGateTotp(
        totpActionPassword,
        approvalGateTotpDeviceLabel.trim() || "local-device"
      );
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== undefined) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setTotpEnrollment(payload.enrollment ?? null);
      setTotpSetupStep("scan");
      setTotpSetupOpen(payload.enrollment !== undefined && payload.enrollment !== null);
      setActionMessage("Scan the QR code, then enter a live code from your app.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to start TOTP enrollment.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpDeviceLabel, onApprovalGateChange]);

  const handleVerifyTotpEnrollment = useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the six-digit code from your authenticator app.");
      return;
    }
    setTotpActionPending("verify");
    setTotpActionError(null);
    try {
      const payload = await verifyApprovalGateTotp(totpActionPassword, approvalGateTotpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== undefined) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app connected.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to verify TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpCode, onApprovalGateChange]);

  const handleDisableTotp = useCallback(async () => {
    handleRequestDisableTotp();
  }, [handleRequestDisableTotp]);

  const handleClearApprovals = useCallback(() => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-approvals" });
      return;
    }
    setClearingApprovals(true);
    setActionMessage(null);
    void clearPolicy({ all: true })
      .then(() => {
        setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
        setActionMessageKind("success");
      })
      .catch((error: unknown) => {
        setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
        setActionMessageKind("error");
      })
      .finally(() => {
        setClearingApprovals(false);
      });
  }, [openProofModal]);

  const handleClearReviewQueue = useCallback(() => {
    if (!window.confirm("Clear the pending review queue? Guard will remove waiting items without creating allow or block decisions.")) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-queue" });
      return;
    }
    setClearingReviewQueue(true);
    setActionMessage(null);
    void clearReviewQueue(buildClearReviewQueuePayload({}))
      .then((result) => {
        setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
        setActionMessageKind("success");
      })
      .catch((error: unknown) => {
        setActionMessage(error instanceof Error ? error.message : "Unable to clear review queue.");
        setActionMessageKind("error");
      })
      .finally(() => {
        setClearingReviewQueue(false);
      });
  }, [openProofModal]);

  const handleClearEvidence = useCallback(async () => {
    if (!window.confirm("Clear the evidence log permanently? This cannot be undone.")) return;
    setClearingEvidence(true);
    setActionMessage(null);
    try {
      await clearEvidence();
      setActionMessage("Evidence log cleared.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear evidence.");
      setActionMessageKind("error");
    } finally {
      setClearingEvidence(false);
    }
  }, []);

  const handleExportDiagnostics = useCallback(async () => {
    setExporting(true);
    setActionMessage(null);
    try {
      const blob = await exportDiagnostics();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-diagnostics-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Diagnostics exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export diagnostics.");
      setActionMessageKind("error");
    } finally {
      setExporting(false);
    }
  }, []);

  const handleRepairApprovalCenter = useCallback(async () => {
    if (!window.confirm("Reset the approval center locator? The daemon will be reachable again after Guard restarts. Pending approvals are preserved.")) return;
    setRepairing(true);
    setActionMessage(null);
    try {
      await repairApprovalCenter();
      setActionMessage("Approval center repaired. Restart Guard to reconnect.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to repair approval center.");
      setActionMessageKind("error");
    } finally {
      setRepairing(false);
    }
  }, []);

  const handleExportSettings = useCallback(async () => {
    setExportingSettings(true);
    setActionMessage(null);
    try {
      const exported = await exportSettings();
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-settings-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Settings exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export settings.");
      setActionMessageKind("error");
    } finally {
      setExportingSettings(false);
    }
  }, []);

  const handleImportSettingsClick = useCallback(() => {
    settingsImportInputRef.current?.click();
  }, []);

  const handleImportSettingsFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setActionMessage(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as GuardSettingsExport;
      const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
      if (savedGateEnabled) {
        openProofModal("maintenance", {
          kind: "maintenance",
          action: "import-settings",
          importExport: parsed,
        });
        return;
      }
      await executeImportSettings(parsed);
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
    }
  }, [executeImportSettings, openProofModal]);

  const handleResetSettings = useCallback(async () => {
    if (!window.confirm("Reset all local Guard settings to defaults? This cannot be undone.")) return;
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "reset-settings" });
      return;
    }
    try {
      await executeResetSettings();
    } catch {
      // executeResetSettings already surfaces the error message.
    }
  }, [executeResetSettings, openProofModal]);

  const handleSetupNotifications = useCallback(async () => {
    setSettingUpNotifications(true);
    setActionMessage(null);
    try {
      const result = await setupDesktopNotifications();
      setNotificationSetup(result);
      if (!result.supported) {
        setActionMessage("Desktop notification setup is not available on this OS.");
        setActionMessageKind("error");
      } else if (result.settings_opened) {
        setActionMessage("Notification settings opened. Turn on alerts and sounds for Guard.");
        setActionMessageKind("success");
      } else {
        setActionMessage(
          "We could not open Settings automatically. Open System Settings > Notifications and allow alerts for Guard."
        );
        setActionMessageKind("success");
      }
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to set up notifications.");
      setActionMessageKind("error");
    } finally {
      setSettingUpNotifications(false);
    }
  }, []);

  if (state.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-10 w-64" />
        <div className="guard-skeleton h-72 w-full" />
      </div>
    );
  }
  if (state.kind === "error" || draft === null) {
    return <EmptyState title="Settings are unavailable" body={state.kind === "error" ? state.message : "Guard did not return editable settings."} tone="teach" />;
  }

  const modeHelp = protectionModeHelp(draft.mode);
  const consequenceSummary = buildConsequenceSummary(draft);
  const searchMatches = filterSettingsBySearch(searchQuery);
  const hasSearch = searchQuery.trim().length > 0;
  const riskSearchMatches = searchMatches.filter((m) => m.section === "risk");
  const visibleRiskControls = hasSearch
    ? riskControls.filter((rc) => riskSearchMatches.some((m) => m.key === rc.key))
    : riskControls;

  return (
    <div className="flex min-h-[calc(100dvh-11rem)] flex-col gap-6">
      <GuardHero
        status="neutral"
        headline="Set how hard Guard should push back"
        subheadline="Pick a security level, then fine-tune individual rules whenever you need more control."
        cta={<Tag tone="blue">{protectionModeLabel(draft.mode)}</Tag>}
      />

      <div className="relative">
        <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
        <input
          id="settings-search"
          name="settings-search"
          type="search"
          value={searchQuery}
          onChange={handleSearchChange}
          placeholder="Search settings..."
          aria-label="Search settings"
          className="w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      {hasSearch && searchMatches.length === 0 && (
        <p className="text-sm text-slate-500">No settings match your search.</p>
      )}

      {hasSearch && riskSearchMatches.length > 0 && (
        <div className="rounded-xl border border-slate-100 p-4">
          <SectionLabel>Matching fine-tuning rules</SectionLabel>
          {!isFineTuningEditable(draft.security_level) ? (
            <div className="mt-3">
              <FineTuningPresetBanner
                securityLevel={draft.security_level}
                onSwitchToCustom={handleSwitchToCustomFineTuning}
              />
            </div>
          ) : null}
          <div className="mt-3 divide-y divide-slate-100 border-t border-slate-100">
            {visibleRiskControls.map((risk) => (
              <RiskControlRow
                key={risk.key}
                risk={risk}
                value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                disabled={!isFineTuningEditable(draft.security_level)}
                onChange={handleRiskActionChange(risk.key)}
                showConsequence
              />
            ))}
          </div>
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col">
      <SettingsSectionShell
        activeTab={activeTab}
        onTabChange={handleTabChange}
        intro={
          !hasSearch && activeTab === "protection" && consequenceSummary ? (
            <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
              <div className="flex items-start gap-3">
                <HiMiniShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" aria-hidden="true" />
                <div>
                  <SectionLabel>What to expect</SectionLabel>
                  <p className="mt-1 text-sm text-slate-500">{consequenceSummary}</p>
                </div>
              </div>
            </div>
          ) : null
        }
      >
        {activeTab === "protection" && (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            <SettingsFormSection
              title="Protection level"
              description={`${securityLevelLabel(draft.security_level)} · ${protectionModeLabel(draft.mode)}`}
            >
              <fieldset className="space-y-6 border-0 p-0">
                <legend className="sr-only">Security level</legend>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  {securityLevels.map((level) => (
                    <SecurityLevelCard
                      key={level.value}
                      level={level}
                      isSelected={draft.security_level === level.value}
                      onSelect={handleSecurityLevelChange}
                    />
                  ))}
                </div>
              </fieldset>
            </SettingsFormSection>

            <SettingsFormSection title="Protection mode" description={modeHelp}>
              <fieldset className="border-0 p-0">
                <legend className="sr-only">Protection mode</legend>
                <div className="grid gap-2 py-3 sm:grid-cols-3">
                  {protectionModeChoices.map((modeChoice) => (
                    <label
                      key={modeChoice.value}
                      className={`flex min-h-11 cursor-pointer items-center justify-center rounded-lg border px-3 py-2 transition-colors ${
                        draft.mode === modeChoice.value
                          ? "border-brand-blue/25 bg-brand-blue/[0.04]"
                          : "border-transparent bg-slate-50/80 hover:bg-white"
                      }`}
                    >
                      <input
                        type="radio"
                        name="mode"
                        value={modeChoice.value}
                        checked={draft.mode === modeChoice.value}
                        onChange={handleModeChange}
                        className="sr-only"
                      />
                      <span className="text-sm font-semibold text-brand-dark">{modeChoice.label}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </SettingsFormSection>

            <SettingsFormSection title="Timing and features">
              <div className="space-y-4 py-3">
                <div>
                  <label htmlFor="approval-wait" className="guard-settings-body font-medium text-brand-dark">
                    How long to wait for your answer
                  </label>
                  <p className="guard-settings-caption text-slate-500">
                    Seconds before Guard returns control to your AI app
                  </p>
                  <input
                    id="approval-wait"
                    type="number"
                    min={0}
                    max={600}
                    value={draft.approval_wait_timeout_seconds}
                    onChange={handleTimeoutChange}
                    className="mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                  />
                </div>
                <SettingsToggleRow
                  label="Telemetry"
                  description="Share anonymized usage to improve Guard."
                  checked={draft.telemetry}
                  onChange={handleTelemetryToggle}
                />
                <SettingsToggleRow
                  label="Cloud sync"
                  description="Sync receipts and policy with Guard Cloud when connected."
                  checked={draft.sync}
                  onChange={handleSyncToggle}
                />
                <SettingsToggleRow
                  label="Billing features"
                  description="Enable paid supply-chain and blocked-install analytics."
                  checked={draft.billing}
                  onChange={handleBillingToggle}
                />
                {perfSnapshot !== null && perfSnapshot.cloud_state === "local_only" && draft.billing ? (
                  <p className="guard-settings-caption -mt-1 text-slate-500">
                    Billing features require a cloud connection. Connect this machine to access paid features.
                  </p>
                ) : null}
              </div>
            </SettingsFormSection>
          </div>
        )}

        {activeTab === "approval" && (
          <div className="flex min-h-0 flex-1 flex-col space-y-4">
            {!approvalGateEnabled ? (
              <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] px-4 py-3">
                <p className="text-sm text-brand-dark">
                  Add a password or phone app code before allow or trust changes stick.
                </p>
              </div>
            ) : null}
            <ApprovalGateCard
              enabled={approvalGateEnabled}
              gateConfig={draft.approval_gate ?? null}
              savedGateConfig={savedSettingsRef.current?.approval_gate ?? null}
              totpCode={approvalGateTotpCode}
              totpDeviceLabel={approvalGateTotpDeviceLabel}
              strictAllDecisions={approvalGateStrictAllDecisions}
              cooldownSeconds={approvalGateCooldown}
              totpEnrollment={totpEnrollment}
              totpSetupOpen={totpSetupOpen}
              totpSetupStep={totpSetupStep}
              totpActionPassword={totpActionPassword}
              totpActionPending={totpActionPending}
              totpActionError={totpActionError}
              onToggle={handleApprovalGateToggle}
              onOpenPasswordChangeModal={handleOpenPasswordChangeModal}
              onTotpCodeChange={handleApprovalGateTotpCode}
              onTotpDeviceLabelChange={handleApprovalGateTotpDeviceLabel}
              onTotpActionPasswordChange={handleTotpActionPasswordChange}
              onOpenTotpSetup={handleOpenTotpSetup}
              onCloseTotpSetup={handleCloseTotpSetup}
              onStrictAllDecisionsChange={handleApprovalGateStrictAllDecisions}
              onCooldownChange={handleApprovalGateCooldownChange}
              onStartTotpEnrollment={handleStartTotpEnrollment}
              onVerifyTotpEnrollment={handleVerifyTotpEnrollment}
              onDisableTotp={handleDisableTotp}
              onRevokeCooldown={handleRequestRevokeCooldown}
            />
          </div>
        )}

        {activeTab === "notifications" && (
          <div className="flex min-h-0 flex-1 flex-col space-y-4">
            <NotificationSetupCard
              result={notificationSetup}
              settingUp={settingUpNotifications}
              onSetup={handleSetupNotifications}
            />
            <SettingsActionMessage message={actionMessage} kind={actionMessageKind} />
          </div>
        )}

        {activeTab === "rules" && (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            {!isFineTuningEditable(draft.security_level) ? (
              <FineTuningPresetBanner
                securityLevel={draft.security_level}
                onSwitchToCustom={handleSwitchToCustomFineTuning}
              />
            ) : null}
            <SettingsFormSection
              title="Risky action types"
              description={resolveFineTuningSectionDescription(draft.security_level)}
            >
              <div className={`space-y-1 ${!isFineTuningEditable(draft.security_level) ? "opacity-60" : ""}`}>
                {riskControls.map((risk) => (
                  <RiskControlRow
                    key={risk.key}
                    risk={risk}
                    value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                    disabled={!isFineTuningEditable(draft.security_level)}
                    onChange={handleRiskActionChange(risk.key)}
                    showConsequence={isFineTuningEditable(draft.security_level)}
                  />
                ))}
                <div className="grid gap-2 border-t border-slate-100 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center">
                  <div>
                    <p className="text-sm font-medium text-brand-dark">Codex reading secret files</p>
                    <p className="text-xs text-slate-500">
                      Only for trusted projects where Codex may read .env or .npmrc without an extra prompt.
                    </p>
                  </div>
                  <SettingSelect
                    label="Codex should"
                    value={
                      draft.harness_risk_actions.codex?.local_secret_read
                      ?? draft.risk_actions.local_secret_read
                      ?? "require-reapproval"
                    }
                    options={actionOptions}
                    onChange={handleCodexSecretReadChange}
                    disabled={!isFineTuningEditable(draft.security_level)}
                  />
                </div>
              </div>
            </SettingsFormSection>

            <details className="group rounded-xl border border-slate-200 bg-slate-50/40 open:bg-white">
              <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-4 rounded-xl px-4 py-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 [&::-webkit-details-marker]:hidden">
                <span>
                  <span className="block text-sm font-semibold text-brand-dark">Advanced fallback behavior</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-slate-500">
                    Decide what happens when Guard has no remembered rule or specific risk match.
                  </span>
                </span>
                <HiMiniChevronDown className="h-5 w-5 shrink-0 text-slate-400 transition-transform group-open:rotate-180" aria-hidden="true" />
              </summary>
              <div className="border-t border-slate-100 px-4 pb-4">
                <div className="grid gap-3 py-4 sm:grid-cols-2">
                  <SettingSelect label="First-time action" value={draft.default_action} options={actionOptions} onChange={handleStringChange("default_action")} />
                  <SettingSelect label="Unknown source" value={draft.unknown_publisher_action} options={actionOptions} onChange={handleStringChange("unknown_publisher_action")} />
                  <SettingSelect label="Changed command" value={draft.changed_hash_action} options={actionOptions} onChange={handleStringChange("changed_hash_action")} />
                  <SettingSelect label="New website or host" value={draft.new_network_domain_action} options={actionOptions} onChange={handleStringChange("new_network_domain_action")} />
                  <SettingSelect label="Nested commands" value={draft.subprocess_action} options={actionOptions} onChange={handleStringChange("subprocess_action")} />
                  <SettingSelect label="Where to ask" value={draft.approval_surface_policy} options={surfacePolicyOptions} onChange={handleStringChange("approval_surface_policy")} />
                </div>
                {draft.approval_surface_policy === "attention-aware" ? (
                  <div className="grid gap-3 border-t border-slate-100 py-4 sm:grid-cols-2">
                    <SettingNumber
                      label="Browser delay"
                      value={draft.approval_browser_delay_seconds}
                      min={0}
                      max={300}
                      suffix="seconds"
                      onChange={handleNumberChange("approval_browser_delay_seconds")}
                    />
                    <SettingSelect
                      label="Open immediately for"
                      value={draft.approval_browser_immediate_severity}
                      options={attentionSeverityOptions}
                      onChange={handleStringChange("approval_browser_immediate_severity")}
                    />
                    <p className="text-xs leading-5 text-slate-500 sm:col-span-2">
                      Guard cancels the browser prompt when your AI app continues with a different action. Desktop and in-app notices still appear immediately.
                    </p>
                  </div>
                ) : null}
              </div>
            </details>
          </div>
        )}

        {activeTab === "maintenance" && (
          <div className="flex min-h-0 flex-1 flex-col space-y-6">
            <SettingsFormSection title="Keep this machine tidy" description="Export, reset, clear history, or fix a broken approval link.">
              <div className="space-y-4 py-3">
                {perfSnapshot !== null ? <DiagnosticsPerfCard snapshot={perfSnapshot} /> : null}
                <input
                  ref={settingsImportInputRef}
                  type="file"
                  accept="application/json,.json"
                  className="sr-only"
                  onChange={handleImportSettingsFile}
                  aria-hidden="true"
                  tabIndex={-1}
                />
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear saved approvals</p>
                      <p className="text-xs text-slate-500">Guard will ask again for every action that was previously approved.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearApprovals} disabled={clearingApprovals} variant="outline">
                          {clearingApprovals ? "Clearing…" : "Clear approvals"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear review queue</p>
                      <p className="text-xs text-slate-500">Removes pending review items only.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearReviewQueue} disabled={clearingReviewQueue} variant="outline">
                          {clearingReviewQueue ? "Clearing…" : "Clear review queue"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Clear evidence log</p>
                      <p className="text-xs text-slate-500">Permanently removes local audit history.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleClearEvidence} disabled={clearingEvidence} variant="outline">
                          {clearingEvidence ? "Clearing…" : "Clear evidence"}
                        </ActionButton>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Export settings</p>
                      <p className="text-xs text-slate-500">Download local Guard preferences as JSON.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleExportSettings} disabled={exportingSettings} variant="secondary">
                          {exportingSettings ? "Exporting…" : "Export settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Import settings</p>
                      <p className="text-xs text-slate-500">Restore preferences from a Guard settings export file.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleImportSettingsClick} disabled={importingSettings} variant="secondary">
                          {importingSettings ? "Importing…" : "Import settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Export diagnostics</p>
                      <p className="text-xs text-slate-500">Download evidence and runtime details for support.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleExportDiagnostics} disabled={exporting} variant="secondary">
                          {exporting ? "Exporting…" : "Export diagnostics"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Reset to defaults</p>
                      <p className="text-xs text-slate-500">Restore factory local settings on this machine.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleResetSettings} disabled={resettingSettings} variant="outline">
                          {resettingSettings ? "Resetting…" : "Reset settings"}
                        </ActionButton>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-brand-dark">Repair approval center</p>
                      <p className="text-xs text-slate-500">Use when the approval link fails after Guard restarts.</p>
                      <div className="mt-2">
                        <ActionButton onClick={handleRepairApprovalCenter} disabled={repairing} variant="secondary">
                          {repairing ? "Repairing…" : "Repair"}
                        </ActionButton>
                      </div>
                    </div>
                  </div>
                </div>
                <SettingsActionMessage message={actionMessage} kind={actionMessageKind} />
              </div>
            </SettingsFormSection>
          </div>
        )}
      </SettingsSectionShell>
      </div>

      <div
        className="sticky bottom-2 mt-auto rounded-xl border border-slate-200 bg-white/95 p-3 shadow-lg backdrop-blur sm:bottom-4 sm:p-4"
        role="region"
        aria-label="Save settings"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <ActionButton onClick={handleSave} disabled={saving || saveSuccess}>
              {saveSuccess ? (
                <span className="flex items-center gap-2">
                  <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                  Saved
                </span>
              ) : saving ? "Saving…" : "Save settings"}
            </ActionButton>
            {hasUnsavedChanges(savedSettingsRef.current, draft) && (
              <span className="ml-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention">
                <span className="h-1.5 w-1.5 rounded-full bg-brand-attention" />
                Unsaved changes
              </span>
            )}
          </div>
          {saveSuccess ? (
            <p className="text-sm font-semibold text-emerald-600">Settings saved</p>
          ) : saveError ? (
            <p className="text-sm text-brand-purple">{saveError}</p>
          ) : (
            <p className="hidden text-xs text-slate-500 sm:block">Use this for local tuning. Team policy from Guard Cloud may still override some decisions.</p>
          )}
          <div aria-live="polite" aria-atomic="true" className="sr-only">
            {saveStatusText(saveSuccess, saveError)}
          </div>
        </div>
      </div>

      {proofModalOpen && pendingProofAction !== null ? (
        <SettingsSaveProofModal
          open={proofModalOpen}
          mode={proofModalMode}
          gate={savedSettingsRef.current?.approval_gate ?? null}
          {...resolveSettingsSaveProofModalCopy({
            mode: proofModalMode,
            gateSettingsChanged: hasApprovalGateSettingsChanged(
              savedSettingsRef.current?.approval_gate ?? null,
              approvalGateEnabled,
              approvalGateCooldown,
              approvalGateStrictAllDecisions,
            ),
            maintenanceAction: pendingProofAction.kind === "maintenance"
              ? pendingProofAction.action
              : undefined,
          })}
          error={proofModalError}
          pending={proofModalPending || saving || importingSettings || resettingSettings}
          onCancel={closeProofModal}
          onConfirm={handleProofModalConfirm}
        />
      ) : null}

      {pendingMode === "observe" && (
        <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl">
            <div className="flex items-start gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10">
                <HiMiniExclamationTriangle className="h-5 w-5 text-brand-attention" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-brand-dark">Switch to Watch only?</h3>
                <p className="mt-2 text-sm text-slate-500">In Watch only mode, Guard records what your AI apps do but does not pause anything. Use this only when debugging or in a fully trusted environment.</p>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <button onClick={confirmModeChange} className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90">Switch to Watch only</button>
              <button onClick={cancelModeChange} className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50">Keep current mode</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SettingsActionMessage(props: { message: string | null; kind: "success" | "error" }) {
  if (props.message === null) {
    return null;
  }
  return (
    <div
      className={`rounded-xl border px-4 py-3 text-sm font-medium ${
        props.kind === "error"
          ? "border-brand-attention/20 bg-brand-attention/[0.04] text-brand-dark"
          : "border-brand-blue/15 bg-brand-blue/[0.04] text-brand-dark"
      }`}
      role={props.kind === "error" ? "alert" : "status"}
    >
      {props.message}
    </div>
  );
}

function DiagnosticsPerfCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return (
    <div className="rounded-lg bg-slate-50/80 px-3 py-2">
      <p className="text-xs font-semibold text-brand-dark">Background service</p>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        {threadCount !== undefined && <span>{threadCount} worker threads</span>}
        {daemonPort !== null && <span>Local port {daemonPort}</span>}
        {startedAt !== null && <span>Running since {new Date(startedAt).toLocaleTimeString()}</span>}
      </div>
    </div>
  );
}

function NotificationSetupCard(props: {
  result: GuardNotificationSetupResult | null;
  settingUp: boolean;
  onSetup: () => void;
}) {
  return (
    <div className="rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-5">
      <div className="flex gap-4">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
          <HiMiniBellAlert className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1 space-y-4">
          <div>
            <p className="text-sm font-semibold text-brand-dark">Desktop alerts</p>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-500">
              When Guard pauses something, a banner helps you respond without hunting for this tab.
            </p>
          </div>
          <ol className="grid gap-2 text-xs text-slate-600 sm:grid-cols-3">
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">1. Open notification settings.</li>
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">2. Allow alerts for Guard.</li>
            <li className="rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100">3. Turn on banners and sound.</li>
          </ol>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
            <div className="flex flex-wrap gap-2">
              {props.result ? (
                <>
                  <Tag tone={props.result.supported ? "blue" : "slate"}>
                    {props.result.supported ? "Supported on this Mac" : "Not supported here"}
                  </Tag>
                  <Tag tone={props.result.preview_sent ? "blue" : "slate"}>
                    {props.result.preview_sent ? "Test alert sent" : "No test alert yet"}
                  </Tag>
                  <Tag tone={props.result.settings_opened ? "blue" : "slate"}>
                    {props.result.settings_opened ? "Settings opened" : "Settings not opened"}
                  </Tag>
                </>
              ) : (
                <Tag tone="slate">Not set up yet</Tag>
              )}
            </div>
            <button
              type="button"
              onClick={props.onSetup}
              disabled={props.settingUp}
              className="inline-flex min-h-9 shrink-0 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-semibold text-brand-dark transition-colors hover:border-brand-blue/30 hover:bg-slate-50 disabled:pointer-events-none disabled:opacity-50"
            >
              {props.settingUp ? "Opening…" : "Set up alerts"}
            </button>
          </div>
          {props.result?.guidance ? (
            <p className="text-xs leading-relaxed text-slate-500">{props.result.guidance}</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function SettingSelect(props: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  disabled?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-slate-500">{props.label}</span>
      <select
        value={props.value}
        onChange={props.onChange}
        disabled={props.disabled}
        className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {props.options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function SettingNumber(props: {
  label: string;
  value: number;
  min: number;
  max: number;
  suffix: string;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  const inputId = `setting-${props.label.toLowerCase().replaceAll(" ", "-")}`;
  return (
    <label htmlFor={inputId} className="space-y-2">
      <span className="block text-sm font-medium text-brand-dark">{props.label}</span>
      <span className="flex min-h-11 items-center rounded-lg border border-slate-200 bg-white focus-within:border-brand-blue focus-within:ring-1 focus-within:ring-brand-blue/20">
        <input
          id={inputId}
          type="number"
          min={props.min}
          max={props.max}
          value={props.value}
          onChange={props.onChange}
          className="min-w-0 flex-1 bg-transparent px-3 py-2 text-sm text-brand-dark focus:outline-none"
        />
        <span className="border-l border-slate-100 px-3 text-xs text-slate-500">{props.suffix}</span>
      </span>
    </label>
  );
}

function SettingToggle(props: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label htmlFor={props.id} className="flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 transition-colors hover:bg-slate-100/60">
      <span className="text-sm text-brand-dark">{props.label}</span>
      <input id={props.id} name={props.id} type="checkbox" checked={props.checked} onChange={props.onChange} className="h-4 w-4 accent-brand-blue" />
    </label>
  );
}

function FineTuningPresetBanner(props: {
  securityLevel: GuardSettings["security_level"];
  onSwitchToCustom: () => void;
}) {
  if (isFineTuningEditable(props.securityLevel)) return null;

  return (
    <div
      className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-4 sm:flex sm:items-center sm:justify-between sm:gap-4"
      role="region"
      aria-label="Fine-tuning preset controls"
    >
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">
          Using the {securityLevelLabel(props.securityLevel)} preset
        </p>
        <p className="mt-1 text-sm text-slate-500">
          Individual rules match this preset. Switch to Custom to change how Guard handles each risky action type on this machine.
        </p>
      </div>
      <div className="mt-3 w-full shrink-0 sm:mt-0 sm:w-auto">
        <ActionButton onClick={props.onSwitchToCustom}>Use Custom fine-tuning</ActionButton>
      </div>
    </div>
  );
}

type SecurityLevelCardProps = {
  level: (typeof securityLevels)[number];
  isSelected: boolean;
  onSelect: (value: "relaxed" | "balanced" | "strict" | "custom") => void;
};

function SecurityLevelCard({ level, isSelected, onSelect }: SecurityLevelCardProps) {
  const LevelIcon = level.icon;
  const toneClasses = getSecurityToneClasses(level.tone);
  const iconColorClass = toneClasses.icon;
  const iconBgClass = toneClasses.iconBg;
  const selectedBorderClass = toneClasses.selected;

  const handleClick = useCallback(() => onSelect(level.value), [onSelect, level.value]);

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-pressed={isSelected}
      className={`relative rounded-xl border p-4 text-left transition-all duration-150 hover:-translate-y-0.5 ${isSelected ? selectedBorderClass : "border-transparent bg-slate-50/80 hover:bg-white"}`}
    >
      {isSelected && (
        <span className="absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-emerald-600">
          <HiMiniCheckCircle className="h-3.5 w-3.5 text-white" aria-hidden="true" />
        </span>
      )}
      <span className={`inline-flex h-8 w-8 items-center justify-center rounded-lg ${iconBgClass}`}>
        <LevelIcon className={`h-4 w-4 ${iconColorClass}`} aria-hidden="true" />
      </span>
      <span className="mt-2 block text-sm font-semibold text-brand-dark">{level.label}</span>
      <span className="mt-1 block text-xs leading-relaxed text-slate-500">{level.description}</span>
      {level.protects.length > 0 && (
        <ul className="mt-2 space-y-0.5">
          {level.protects.map((item) => (
            <li key={item} className="flex items-center gap-1.5 text-[11px] text-slate-500">
              <span className={`h-1 w-1 shrink-0 rounded-full ${iconColorClass}`} />
              {item}
            </li>
          ))}
        </ul>
      )}
    </button>
  );
}

type RiskControlRowProps = {
  risk: { key: string; label: string; description: string; consequence?: { example: string; impact: string } | undefined };
  value: string;
  disabled: boolean;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  showConsequence?: boolean;
};

function RiskControlRow({ risk, value, disabled, onChange, showConsequence }: RiskControlRowProps) {
  return (
    <div className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-start">
      <div>
        <p className="text-sm font-medium text-brand-dark">{risk.label}</p>
        <p className="text-xs text-slate-500">{risk.description}</p>
        {showConsequence && risk.consequence && (
          <p className="mt-1 text-xs text-slate-400">
            <span className="font-medium">Example:</span> {risk.consequence.example}
          </p>
        )}
        {showConsequence && risk.consequence && (
          <p className="mt-0.5 text-xs text-slate-400">{risk.consequence.impact}</p>
        )}
      </div>
      <SettingSelect label="Guard should" value={value} options={actionOptions} onChange={onChange} disabled={disabled} />
    </div>
  );
}

const cooldownOptions = [
  { value: "0", label: approvalGateCooldownLabel(0) },
  { value: "900", label: approvalGateCooldownLabel(900) },
  { value: "3600", label: approvalGateCooldownLabel(3600) },
];

type ApprovalGateCardProps = {
  enabled: boolean;
  gateConfig: GuardApprovalGatePublicConfig | null;
  savedGateConfig: GuardApprovalGatePublicConfig | null;
  totpCode: string;
  totpDeviceLabel: string;
  strictAllDecisions: boolean;
  cooldownSeconds: number;
  totpEnrollment: GuardApprovalGateTotpEnrollment | null;
  totpSetupOpen: boolean;
  totpSetupStep: TotpSetupStep;
  totpActionPassword: string;
  totpActionPending: "enroll" | "verify" | "disable" | null;
  totpActionError: string | null;
  onToggle: (event: ChangeEvent<HTMLInputElement>) => void;
  onOpenPasswordChangeModal: () => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onOpenTotpSetup: () => void;
  onCloseTotpSetup: () => void;
  onStrictAllDecisionsChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCooldownChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  onStartTotpEnrollment: () => void;
  onVerifyTotpEnrollment: () => void;
  onDisableTotp: () => void;
  onRevokeCooldown: () => void;
};

function ApprovalGateCard(props: ApprovalGateCardProps) {
  const wasConfigured = props.savedGateConfig?.configured === true;
  const gateSettingsChanged = hasApprovalGateSettingsChanged(
    props.savedGateConfig,
    props.enabled,
    props.cooldownSeconds,
    props.strictAllDecisions,
  );
  const showGateDetails = props.enabled || gateSettingsChanged;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const totpEnabled = props.gateConfig?.totp_enabled === true;
  const totpPending = props.gateConfig?.totp_pending === true;
  const failClosed = props.gateConfig?.fail_closed === true;
  const cooldownLabel = cooldownExpiresAt
    ? new Date(cooldownExpiresAt).toLocaleTimeString()
    : null;

  return (
    <div className="space-y-4 rounded-xl border border-slate-100 bg-slate-50/40 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <SettingToggle
            id="settings-approval-gate"
            label="Ask for proof on allow decisions"
            checked={props.enabled}
            onChange={props.onToggle}
          />
          <p className="mt-1 text-xs text-slate-500">
            Use a password before allow or trust changes stick. Turn on strict mode to require proof for block decisions too.
          </p>
        </div>
      </div>

      {failClosed && props.enabled && (
        <div className="rounded-lg border border-brand-purple/20 bg-brand-purple/[0.04] px-3 py-2">
          <p className="text-xs text-brand-purple">
            Guard needs your approval setup fixed before trust or policy changes can continue.
          </p>
        </div>
      )}

      {showGateDetails ? (
        <div className="space-y-3">
          <div className="rounded-xl border border-slate-100 bg-white p-4">
            <SectionLabel>Approval password</SectionLabel>
            <p className="mt-1 text-xs text-slate-500">{resolveApprovalPasswordSectionCopy(wasConfigured)}</p>
            {wasConfigured ? (
              <div className="mt-3">
                <button
                  type="button"
                  onClick={props.onOpenPasswordChangeModal}
                  className="text-xs font-medium text-brand-blue transition-colors hover:text-brand-blue/80"
                >
                  Change password
                </button>
              </div>
            ) : null}
          </div>

          <div className="rounded-xl border border-slate-100 bg-white p-4">
            <SectionLabel>Extra checks</SectionLabel>
            <div className="mt-3 space-y-3">
              <SettingToggle
                id="settings-approval-gate-strict"
                label="Also ask before block decisions"
                checked={props.strictAllDecisions}
                onChange={props.onStrictAllDecisionsChange}
              />
              <label className="block">
                <span className="text-xs font-medium text-slate-500">Cooldown after approval</span>
                <select
                  value={String(props.cooldownSeconds)}
                  onChange={props.onCooldownChange}
                  className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                >
                  {cooldownOptions.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </label>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-brand-blue/15 bg-white">
            <div className="flex items-center justify-between gap-2">
              <div className="px-4 py-3">
                <SectionLabel>Authenticator app</SectionLabel>
                <p className="mt-1 max-w-xl text-xs leading-5 text-slate-500">
                  Add a six-digit code from Google Authenticator, 1Password, Authy, or iCloud Passwords for high-risk approvals.
                </p>
              </div>
              <div className="px-4">
                <Tag tone={totpEnabled ? "green" : totpPending ? "blue" : "slate"}>
                  {totpEnabled ? "Enabled" : totpPending ? "Pending verification" : "Not connected"}
                </Tag>
              </div>
            </div>
            <div className="border-t border-slate-100 bg-slate-50/50 px-4 py-3">
              {!totpEnabled && !totpPending && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="max-w-xl space-y-1">
                    <p className="text-sm font-medium text-brand-dark">Add a second factor for high-risk approvals.</p>
                    <p className="text-xs text-slate-500">
                      Setup opens a guided flow for password confirmation, then QR scan.
                    </p>
                  </div>
                  <ActionButton
                    onClick={props.onOpenTotpSetup}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    Set up authenticator
                  </ActionButton>
                </div>
              )}
              {totpPending && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="max-w-xl space-y-1">
                    <p className="text-sm font-medium text-brand-dark">Finish connecting your authenticator app.</p>
                    <p className="text-xs text-slate-500">
                      Open setup to scan the QR code and enter a live six-digit code.
                    </p>
                  </div>
                  <ActionButton
                    onClick={props.onOpenTotpSetup}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    Continue setup
                  </ActionButton>
                </div>
              )}
              {totpEnabled && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="max-w-xl text-xs text-slate-500">
                    Disconnecting removes the app code requirement from future high-risk approvals.
                  </p>
                  <ActionButton
                    onClick={props.onDisableTotp}
                    disabled={props.totpActionPending !== null}
                    variant="outline"
                  >
                    {props.totpActionPending === "disable" ? "Disconnecting..." : "Disconnect authenticator"}
                  </ActionButton>
                </div>
              )}
              {props.totpActionError !== null && !props.totpSetupOpen && (
                <p className="mt-2 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
                  {props.totpActionError}
                </p>
              )}
            </div>
            {props.totpSetupOpen && (
              <TotpSetupModal
                step={props.totpSetupStep}
                enrollment={props.totpEnrollment}
                deviceLabel={props.totpDeviceLabel}
                actionPassword={props.totpActionPassword}
                totpCode={props.totpCode}
                pending={props.totpActionPending}
                error={props.totpActionError}
                onActionPasswordChange={props.onTotpActionPasswordChange}
                onDeviceLabelChange={props.onTotpDeviceLabelChange}
                onTotpCodeChange={props.onTotpCodeChange}
                onConfirmPassword={props.onStartTotpEnrollment}
                onVerify={props.onVerifyTotpEnrollment}
                onClose={props.onCloseTotpSetup}
              />
            )}
          </div>

          {cooldownActive && cooldownLabel !== null && (
            <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4">
              <SectionLabel>Active cooldown</SectionLabel>
              <p className="mt-1 text-xs text-brand-dark">Cooldown active until {cooldownLabel}</p>
              <div className="mt-3">
                <ActionButton onClick={props.onRevokeCooldown} variant="outline">
                  Revoke cooldown
                </ActionButton>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}

function TotpSetupConfirmStep(props: {
  actionPassword: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmPassword: () => void;
}) {
  return (
    <div className="space-y-4 p-6">
      <label className="block">
        <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={props.actionPassword}
          onChange={props.onActionPasswordChange}
          onKeyDown={(event) => {
            if (
              event.key === "Enter"
              && props.actionPassword.trim().length > 0
              && props.pending === null
            ) {
              props.onConfirmPassword();
            }
          }}
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>
      {props.error !== null && (
        <p className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
          {props.error}
        </p>
      )}
      <ActionButton onClick={props.onConfirmPassword} disabled={props.pending !== null}>
        {props.pending === "enroll" ? "Continuing..." : "Continue"}
      </ActionButton>
    </div>
  );
}

function TotpSetupScanStep(props: {
  enrollment: GuardApprovalGateTotpEnrollment;
  deviceLabel: string;
  actionPassword: string;
  totpCode: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onVerify: () => void;
}) {
  return (
    <div className="grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_260px]">
      <TotpEnrollmentQrPanel enrollment={props.enrollment} />
      <div className="space-y-4 rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={props.actionPassword}
            onChange={props.onActionPasswordChange}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
          <p className="mt-1 text-xs text-slate-500">
            Update this if you changed your approval password after starting setup.
          </p>
        </label>
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Device label</span>
          <input
            type="text"
            value={props.deviceLabel}
            onChange={props.onDeviceLabelChange}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Six-digit code</span>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={props.totpCode}
            onChange={props.onTotpCodeChange}
            onKeyDown={(event) => {
              if (
                event.key === "Enter"
                && props.totpCode.trim().length > 0
                && props.pending === null
              ) {
                props.onVerify();
              }
            }}
            placeholder="123456"
            className="mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        {props.error !== null && (
          <p className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
            {props.error}
          </p>
        )}
        <ActionButton onClick={props.onVerify} disabled={props.pending !== null}>
          {props.pending === "verify" ? "Verifying..." : "Finish setup"}
        </ActionButton>
      </div>
    </div>
  );
}

function TotpSetupModal(props: {
  step: TotpSetupStep;
  enrollment: GuardApprovalGateTotpEnrollment | null;
  deviceLabel: string;
  actionPassword: string;
  totpCode: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmPassword: () => void;
  onVerify: () => void;
  onClose: () => void;
}) {
  const modalRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, modalRef);
  const isConfirmStep = props.step === "confirm" || props.enrollment === null;
  const stepLabel = isConfirmStep ? "1" : "2";

  return (
    <div
      className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/45 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Set up authenticator app"
    >
      <div ref={modalRef} className="w-full max-w-3xl overflow-hidden rounded-3xl border border-brand-blue/15 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5">
          <div>
            <SectionLabel>Authenticator setup</SectionLabel>
            <p className="mt-2 text-xs font-medium uppercase tracking-[0.16em] text-slate-500">
              Step {stepLabel} of 2
            </p>
            <h3 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">
              {resolveTotpSetupModalTitle(isConfirmStep)}
            </h3>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              {resolveTotpSetupModalDescription(isConfirmStep)}
            </p>
          </div>
          <button
            type="button"
            onClick={props.onClose}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark"
            aria-label="Close authenticator setup"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        {isConfirmStep ? (
          <TotpSetupConfirmStep
            actionPassword={props.actionPassword}
            pending={props.pending}
            error={props.error}
            onActionPasswordChange={props.onActionPasswordChange}
            onConfirmPassword={props.onConfirmPassword}
          />
        ) : null}
        {!isConfirmStep && props.enrollment !== null ? (
          <TotpSetupScanStep
            enrollment={props.enrollment}
            deviceLabel={props.deviceLabel}
            actionPassword={props.actionPassword}
            totpCode={props.totpCode}
            pending={props.pending}
            error={props.error}
            onActionPasswordChange={props.onActionPasswordChange}
            onDeviceLabelChange={props.onDeviceLabelChange}
            onTotpCodeChange={props.onTotpCodeChange}
            onVerify={props.onVerify}
          />
        ) : null}
      </div>
    </div>
  );
}
