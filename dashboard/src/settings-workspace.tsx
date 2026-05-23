import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniCog6Tooth,
  HiMiniCheckCircle,
  HiMiniInformationCircle,
  HiMiniExclamationTriangle,
  HiMiniBellAlert,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniMagnifyingGlass,
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
  exportDiagnostics,
  fetchRuntimeSnapshot,
  fetchSettings,
  updateSettings,
  clearPolicy,
  repairApprovalCenter,
  setupDesktopNotifications,
  revokeApprovalGateCooldown,
} from "./guard-api";
import { approvalGateCooldownLabel } from "./approval-gate-utils";
import { resolveProtectionLevelCopy } from "./runtime-overview";
import { RISK_CONTROL_CONSEQUENCES, filterSettingsBySearch, securityLevelLabel } from "./apps/app-catalog";
import type {
  GuardApprovalGatePublicConfig,
  GuardNotificationSetupResult,
  GuardRuntimeSnapshot,
  GuardSettings,
  GuardSettingsPayload,
} from "./guard-types";

export const resolveSecurityLevelDescription = resolveProtectionLevelCopy;

export function resolveSecurityLevelCardDescription(level: "relaxed" | "balanced" | "strict" | "custom"): string {
  if (level === "relaxed") return "Warn on dangerous actions. Most safe actions run without a prompt.";
  if (level === "balanced") return "Ask before secret access, hidden execution, exfiltration, and destructive actions.";
  if (level === "strict") return "Ask more often, including new network destinations.";
  return "Use the exact choices below for this machine and connected apps.";
}

export function buildClearPolicyPayload(all: boolean): { harness?: string; all?: boolean } {
  return { all };
}

type SettingsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; payload: GuardSettingsPayload };

const actionOptions = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Warn" },
  { value: "review", label: "Review" },
  { value: "require-reapproval", label: "Ask again" },
  { value: "sandbox-required", label: "Require sandbox" },
  { value: "block", label: "Block" }
];

const surfacePolicyOptions = [
  { value: "auto-open-once", label: "Open approval center once" },
  { value: "approval-center", label: "Approval center only" },
  { value: "native-only", label: "Harness prompt only" }
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
  { key: "mcp_dangerous_tool", label: "MCP tools", description: "MCP server and tool calls that can touch files, shell, or network.", consequence: RISK_CONTROL_CONSEQUENCES["mcp_dangerous_tool"] },
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

function hasUnsavedChanges(saved: GuardSettings | null, draft: GuardSettings | null): boolean {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
}

function protectionModeHelp(mode: GuardSettings["mode"]): string {
  if (mode === "enforce") {
    return "Guard blocks risky actions until a saved decision allows them.";
  }
  if (mode === "observe") {
    return "Guard records what it sees without pausing actions.";
  }
  return "Guard asks before risky actions continue.";
}

function saveStatusText(saveSuccess: boolean, saveError: string | null): string {
  if (saveSuccess) {
    return "Settings saved successfully.";
  }
  return saveError ?? "";
}

export function SettingsWorkspace() {
  const [state, setState] = useState<SettingsState>({ kind: "loading" });
  const [draft, setDraft] = useState<GuardSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [clearingApprovals, setClearingApprovals] = useState(false);
  const [clearingEvidence, setClearingEvidence] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [repairing, setRepairing] = useState(false);
  const [settingUpNotifications, setSettingUpNotifications] = useState(false);
  const [notificationSetup, setNotificationSetup] = useState<GuardNotificationSetupResult | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [perfSnapshot, setPerfSnapshot] = useState<GuardRuntimeSnapshot | null>(null);
  const [pendingMode, setPendingMode] = useState<GuardSettings["mode"] | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({ "protection": true, "risk": false, "diagnostics": false });
  const saveSuccessTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedSettingsRef = useRef<GuardSettings | null>(null);
  const [approvalGateEnabled, setApprovalGateEnabled] = useState(false);
  const [approvalGateNewPassword, setApprovalGateNewPassword] = useState("");
  const [approvalGateConfirmPassword, setApprovalGateConfirmPassword] = useState("");
  const [approvalGateCurrentPassword, setApprovalGateCurrentPassword] = useState("");
  const [approvalGateCooldown, setApprovalGateCooldown] = useState(0);
  const [revokingCooldown, setRevokingCooldown] = useState(false);
  const [revokePassword, setRevokePassword] = useState("");
  const [revokeError, setRevokeError] = useState<string | null>(null);

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
          }
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
        }
      });
    return () => { cancelled = true; };
  }, []);

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

  const toggleSection = useCallback((key: string) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const handleToggleProtection = useCallback(() => toggleSection("protection"), [toggleSection]);
  const handleToggleRisk = useCallback(() => toggleSection("risk"), [toggleSection]);
  const handleToggleDiagnostics = useCallback(() => toggleSection("diagnostics"), [toggleSection]);

  const handleAdvancedToggle = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setShowAdvanced(event.target.checked);
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

  const handleApprovalGateToggle = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateEnabled(event.target.checked);
    setSaveError(null);
  }, []);

  const handleApprovalGateNewPassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateNewPassword(event.target.value);
  }, []);

  const handleApprovalGateConfirmPassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateConfirmPassword(event.target.value);
  }, []);

  const handleApprovalGateCurrentPassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalGateCurrentPassword(event.target.value);
  }, []);

  const handleApprovalGateCooldownChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setApprovalGateCooldown(Number(event.target.value));
    setSaveError(null);
  }, []);

  const handleRevokePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setRevokePassword(event.target.value);
    setRevokeError(null);
  }, []);

  const handleRevokeCooldown = useCallback(async () => {
    setRevokingCooldown(true);
    setRevokeError(null);
    try {
      await revokeApprovalGateCooldown(revokePassword);
      setRevokePassword("");
      setActionMessage("Cooldown revoked successfully.");
    } catch (error) {
      setRevokeError(error instanceof Error ? error.message : "Unable to revoke cooldown.");
    } finally {
      setRevokingCooldown(false);
    }
  }, [revokePassword]);

  const handleSave = useCallback(async () => {
    if (draft === null) return;
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const approvalGateUpdate: GuardApprovalGatePublicConfig & {
        current_password?: string;
        new_password?: string;
        confirm_password?: string;
      } = {
        enabled: approvalGateEnabled,
        configured: draft.approval_gate?.configured ?? false,
        cooldown_seconds: approvalGateCooldown,
        cooldown_active: draft.approval_gate?.cooldown_active ?? false,
        cooldown_expires_at: draft.approval_gate?.cooldown_expires_at ?? null,
        locked_until: draft.approval_gate?.locked_until ?? null,
        fail_closed: draft.approval_gate?.fail_closed ?? false,
        strict_all_decisions: draft.approval_gate?.strict_all_decisions ?? false,
        ...(approvalGateCurrentPassword ? { current_password: approvalGateCurrentPassword } : {}),
        ...(approvalGateNewPassword ? { new_password: approvalGateNewPassword } : {}),
        ...(approvalGateConfirmPassword ? { confirm_password: approvalGateConfirmPassword } : {}),
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
      setSaveSuccess(true);
      setApprovalGateNewPassword("");
      setApprovalGateCurrentPassword("");
      setApprovalGateConfirmPassword("");
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
      saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2000);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      setSaving(false);
    }
  }, [draft, approvalGateEnabled, approvalGateCooldown, approvalGateCurrentPassword, approvalGateNewPassword, approvalGateConfirmPassword]);

  const handleClearApprovals = useCallback(async () => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) return;
    setClearingApprovals(true);
    setActionMessage(null);
    try {
      await clearPolicy({ all: true, approval_password: approvalGateCurrentPassword || undefined });
      setActionMessage("All saved approvals cleared.");
      setApprovalGateCurrentPassword("");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
    } finally {
      setClearingApprovals(false);
    }
  }, [approvalGateCurrentPassword]);

  const handleClearEvidence = useCallback(async () => {
    if (!window.confirm("Clear the evidence log permanently? This cannot be undone.")) return;
    setClearingEvidence(true);
    setActionMessage(null);
    try {
      await clearEvidence();
      setActionMessage("Evidence log cleared.");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear evidence.");
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
      anchor.click();
      URL.revokeObjectURL(url);
      setActionMessage("Diagnostics exported.");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export diagnostics.");
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
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to repair approval center.");
    } finally {
      setRepairing(false);
    }
  }, []);

  const handleSetupNotifications = useCallback(async () => {
    setSettingUpNotifications(true);
    setActionMessage(null);
    try {
      const result = await setupDesktopNotifications();
      setNotificationSetup(result);
      if (!result.supported) {
        setActionMessage("Desktop notification setup is not available on this OS.");
      } else if (result.settings_opened) {
        setActionMessage("Notification settings opened. Enable terminal-notifier alerts, banners, and sounds.");
      } else {
        setActionMessage(
          "Notification setup ran, but macOS did not open Settings. Open System Settings > Notifications and choose terminal-notifier."
        );
      }
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to set up notifications.");
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
    <div className="space-y-6">
      <GuardHero
        status="clear"
        headline="Choose how protective Guard should be"
        subheadline="Start with a simple security level, then tune exact risk types when a trusted app needs more room to work."
        cta={<Tag tone="blue">{draft.mode}</Tag>}
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
          <SectionLabel>Risk controls matching search</SectionLabel>
          <div className="mt-3 divide-y divide-slate-100 border-t border-slate-100">
            {visibleRiskControls.map((risk) => (
              <RiskControlRow
                key={risk.key}
                risk={risk}
                value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                disabled={draft.security_level !== "custom"}
                onChange={handleRiskActionChange(risk.key)}
                showConsequence
              />
            ))}
          </div>
        </div>
      )}

      {!hasSearch && consequenceSummary && (
        <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
          <div className="flex items-start gap-3">
            <HiMiniShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
            <div>
              <SectionLabel>What to expect</SectionLabel>
              <p className="mt-1 text-sm text-slate-500">{consequenceSummary}</p>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-2" role="region" aria-label="Settings sections">
        <AccordionSection
          title="Protection level"
          subtitle={`${securityLevelLabel(draft.security_level)} · ${draft.mode}`}
          expanded={expandedSections["protection"]}
          onToggle={handleToggleProtection}
          sectionId="protection"
        >
          <fieldset className="space-y-6">
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

            <div>
              <SectionLabel>Protection mode</SectionLabel>
              <fieldset className="mt-2 grid gap-2 sm:grid-cols-3">
                <legend className="sr-only">Protection mode</legend>
                {(["prompt", "enforce", "observe"] as const).map((mode) => (
                  <label
                    key={mode}
                    className={`cursor-pointer rounded-lg border p-3 transition-all ${draft.mode === mode ? "border-brand-blue/25 bg-brand-blue/[0.04]" : "border-transparent bg-slate-50/80 hover:bg-white"}`}
                  >
                    <input type="radio" name="mode" value={mode} checked={draft.mode === mode} onChange={handleModeChange} className="sr-only" />
                    <span className="text-sm font-semibold capitalize text-brand-dark">{mode}</span>
                  </label>
                ))}
              </fieldset>
              <p className="mt-2 text-sm text-slate-500">{modeHelp}</p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="approval-wait" className="block text-sm font-semibold text-brand-dark">Approval wait timeout</label>
                <p className="text-xs text-slate-500">Seconds to wait before returning to the app</p>
                <input id="approval-wait" type="number" min={0} max={600} value={draft.approval_wait_timeout_seconds} onChange={handleTimeoutChange} className="mt-2 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20" />
              </div>
              <fieldset className="space-y-2">
                <legend className="sr-only">Feature toggles</legend>
                <SettingToggle id="settings-telemetry" label="Telemetry" checked={draft.telemetry} onChange={handleBooleanChange("telemetry")} />
                <SettingToggle id="settings-cloud-sync" label="Cloud sync" checked={draft.sync} onChange={handleBooleanChange("sync")} />
                <SettingToggle id="settings-billing" label="Billing features" checked={draft.billing} onChange={handleBooleanChange("billing")} />
              </fieldset>
            </div>

            <ApprovalGateCard
              enabled={approvalGateEnabled}
              gateConfig={draft.approval_gate ?? null}
              newPassword={approvalGateNewPassword}
              confirmPassword={approvalGateConfirmPassword}
              currentPassword={approvalGateCurrentPassword}
              cooldownSeconds={approvalGateCooldown}
              revokingCooldown={revokingCooldown}
              revokePassword={revokePassword}
              revokeError={revokeError}
              onToggle={handleApprovalGateToggle}
              onNewPasswordChange={handleApprovalGateNewPassword}
              onConfirmPasswordChange={handleApprovalGateConfirmPassword}
              onCurrentPasswordChange={handleApprovalGateCurrentPassword}
              onCooldownChange={handleApprovalGateCooldownChange}
              onRevokePasswordChange={handleRevokePasswordChange}
              onRevokeCooldown={handleRevokeCooldown}
            />
          </fieldset>
        </AccordionSection>

        <div className="flex items-center justify-between rounded-xl border border-slate-100 bg-white p-4">
          <div>
            <p className="text-sm font-semibold text-brand-dark">Advanced settings</p>
            <p className="text-xs text-slate-500">Fine-tune individual risk controls and diagnostics.</p>
          </div>
          <label className="relative inline-flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              id="advanced-toggle"
              checked={showAdvanced}
              onChange={handleAdvancedToggle}
              className="peer sr-only"
              aria-label="Show advanced settings"
            />
            <div className="h-6 w-11 rounded-full bg-slate-200 transition-colors peer-checked:bg-brand-blue" />
            <div className="absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform peer-checked:translate-x-5" />
          </label>
        </div>

        {showAdvanced && (
          <>
        <AccordionSection
          title="Risk choices"
          subtitle={draft.security_level !== "custom" ? `Managed by ${securityLevelLabel(draft.security_level)}` : "Custom overrides active"}
          expanded={expandedSections["risk"]}
          onToggle={handleToggleRisk}
          sectionId="risk"
        >
          <div className="space-y-4">
            {draft.security_level !== "custom" && (
              <p className="text-sm text-slate-500">All risk behaviors are set by the <span className="font-semibold">{securityLevelLabel(draft.security_level)}</span> level. Select <span className="font-semibold">Custom</span> above to override individual choices.</p>
            )}
            <div className={`divide-y divide-slate-100 border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`}>
              {riskControls.map((risk) => (
                <RiskControlRow
                  key={risk.key}
                  risk={risk}
                  value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                  disabled={draft.security_level !== "custom"}
                  onChange={handleRiskActionChange(risk.key)}
                  showConsequence={draft.security_level === "custom"}
                />
              ))}
            </div>
            <div className={`grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`}>
              <div>
                <p className="text-sm font-medium text-brand-dark">Codex reading local secret files</p>
                <p className="text-xs text-slate-500">Use this only for trusted projects where Codex should read files such as .env or .npmrc without Guard asking.</p>
              </div>
              <SettingSelect label="Codex should" value={draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval"} options={actionOptions} onChange={handleCodexSecretReadChange} disabled={draft.security_level !== "custom"} />
            </div>
            <div className="border-t border-slate-100 pt-3">
              <SectionLabel>Advanced defaults</SectionLabel>
              <div className="mt-2 grid gap-3 sm:grid-cols-2">
                <SettingSelect label="New action" value={draft.default_action} options={actionOptions} onChange={handleStringChange("default_action")} />
                <SettingSelect label="Unknown source" value={draft.unknown_publisher_action} options={actionOptions} onChange={handleStringChange("unknown_publisher_action")} />
                <SettingSelect label="Changed command" value={draft.changed_hash_action} options={actionOptions} onChange={handleStringChange("changed_hash_action")} />
                <SettingSelect label="New network domain" value={draft.new_network_domain_action} options={actionOptions} onChange={handleStringChange("new_network_domain_action")} />
                <SettingSelect label="Subprocess action" value={draft.subprocess_action} options={actionOptions} onChange={handleStringChange("subprocess_action")} />
                <SettingSelect label="Approval surface" value={draft.approval_surface_policy} options={surfacePolicyOptions} onChange={handleStringChange("approval_surface_policy")} />
              </div>
            </div>
          </div>
        </AccordionSection>

        <AccordionSection
          title="Diagnostics & data"
          subtitle="Clear approvals, export logs, repair"
          expanded={expandedSections["diagnostics"]}
          onToggle={handleToggleDiagnostics}
          sectionId="diagnostics"
        >
          <div className="space-y-4">
            <NotificationSetupCard
              result={notificationSetup}
              settingUp={settingUpNotifications}
              onSetup={handleSetupNotifications}
            />
            {perfSnapshot !== null && <DiagnosticsPerfCard snapshot={perfSnapshot} />}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-semibold text-brand-dark">Clear saved approvals</p>
                  <p className="text-xs text-slate-500">Removes all stored allow and block decisions. Guard will ask again for every action that was previously approved.</p>
                  <div className="mt-2">
                    <ActionButton onClick={handleClearApprovals} disabled={clearingApprovals} variant="outline">{clearingApprovals ? "Clearing…" : "Clear approvals"}</ActionButton>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-semibold text-brand-dark">Clear evidence log</p>
                  <p className="text-xs text-slate-500">Permanently removes all recorded evidence. This action cannot be undone and removes the local audit history.</p>
                  <div className="mt-2">
                    <ActionButton onClick={handleClearEvidence} disabled={clearingEvidence} variant="outline">{clearingEvidence ? "Clearing…" : "Clear evidence"}</ActionButton>
                  </div>
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-semibold text-brand-dark">Export diagnostics</p>
                  <p className="text-xs text-slate-500">Downloads a JSON file with local Guard evidence for debugging or support requests.</p>
                  <div className="mt-2">
                    <ActionButton onClick={handleExportDiagnostics} disabled={exporting} variant="secondary">{exporting ? "Exporting…" : "Export"}</ActionButton>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-semibold text-brand-dark">Repair approval center</p>
                  <p className="text-xs text-slate-500">Resets the approval center locator. Use this when the approval link returns an API error after Guard restarts.</p>
                  <div className="mt-2">
                    <ActionButton onClick={handleRepairApprovalCenter} disabled={repairing} variant="secondary">{repairing ? "Repairing…" : "Repair"}</ActionButton>
                  </div>
                </div>
              </div>
            </div>
            {actionMessage ? <p className="text-sm text-slate-600">{actionMessage}</p> : null}
          </div>
        </AccordionSection>
          </>
        )}
      </div>

      <div
        className="sticky bottom-4 rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur"
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
            <p className="text-xs text-slate-500">Use this for local tuning. Team policy from Guard Cloud may still override some decisions.</p>
          )}
          <div aria-live="polite" aria-atomic="true" className="sr-only">
            {saveStatusText(saveSuccess, saveError)}
          </div>
        </div>
      </div>

      {pendingMode === "observe" && (
        <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl">
            <div className="flex items-start gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10">
                <HiMiniExclamationTriangle className="h-5 w-5 text-brand-attention" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-brand-dark">Switch to Observe mode?</h3>
                <p className="mt-2 text-sm text-slate-500">In Observe mode, Guard records what your AI apps do but does not pause any actions. This reduces your protection. Only use this when debugging or in trusted environments.</p>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <button onClick={confirmModeChange} className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90">Switch to Observe</button>
              <button onClick={cancelModeChange} className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50">Keep current mode</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

type AccordionSectionProps = {
  title: string;
  subtitle: string;
  expanded: boolean;
  onToggle: () => void;
  sectionId: string;
  children: React.ReactNode;
};

function AccordionSection(props: AccordionSectionProps) {
  const panelId = `accordion-panel-${props.sectionId}`;
  const buttonId = `accordion-btn-${props.sectionId}`;
  return (
    <div className="overflow-hidden rounded-xl border border-slate-100">
      <button
        id={buttonId}
        onClick={props.onToggle}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50/60"
        aria-expanded={props.expanded}
        aria-controls={panelId}
      >
        <div>
          <p className="text-sm font-semibold text-brand-dark">{props.title}</p>
          <p className="text-xs text-slate-400">{props.subtitle}</p>
        </div>
        {props.expanded ? (
          <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
        )}
      </button>
      {props.expanded && (
        <div id={panelId} role="region" aria-labelledby={buttonId} className="border-t border-slate-100 px-4 py-4">
          {props.children}
        </div>
      )}
    </div>
  );
}

function DiagnosticsPerfCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return (
    <div className="rounded-lg bg-slate-50/80 px-3 py-2">
      <p className="text-xs font-semibold text-brand-dark">Runtime</p>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        {threadCount !== undefined && <span>{threadCount} threads</span>}
        {daemonPort !== null && <span>Port {daemonPort}</span>}
        {startedAt !== null && <span>Started {new Date(startedAt).toLocaleTimeString()}</span>}
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
    <div className="rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-4">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex min-w-0 gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
            <HiMiniBellAlert className="h-5 w-5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-brand-dark">Desktop notifications</p>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-slate-500">
              Guard pauses risky AI actions. Enable local alerts so approvals do not hide behind the dashboard.
            </p>
            <ol className="mt-3 grid gap-2 text-xs text-slate-600 sm:grid-cols-3">
              <li className="rounded-lg bg-white/80 p-3 ring-1 ring-slate-100">1. Open notification settings.</li>
              <li className="rounded-lg bg-white/80 p-3 ring-1 ring-slate-100">2. Choose terminal-notifier on macOS.</li>
              <li className="rounded-lg bg-white/80 p-3 ring-1 ring-slate-100">3. Enable banners or alerts plus sounds.</li>
            </ol>
          </div>
        </div>
        <ActionButton onClick={props.onSetup} disabled={props.settingUp}>
          {props.settingUp ? "Opening..." : "Open notification settings"}
        </ActionButton>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {props.result ? (
          <>
            <Tag tone={props.result.supported ? "blue" : "slate"}>
              {props.result.supported ? "Supported" : "Unsupported"}
            </Tag>
            <Tag tone={props.result.preview_sent ? "blue" : "slate"}>
              {props.result.preview_sent ? "Preview sent" : "Preview not sent"}
            </Tag>
            <Tag tone={props.result.settings_opened ? "blue" : "slate"}>
              {props.result.settings_opened ? "Settings opened" : "Settings not opened"}
            </Tag>
          </>
        ) : (
          <Tag tone="slate">Not configured from this dashboard session</Tag>
        )}
      </div>
      {props.result?.guidance ? (
        <p className="mt-3 text-xs leading-relaxed text-slate-500">{props.result.guidance}</p>
      ) : null}
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
        className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {props.options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
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
  newPassword: string;
  confirmPassword: string;
  currentPassword: string;
  cooldownSeconds: number;
  revokingCooldown: boolean;
  revokePassword: string;
  revokeError: string | null;
  onToggle: (event: ChangeEvent<HTMLInputElement>) => void;
  onNewPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCurrentPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCooldownChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  onRevokePasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onRevokeCooldown: () => void;
};

function ApprovalGateCard(props: ApprovalGateCardProps) {
  const wasConfigured = props.gateConfig?.configured === true;
  const showCurrentPassword = props.enabled && wasConfigured;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const cooldownLabel = cooldownExpiresAt
    ? new Date(cooldownExpiresAt).toLocaleTimeString()
    : null;

  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/40 p-4">
      <SettingToggle
        id="settings-approval-gate"
        label="Require password for approvals"
        checked={props.enabled}
        onChange={props.onToggle}
      />
      <p className="mt-1 px-1 text-xs text-slate-500">
        Ask for a password before each approve or block decision.
      </p>

      {props.enabled && (
        <div className="mt-4 space-y-3">
          {showCurrentPassword && (
            <label className="block">
              <span className="text-xs font-medium text-slate-500">Current password</span>
              <input
                type="password"
                autoComplete="current-password"
                value={props.currentPassword}
                onChange={props.onCurrentPasswordChange}
                className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
              />
            </label>
          )}
          <label className="block">
            <span className="text-xs font-medium text-slate-500">New password</span>
            <input
              type="password"
              autoComplete="new-password"
              value={props.newPassword}
              onChange={props.onNewPasswordChange}
              className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-500">Confirm password</span>
            <input
              type="password"
              autoComplete="new-password"
              value={props.confirmPassword}
              onChange={props.onConfirmPasswordChange}
              className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-500">Cooldown after approval</span>
            <select
              value={String(props.cooldownSeconds)}
              onChange={props.onCooldownChange}
              className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
            >
              {cooldownOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </label>

          {cooldownActive && cooldownLabel !== null && (
            <div className="rounded-lg border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2">
              <p className="text-xs text-brand-dark">Cooldown active until {cooldownLabel}</p>
              <div className="mt-2 space-y-2">
                <label className="block">
                  <span className="text-xs font-medium text-slate-500">Password to revoke</span>
                  <input
                    type="password"
                    autoComplete="current-password"
                    value={props.revokePassword}
                    onChange={props.onRevokePasswordChange}
                    className="mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                  />
                </label>
                {props.revokeError !== null && (
                  <p className="text-xs text-brand-purple">{props.revokeError}</p>
                )}
                <ActionButton onClick={props.onRevokeCooldown} disabled={props.revokingCooldown} variant="outline">
                  {props.revokingCooldown ? "Revoking…" : "Revoke cooldown"}
                </ActionButton>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
