import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniCog6Tooth,
  HiMiniCheckCircle,
  HiMiniInformationCircle,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";

import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
} from "./approval-center-primitives";
import { clearEvidence, exportDiagnostics, fetchRuntimeSnapshot, fetchSettings, updateSettings, clearPolicy, repairApprovalCenter } from "./guard-api";
import { resolveProtectionLevelCopy } from "./runtime-overview";
import type { GuardRuntimeSnapshot, GuardSettings, GuardSettingsPayload } from "./guard-types";

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
    value: "balanced",
    label: "Balanced",
    description: "Ask before secret access, hidden execution, exfiltration, and destructive actions.",
    icon: HiMiniShieldCheck,
    protects: ["Secret file access", "Credential sharing", "Destructive shell commands", "Hidden scripts"],
    tone: "blue" as const,
  },
  {
    value: "strict",
    label: "Strict",
    description: "Ask more often, including new network destinations.",
    icon: HiMiniLockClosed,
    protects: ["Everything in Balanced", "New network destinations"],
    tone: "purple" as const,
  },
  {
    value: "custom",
    label: "Custom",
    description: "Use the exact choices below for this machine and connected apps.",
    icon: HiMiniCog6Tooth,
    protects: [],
    tone: "slate" as const,
  }
] as const;

const riskControls = [
  {
    key: "local_secret_read",
    label: "Local secrets",
    description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials."
  },
  {
    key: "credential_exfiltration",
    label: "Credential sharing",
    description: "Commands or scripts that appear to send keys, tokens, or credentials away."
  },
  {
    key: "data_flow_exfiltration",
    label: "Secret data flow",
    description: "Detected source-to-sink route where a local secret is read and its value reaches a network or external sink."
  },
  {
    key: "destructive_shell",
    label: "Destructive commands",
    description: "Shell actions that delete, overwrite, or rewrite local files."
  },
  {
    key: "encoded_execution",
    label: "Hidden scripts",
    description: "Encoded, encrypted, or decoded-and-run command payloads."
  },
  {
    key: "network_egress",
    label: "New network destinations",
    description: "Outbound connections Guard has not seen in this context."
  }
] as const;

type RiskKey = (typeof riskControls)[number]["key"];

const riskProfileActions: Record<"balanced" | "strict" | "custom", Record<RiskKey, string>> = {
  balanced: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn"
  },
  strict: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "block",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "require-reapproval"
  },
  custom: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn"
  }
};

function normalizeSettingsPayload(payload: GuardSettingsPayload): GuardSettingsPayload {
  return {
    ...payload,
    settings: normalizeGuardSettings(payload.settings)
  };
}

function normalizeGuardSettings(settings: GuardSettings): GuardSettings {
  const defaults = riskProfileActions[settings.security_level];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce<Record<RiskKey, string>>((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {} as Record<RiskKey, string>);
  return {
    ...settings,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}

export const resolveSecurityLevelDescription = resolveProtectionLevelCopy;

export function buildClearPolicyPayload(all: boolean): { harness?: string; all?: boolean } {
  return { all };
}

function buildConsequenceSummary(settings: GuardSettings): string {
  const level = settings.security_level;
  const mode = settings.mode;
  if (mode === "observe") {
    return "Guard is watching and recording what your AI apps do, but it will not pause any actions. Switch to Prompt or Enforce when you want Guard to actively protect you.";
  }
  if (level === "balanced") {
    return "Guard will ask before secret access, hidden execution, and destructive commands. New network destinations get a warning. This is the recommended setting for most users.";
  }
  if (level === "strict") {
    return "Guard will ask before almost every risky action, including new network destinations. Use this when working with sensitive data or untrusted AI tools.";
  }
  if (level === "custom") {
    return "You have customized individual risk controls. Review the choices below to make sure they match how you want Guard to behave.";
  }
  return "";
}

function hasUnsavedChanges(saved: GuardSettings | null, draft: GuardSettings | null): boolean {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
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
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [perfSnapshot, setPerfSnapshot] = useState<GuardRuntimeSnapshot | null>(null);
  const [pendingMode, setPendingMode] = useState<GuardSettings["mode"] | null>(null);
  const saveSuccessTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedSettingsRef = useRef<GuardSettings | null>(null);

  useEffect(() => {
    let cancelled = false;
      fetchSettings()
        .then((payload) => {
          if (!cancelled) {
            const normalizedPayload = normalizeSettingsPayload(payload);
            setState({ kind: "ready", payload: normalizedPayload });
            setDraft(normalizedPayload.settings);
            savedSettingsRef.current = normalizedPayload.settings;
          }
        })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load Guard settings."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot()
      .then((snapshot) => {
        if (!cancelled) setPerfSnapshot(snapshot);
      })
      .catch((error: unknown) => {
        console.error("Failed to fetch runtime snapshot:", error);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    return () => {
      if (saveSuccessTimerRef.current !== null) {
        clearTimeout(saveSuccessTimerRef.current);
      }
    };
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
      if (securityLevel === "custom") {
        return { ...value, security_level: securityLevel };
      }
      return {
        ...value,
        security_level: securityLevel,
        risk_actions: riskProfileActions[securityLevel],
        risk_action_overrides: {},
        harness_risk_actions: {}
      };
    });
    setSaveError(null);
  }, []);

  const handleRiskActionChange = useCallback(
    (riskKey: string) => (event: ChangeEvent<HTMLSelectElement>) => {
      setDraft((value) => {
        if (value === null) return value;
        return {
          ...value,
          security_level: "custom",
          risk_actions: {
            ...value.risk_actions,
            [riskKey]: event.target.value
          },
          risk_action_overrides: {
            ...value.risk_action_overrides,
            [riskKey]: event.target.value
          }
        };
      });
      setSaveError(null);
    },
    []
  );

  const handleCodexSecretReadChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setDraft((value) => {
      if (value === null) return value;
      return {
        ...value,
        security_level: "custom",
        harness_risk_actions: {
          ...value.harness_risk_actions,
          codex: {
            ...(value.harness_risk_actions.codex ?? {}),
            local_secret_read: event.target.value
          }
        }
      };
    });
    setSaveError(null);
  }, []);

  const handleTimeoutChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: Number.isNaN(nextValue) ? 0 : nextValue });
    setSaveError(null);
  }, []);

  const handleModeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const nextMode = event.target.value as GuardSettings["mode"];
    if (nextMode === "observe") {
      setPendingMode(nextMode);
      return;
    }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);

  const confirmModeChange = useCallback(() => {
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [pendingMode]);

  const cancelModeChange = useCallback(() => {
    setPendingMode(null);
  }, []);

  const handleBooleanChange = useCallback(
    (key: keyof GuardSettings) => (event: ChangeEvent<HTMLInputElement>) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );

  const handleSave = useCallback(async () => {
    if (draft === null) return;
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const payload = await updateSettings({
        ...draft,
        risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides
      });
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      setSaveSuccess(true);
      if (saveSuccessTimerRef.current !== null) {
        clearTimeout(saveSuccessTimerRef.current);
      }
      saveSuccessTimerRef.current = setTimeout(() => {
        setSaveSuccess(false);
      }, 2000);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      setSaving(false);
    }
  }, [draft]);

  const handleClearApprovals = useCallback(async () => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) {
      return;
    }
    setClearingApprovals(true);
    setActionMessage(null);
    try {
      await clearPolicy({ all: true });
      setActionMessage("All saved approvals cleared.");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
    } finally {
      setClearingApprovals(false);
    }
  }, []);

  const handleClearEvidence = useCallback(async () => {
    if (!window.confirm("Clear the evidence log permanently? This cannot be undone.")) {
      return;
    }
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
    if (!window.confirm("Reset the approval center locator? The daemon will be reachable again after Guard restarts. Pending approvals are preserved.")) {
      return;
    }
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

  const modeHelp = draft.mode === "enforce"
    ? "Guard blocks risky actions until a saved decision allows them."
    : draft.mode === "observe"
      ? "Guard records what it sees without pausing actions."
      : "Guard asks before risky actions continue.";

  const consequenceSummary = buildConsequenceSummary(draft);

  return (
    <div className="space-y-6">
      <GuardHero
        status="clear"
        headline="Choose how protective Guard should be"
        subheadline="Start with a simple security level, then tune exact risk types when a trusted app needs more room to work."
        cta={<Tag tone="blue">{draft.mode}</Tag>}
      />

      {consequenceSummary && (
        <div className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5 shadow-sm sm:p-6">
          <div className="flex items-start gap-3">
            <HiMiniShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
            <div>
              <SectionLabel>What to expect</SectionLabel>
              <p className="mt-2 text-sm text-muted-foreground">{consequenceSummary}</p>
            </div>
          </div>
        </div>
      )}

      <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-6">
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Security level</SectionLabel>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Pick a level to set up all risk choices at once. Switch to Custom only when you need to override individual behaviors.
            </p>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              {securityLevels.map((level) => {
                const LevelIcon = level.icon;
                const isSelected = draft.security_level === level.value;
                const iconColorClass =
                  level.tone === "blue" ? "text-brand-blue" :
                  level.tone === "purple" ? "text-brand-purple" :
                  "text-slate-500";
                const iconBgClass =
                  level.tone === "blue" ? "bg-brand-blue/10" :
                  level.tone === "purple" ? "bg-brand-purple/10" :
                  "bg-slate-100";
                const selectedBorderClass =
                  level.tone === "blue" ? "border-brand-blue/35 bg-brand-blue/[0.07] shadow-[0_12px_32px_rgba(85,153,254,0.14)]" :
                  level.tone === "purple" ? "border-brand-purple/35 bg-brand-purple/[0.06] shadow-[0_12px_32px_rgba(181,108,255,0.12)]" :
                  "border-slate-300 bg-slate-50 shadow-sm";
                return (
                  <button
                    key={level.value}
                    type="button"
                    onClick={() => handleSecurityLevelChange(level.value)}
                    aria-pressed={isSelected}
                    className={`relative min-h-36 rounded-[1.5rem] border p-4 text-left transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md ${
                      isSelected ? selectedBorderClass : "border-transparent bg-surface-1/80 hover:bg-white"
                    }`}
                  >
                    {isSelected && (
                      <span className="absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-[#059669]">
                        <HiMiniCheckCircle className="h-4 w-4 text-white" aria-hidden="true" />
                      </span>
                    )}
                    <span className={`inline-flex h-8 w-8 items-center justify-center rounded-lg ${iconBgClass}`}>
                      <LevelIcon className={`h-4 w-4 ${iconColorClass}`} aria-hidden="true" />
                    </span>
                    <span className="mt-3 block text-base font-semibold text-brand-dark">{level.label}</span>
                    <span className="mt-1.5 block text-sm leading-6 text-muted-foreground">{level.description}</span>
                    {level.protects.length > 0 && (
                      <ul className="mt-3 space-y-1">
                        {level.protects.map((item) => (
                          <li key={item} className="flex items-center gap-1.5 text-[11px] font-medium text-brand-dark/60">
                            <span className={`h-1 w-1 shrink-0 rounded-full ${iconColorClass}`} />
                            {item}
                          </li>
                        ))}
                      </ul>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Protection mode</SectionLabel>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              {(["prompt", "enforce", "observe"] as const).map((mode) => (
                <label
                  key={mode}
                  className={`cursor-pointer rounded-[1.25rem] border p-4 transition-all duration-150 ${
                    draft.mode === mode ? "border-brand-blue/30 bg-brand-blue/[0.06] shadow-sm" : "border-transparent bg-surface-1/80 hover:bg-white"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value={mode}
                    checked={draft.mode === mode}
                    onChange={handleModeChange}
                    className="sr-only"
                  />
                  <span className="text-sm font-semibold capitalize text-brand-dark">{mode}</span>
                </label>
              ))}
            </div>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">{modeHelp}</p>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <SectionLabel>Risk choices</SectionLabel>
              {draft.security_level !== "custom" ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                  <HiMiniLockClosed className="h-3 w-3" aria-hidden="true" />
                  Managed by {draft.security_level === "balanced" ? "Balanced" : "Strict"}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-brand-blue/25 bg-brand-blue/[0.06] px-3 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue">
                  <HiMiniCog6Tooth className="h-3 w-3" aria-hidden="true" />
                  Custom overrides active
                </span>
              )}
            </div>
            {draft.security_level !== "custom" && (
              <div className="mt-3 flex items-center justify-between gap-3 rounded-[1rem] border border-slate-200/60 bg-slate-50/80 px-4 py-3">
                <p className="text-sm text-brand-dark/65">
                  All risk behaviors are set by the <span className="font-semibold">{draft.security_level === "balanced" ? "Balanced" : "Strict"}</span> level. Select <span className="font-semibold">Custom</span> above to override individual choices.
                </p>
              </div>
            )}
            <div className={`mt-4 divide-y divide-slate-200/70 overflow-hidden rounded-[1.35rem] border border-slate-200/70 bg-white ${draft.security_level !== "custom" ? "opacity-60" : ""}`}>
              {riskControls.map((risk) => (
                <div key={risk.key} className="grid gap-3 px-4 py-4 md:grid-cols-[minmax(0,1fr)_220px] md:items-center">
                  <div>
                    <p className="text-sm font-semibold text-brand-dark">{risk.label}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{risk.description}</p>
                    <details className="group mt-1">
                      <summary className="cursor-pointer text-xs font-semibold text-brand-blue [&::-webkit-details-marker]:hidden">
                        What this means ›
                      </summary>
                      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                        {risk.description} Choosing <strong>Ask again</strong> means Guard will prompt your AI agent each time it tries this action until you approve it for the current session or workspace.
                      </p>
                    </details>
                  </div>
                  <SettingSelect
                    label="Guard should"
                    value={draft.risk_actions[risk.key] ?? "require-reapproval"}
                    options={actionOptions}
                    onChange={handleRiskActionChange(risk.key)}
                    disabled={draft.security_level !== "custom"}
                  />
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Codex override</SectionLabel>
            <div className={`mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_260px] md:items-center ${draft.security_level !== "custom" ? "opacity-60" : ""}`}>
              <div>
                <p className="text-sm font-semibold text-brand-dark">Codex reading local secret files</p>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">
                  Use this only for trusted projects where Codex should be allowed to open files such as .env or .npmrc.
                </p>
              </div>
              <SettingSelect
                label="Codex should"
                value={draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval"}
                options={actionOptions}
                onChange={handleCodexSecretReadChange}
                disabled={draft.security_level !== "custom"}
              />
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Advanced defaults</SectionLabel>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <SettingSelect label="New action" value={draft.default_action} options={actionOptions} onChange={handleStringChange("default_action")} />
              <SettingSelect label="Unknown source" value={draft.unknown_publisher_action} options={actionOptions} onChange={handleStringChange("unknown_publisher_action")} />
              <SettingSelect label="Changed command" value={draft.changed_hash_action} options={actionOptions} onChange={handleStringChange("changed_hash_action")} />
              <SettingSelect label="New network domain" value={draft.new_network_domain_action} options={actionOptions} onChange={handleStringChange("new_network_domain_action")} />
              <SettingSelect label="Subprocess action" value={draft.subprocess_action} options={actionOptions} onChange={handleStringChange("subprocess_action")} />
              <SettingSelect label="Approval surface" value={draft.approval_surface_policy} options={surfacePolicyOptions} onChange={handleStringChange("approval_surface_policy")} />
            </div>
          </div>
        </div>

        <aside className="space-y-4">
          <div className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5">
            <SectionLabel>Approval wait</SectionLabel>
            <label htmlFor="approval-wait" className="mt-3 block text-sm font-semibold text-brand-dark">
              Seconds to wait before returning to the harness
            </label>
            <input
              id="approval-wait"
              type="number"
              min={0}
              max={600}
              value={draft.approval_wait_timeout_seconds}
              onChange={handleTimeoutChange}
              className="mt-2 min-h-11 w-full rounded-full border border-border bg-white px-4 py-2 text-sm text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </div>
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
            <SectionLabel>Local toggles</SectionLabel>
            <div className="mt-4 space-y-3">
              <SettingToggle label="Telemetry" checked={draft.telemetry} onChange={handleBooleanChange("telemetry")} />
              <SettingToggle label="Cloud sync" checked={draft.sync} onChange={handleBooleanChange("sync")} />
              <SettingToggle label="Billing features" checked={draft.billing} onChange={handleBooleanChange("billing")} />
            </div>
          </div>
          {perfSnapshot !== null ? (
            <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm">
              <SectionLabel>Runtime diagnostics</SectionLabel>
              <div className="mt-4">
                <DiagnosticsPerfCard snapshot={perfSnapshot} />
              </div>
            </div>
          ) : null}
          <div className="rounded-[1.75rem] border border-brand-purple/20 bg-brand-purple/[0.04] p-5">
            <SectionLabel>Data management</SectionLabel>
            <div className="mt-4 space-y-4">
              <div>
                <p className="text-sm font-semibold text-brand-dark">Clear saved approvals</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  Removes all stored allow/block decisions. Guard will ask again for previously approved actions.
                </p>
                <div className="mt-2">
                  <ActionButton onClick={handleClearApprovals} disabled={clearingApprovals} variant="danger">
                    {clearingApprovals ? "Clearing…" : "Clear all approvals"}
                  </ActionButton>
                </div>
              </div>
              <div>
                <p className="text-sm font-semibold text-brand-dark">Clear evidence log</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  Permanently removes all recorded evidence. This cannot be undone.
                </p>
                <div className="mt-2">
                  <ActionButton onClick={handleClearEvidence} disabled={clearingEvidence} variant="danger">
                    {clearingEvidence ? "Clearing…" : "Clear evidence log"}
                  </ActionButton>
                </div>
              </div>
              <div>
                <p className="text-sm font-semibold text-brand-dark">Export diagnostics</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  Downloads a JSON file with local Guard evidence for debugging or support.
                </p>
                <div className="mt-2">
                  <ActionButton onClick={handleExportDiagnostics} disabled={exporting} variant="secondary">
                    {exporting ? "Exporting…" : "Export diagnostics"}
                  </ActionButton>
                </div>
              </div>
              <div>
                <p className="text-sm font-semibold text-brand-dark">Repair local approval center</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  Resets the approval center locator when the approval link returns an API error. Pending approvals are preserved.
                </p>
                <div className="mt-2">
                  <ActionButton onClick={handleRepairApprovalCenter} disabled={repairing} variant="secondary">
                    {repairing ? "Repairing…" : "Repair approval center"}
                  </ActionButton>
                </div>
              </div>
              {actionMessage ? (
                <p className="guard-fade-in text-sm leading-6 text-brand-dark/70">{actionMessage}</p>
              ) : null}
            </div>
          </div>
          <div>
            <SectionLabel>Deep scanner</SectionLabel>
            <div className="mt-4 rounded-[1.25rem] border border-slate-200/70 bg-white/80 px-5 py-4">
              <p className="text-sm font-semibold text-brand-dark">Enhanced scanning</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                Install the Cisco scanner extension to enable skill and MCP evidence enrichment.
              </p>
              <p className="mt-3 rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark">
                pip install holguard[cisco]
              </p>
            </div>
          </div>
          <div className="sticky top-24 rounded-[1.75rem] border border-white/80 bg-white/90 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
            <ActionButton onClick={handleSave} disabled={saving || saveSuccess}>
              {saveSuccess ? (
                <span className="flex items-center gap-2">
                  <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                  Saved
                </span>
              ) : saving ? (
                "Saving…"
              ) : (
                "Save settings"
              )}
            </ActionButton>
            {hasUnsavedChanges(savedSettingsRef.current, draft) && (
              <span className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention">
                <span className="h-1.5 w-1.5 rounded-full bg-brand-attention" />
                Unsaved changes
              </span>
            )}
            {saveSuccess ? (
              <p className="guard-fade-in mt-3 text-sm font-semibold leading-6 text-brand-green">Settings saved</p>
            ) : saveError ? (
              <p className="guard-fade-in mt-3 text-sm leading-6 text-brand-purple">{saveError}</p>
            ) : (
              <p className="mt-3 text-xs leading-5 text-muted-foreground">
                Use this for local tuning. Team policy from Guard Cloud may still override some decisions.
              </p>
            )}
          </div>
        </aside>
      </section>

      {/* Mode change confirmation */}
      {pendingMode === "observe" && (
        <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-[1.75rem] border border-brand-attention/20 bg-white p-6 shadow-xl">
            <div className="flex items-start gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10">
                <HiMiniExclamationTriangle className="h-5 w-5 text-brand-attention" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-base font-semibold text-brand-dark">Switch to Observe mode?</h3>
                <p className="mt-2 text-sm text-muted-foreground">
                  In Observe mode, Guard records what your AI apps do but does not pause any actions. This reduces your protection. Only use this when debugging or in trusted environments.
                </p>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <button
                onClick={confirmModeChange}
                className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90"
              >
                Switch to Observe
              </button>
              <button
                onClick={cancelModeChange}
                className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
              >
                Keep current mode
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DiagnosticsPerfCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const { snapshot } = props;
  const threadCount = snapshot.thread_count;
  const daemonPort = snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = snapshot.runtime_state?.started_at ?? null;
  return (
    <div>
      <h3 className="text-sm font-semibold text-brand-dark">Runtime performance</h3>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
        Live process metrics for this Guard daemon session.
      </p>
      <dl className="mt-3 grid grid-cols-2 gap-2">
        {threadCount !== undefined ? (
          <PerfMetric label="Total interpreter threads" value={String(threadCount)} />
        ) : null}
        {daemonPort !== null ? (
          <PerfMetric label="Daemon port" value={String(daemonPort)} />
        ) : null}
        {startedAt !== null ? (
          <PerfMetric label="Started" value={new Date(startedAt).toLocaleTimeString()} />
        ) : null}
      </dl>
    </div>
  );
}

function PerfMetric(props: { label: string; value: string }) {
  return (
    <div className="rounded-xl bg-surface-1 px-3 py-2">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{props.label}</dt>
      <dd className="mt-0.5 font-mono text-sm font-semibold text-brand-dark">{props.value}</dd>
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
      <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{props.label}</span>
      <select
        value={props.value}
        onChange={props.onChange}
        disabled={props.disabled}
        className="mt-2 min-h-11 w-full rounded-full border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {props.options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function SettingToggle(props: {
  label: string;
  checked: boolean;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label className="flex min-h-11 cursor-pointer items-center justify-between gap-3 rounded-full bg-surface-1 px-4 py-2">
      <span className="text-sm font-semibold text-brand-dark">{props.label}</span>
      <input type="checkbox" checked={props.checked} onChange={props.onChange} className="h-5 w-5 accent-brand-blue" />
    </label>
  );
}
