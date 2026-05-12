import { r as reactExports, w as fetchSettings, x as fetchRuntimeSnapshot, y as updateSettings, z as clearPolicy, C as clearEvidence, D as exportDiagnostics, F as repairApprovalCenter, j as jsxRuntimeExports, E as EmptyState, G as GuardHero, T as Tag, c as HiMiniShieldCheck, S as SectionLabel, I as HiMiniLockClosed, J as HiMiniCog6Tooth, H as HiMiniCheckCircle, A as ActionButton, n as HiMiniExclamationTriangle, l as HiMiniChevronUp, m as HiMiniChevronDown } from "../guard-dashboard.js";
function resolveProtectionLevelCopy(level) {
  if (level === "gentle") {
    return "Monitors quietly, asks only for high-risk actions";
  }
  if (level === "balanced") {
    return "Asks before secrets and destructive commands";
  }
  if (level === "strict") {
    return "Asks more often, including new network";
  }
  if (level === "paranoid") {
    return "Asks before nearly every action";
  }
  return "Custom rules active";
}
const resolveSecurityLevelDescription = resolveProtectionLevelCopy;
function buildClearPolicyPayload(all) {
  return { all };
}
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
    value: "gentle",
    label: "Gentle",
    description: "Ask before dangerous actions. Allow most safe ones.",
    icon: HiMiniShieldCheck,
    protects: ["Destructive commands", "Credential sharing"],
    tone: "green"
  },
  {
    value: "balanced",
    label: "Balanced",
    description: "Ask before secret access, hidden execution, exfiltration, and destructive actions.",
    icon: HiMiniShieldCheck,
    protects: ["Secret file access", "Credential sharing", "Destructive shell commands", "Hidden scripts"],
    tone: "blue"
  },
  {
    value: "strict",
    label: "Strict",
    description: "Ask more often, including new network destinations.",
    icon: HiMiniLockClosed,
    protects: ["Everything in Balanced", "New network destinations"],
    tone: "purple"
  },
  {
    value: "custom",
    label: "Custom",
    description: "Use the exact choices below for this machine and connected apps.",
    icon: HiMiniCog6Tooth,
    protects: [],
    tone: "slate"
  }
];
const riskControls = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials." },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away." },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret is read and its value reaches a network or external sink." },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files." },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads." },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context." }
];
const riskProfileActions = {
  gentle: {
    local_secret_read: "warn",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "warn",
    network_egress: "allow"
  },
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
function normalizeSettingsPayload(payload) {
  return { ...payload, settings: normalizeGuardSettings(payload.settings) };
}
function normalizeGuardSettings(settings) {
  const defaults = riskProfileActions[settings.security_level];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {});
  return {
    ...settings,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}
function buildConsequenceSummary(settings) {
  const level = settings.security_level;
  const mode = settings.mode;
  if (mode === "observe") return "Guard is watching and recording what your AI apps do, but it will not pause any actions. Switch to Prompt or Enforce when you want Guard to actively protect you.";
  if (level === "gentle") return "Guard will ask before destructive commands and credential sharing. Most safe actions are allowed automatically. Good for trusted environments.";
  if (level === "balanced") return "Guard will ask before secret access, hidden execution, and destructive commands. New network destinations get a warning. This is the recommended setting for most users.";
  if (level === "strict") return "Guard will ask before almost every risky action, including new network destinations. Use this when working with sensitive data or untrusted AI tools.";
  if (level === "custom") return "You have customized individual risk controls. Review the choices below to make sure they match how you want Guard to behave.";
  return "";
}
function hasUnsavedChanges(saved, draft) {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
}
function SettingsWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [draft, setDraft] = reactExports.useState(null);
  const [saving, setSaving] = reactExports.useState(false);
  const [saveSuccess, setSaveSuccess] = reactExports.useState(false);
  const [saveError, setSaveError] = reactExports.useState(null);
  const [clearingApprovals, setClearingApprovals] = reactExports.useState(false);
  const [clearingEvidence, setClearingEvidence] = reactExports.useState(false);
  const [exporting, setExporting] = reactExports.useState(false);
  const [repairing, setRepairing] = reactExports.useState(false);
  const [actionMessage, setActionMessage] = reactExports.useState(null);
  const [perfSnapshot, setPerfSnapshot] = reactExports.useState(null);
  const [pendingMode, setPendingMode] = reactExports.useState(null);
  const [showAdvanced, setShowAdvanced] = reactExports.useState(false);
  const [expandedSections, setExpandedSections] = reactExports.useState({ "protection": true, "risk": false, "diagnostics": false });
  const saveSuccessTimerRef = reactExports.useRef(null);
  const savedSettingsRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (!cancelled) {
        const normalizedPayload = normalizeSettingsPayload(payload);
        setState({ kind: "ready", payload: normalizedPayload });
        setDraft(normalizedPayload.settings);
        savedSettingsRef.current = normalizedPayload.settings;
      }
    }).catch((error) => {
      if (!cancelled) {
        setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot().then((snapshot) => {
      if (!cancelled) setPerfSnapshot(snapshot);
    }).catch((error) => {
      console.error("Failed to fetch runtime snapshot:", error);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  reactExports.useEffect(() => {
    return () => {
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
    };
  }, []);
  reactExports.useEffect(() => {
    function handleBeforeUnload(event) {
      if (hasUnsavedChanges(savedSettingsRef.current, draft)) {
        event.preventDefault();
        event.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [draft]);
  const toggleSection = reactExports.useCallback((key) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);
  const handleStringChange = reactExports.useCallback(
    (key) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.value });
      setSaveError(null);
    },
    []
  );
  const handleSecurityLevelChange = reactExports.useCallback((securityLevel) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") return { ...value, security_level: securityLevel };
      return { ...value, security_level: securityLevel, risk_actions: riskProfileActions[securityLevel], risk_action_overrides: {}, harness_risk_actions: {} };
    });
    setSaveError(null);
  }, []);
  const handleRiskActionChange = reactExports.useCallback(
    (riskKey) => (event) => {
      setDraft((value) => {
        if (value === null) return value;
        return { ...value, security_level: "custom", risk_actions: { ...value.risk_actions, [riskKey]: event.target.value }, risk_action_overrides: { ...value.risk_action_overrides, [riskKey]: event.target.value } };
      });
      setSaveError(null);
    },
    []
  );
  const handleCodexSecretReadChange = reactExports.useCallback((event) => {
    setDraft((value) => {
      if (value === null) return value;
      return { ...value, security_level: "custom", harness_risk_actions: { ...value.harness_risk_actions, codex: { ...value.harness_risk_actions.codex ?? {}, local_secret_read: event.target.value } } };
    });
    setSaveError(null);
  }, []);
  const handleTimeoutChange = reactExports.useCallback((event) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: Number.isNaN(nextValue) ? 0 : nextValue });
    setSaveError(null);
  }, []);
  const handleModeChange = reactExports.useCallback((event) => {
    const nextMode = event.target.value;
    if (nextMode === "observe") {
      setPendingMode(nextMode);
      return;
    }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);
  const confirmModeChange = reactExports.useCallback(() => {
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [pendingMode]);
  const cancelModeChange = reactExports.useCallback(() => {
    setPendingMode(null);
  }, []);
  const handleBooleanChange = reactExports.useCallback(
    (key) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );
  const handleSave = reactExports.useCallback(async () => {
    if (draft === null) return;
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const payload = await updateSettings({ ...draft, risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides });
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      setSaveSuccess(true);
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
      saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2e3);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      setSaving(false);
    }
  }, [draft]);
  const handleClearApprovals = reactExports.useCallback(async () => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) return;
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
  const handleClearEvidence = reactExports.useCallback(async () => {
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
  const handleExportDiagnostics = reactExports.useCallback(async () => {
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
  const handleRepairApprovalCenter = reactExports.useCallback(async () => {
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
  if (state.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10 w-64" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-72 w-full" })
    ] });
  }
  if (state.kind === "error" || draft === null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: "Settings are unavailable", body: state.kind === "error" ? state.message : "Guard did not return editable settings.", tone: "teach" });
  }
  const modeHelp = draft.mode === "enforce" ? "Guard blocks risky actions until a saved decision allows them." : draft.mode === "observe" ? "Guard records what it sees without pausing actions." : "Guard asks before risky actions continue.";
  const consequenceSummary = buildConsequenceSummary(draft);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: "clear",
        headline: "Choose how protective Guard should be",
        subheadline: "Start with a simple security level, then tune exact risk types when a trusted app needs more room to work.",
        cta: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: draft.mode })
      }
    ),
    consequenceSummary && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What to expect" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: consequenceSummary })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        AccordionSection,
        {
          title: "Protection level",
          subtitle: `${draft.security_level === "gentle" ? "Gentle" : draft.security_level === "balanced" ? "Balanced" : draft.security_level === "strict" ? "Strict" : "Custom"} · ${draft.mode}`,
          expanded: expandedSections["protection"],
          onToggle: () => toggleSection("protection"),
          children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 md:grid-cols-2 lg:grid-cols-4", children: securityLevels.map((level) => {
              const LevelIcon = level.icon;
              const isSelected = draft.security_level === level.value;
              const iconColorClass = level.tone === "green" ? "text-emerald-600" : level.tone === "blue" ? "text-brand-blue" : level.tone === "purple" ? "text-brand-purple" : "text-slate-500";
              const iconBgClass = level.tone === "green" ? "bg-emerald-50" : level.tone === "blue" ? "bg-brand-blue/10" : level.tone === "purple" ? "bg-brand-purple/10" : "bg-slate-100";
              const selectedBorderClass = level.tone === "green" ? "border-emerald-300 bg-emerald-50" : level.tone === "blue" ? "border-brand-blue/30 bg-brand-blue/[0.05]" : level.tone === "purple" ? "border-brand-purple/30 bg-brand-purple/[0.04]" : "border-slate-300 bg-slate-50";
              return /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "button",
                {
                  type: "button",
                  onClick: () => handleSecurityLevelChange(level.value),
                  "aria-pressed": isSelected,
                  className: `relative rounded-xl border p-4 text-left transition-all duration-150 hover:-translate-y-0.5 ${isSelected ? selectedBorderClass : "border-transparent bg-slate-50/80 hover:bg-white"}`,
                  children: [
                    isSelected && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-[#059669]", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 text-white", "aria-hidden": "true" }) }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex h-8 w-8 items-center justify-center rounded-lg ${iconBgClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx(LevelIcon, { className: `h-4 w-4 ${iconColorClass}`, "aria-hidden": "true" }) }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-2 block text-sm font-semibold text-brand-dark", children: level.label }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-xs leading-relaxed text-slate-500", children: level.description }),
                    level.protects.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-0.5", children: level.protects.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-1.5 text-[11px] text-slate-500", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `h-1 w-1 shrink-0 rounded-full ${iconColorClass}` }),
                      item
                    ] }, item)) })
                  ]
                },
                level.value
              );
            }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Protection mode" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 grid gap-2 sm:grid-cols-3", children: ["prompt", "enforce", "observe"].map((mode) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "label",
                {
                  className: `cursor-pointer rounded-lg border p-3 transition-all ${draft.mode === mode ? "border-brand-blue/25 bg-brand-blue/[0.04]" : "border-transparent bg-slate-50/80 hover:bg-white"}`,
                  children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "radio", name: "mode", value: mode, checked: draft.mode === mode, onChange: handleModeChange, className: "sr-only" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold capitalize text-brand-dark", children: mode })
                  ]
                },
                mode
              )) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: modeHelp })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "approval-wait", className: "block text-sm font-semibold text-brand-dark", children: "Approval wait timeout" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Seconds to wait before returning to the harness" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "approval-wait", type: "number", min: 0, max: 600, value: draft.approval_wait_timeout_seconds, onChange: handleTimeoutChange, className: "mt-2 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { label: "Telemetry", checked: draft.telemetry, onChange: handleBooleanChange("telemetry") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { label: "Cloud sync", checked: draft.sync, onChange: handleBooleanChange("sync") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { label: "Billing features", checked: draft.billing, onChange: handleBooleanChange("billing") })
              ] })
            ] })
          ] })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Advanced settings" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Fine-tune individual risk controls and diagnostics." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative inline-flex cursor-pointer items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              checked: showAdvanced,
              onChange: (e) => setShowAdvanced(e.target.checked),
              className: "peer sr-only"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-6 w-11 rounded-full bg-slate-200 transition-colors peer-checked:bg-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform peer-checked:translate-x-5" })
        ] })
      ] }),
      showAdvanced && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AccordionSection,
          {
            title: "Risk choices",
            subtitle: draft.security_level !== "custom" ? `Managed by ${draft.security_level}` : "Custom overrides active",
            expanded: expandedSections["risk"],
            onToggle: () => toggleSection("risk"),
            children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
              draft.security_level !== "custom" && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-500", children: [
                "All risk behaviors are set by the ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: draft.security_level === "gentle" ? "Gentle" : draft.security_level === "balanced" ? "Balanced" : "Strict" }),
                " level. Select ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "Custom" }),
                " above to override individual choices."
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `divide-y divide-slate-100 border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`, children: riskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: risk.label }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: risk.description })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Guard should", value: draft.risk_actions[risk.key] ?? "require-reapproval", options: actionOptions, onChange: handleRiskActionChange(risk.key), disabled: draft.security_level !== "custom" })
              ] }, risk.key)) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Codex reading local secret files" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use this only for trusted projects where Codex should be allowed to open files such as .env or .npmrc." })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Codex should", value: draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval", options: actionOptions, onChange: handleCodexSecretReadChange, disabled: draft.security_level !== "custom" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 pt-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Advanced defaults" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 grid gap-3 sm:grid-cols-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New action", value: draft.default_action, options: actionOptions, onChange: handleStringChange("default_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Unknown source", value: draft.unknown_publisher_action, options: actionOptions, onChange: handleStringChange("unknown_publisher_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Changed command", value: draft.changed_hash_action, options: actionOptions, onChange: handleStringChange("changed_hash_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New network domain", value: draft.new_network_domain_action, options: actionOptions, onChange: handleStringChange("new_network_domain_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Subprocess action", value: draft.subprocess_action, options: actionOptions, onChange: handleStringChange("subprocess_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Approval surface", value: draft.approval_surface_policy, options: surfacePolicyOptions, onChange: handleStringChange("approval_surface_policy") })
                ] })
              ] })
            ] })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AccordionSection,
          {
            title: "Diagnostics & data",
            subtitle: "Clear approvals, export logs, repair",
            expanded: expandedSections["diagnostics"],
            onToggle: () => toggleSection("diagnostics"),
            children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
              perfSnapshot !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(DiagnosticsPerfCard, { snapshot: perfSnapshot }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear saved approvals" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes all stored allow/block decisions. Guard will ask again for previously approved actions." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearApprovals, disabled: clearingApprovals, variant: "outline", children: clearingApprovals ? "Clearing…" : "Clear approvals" }) })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear evidence log" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Permanently removes all recorded evidence. This cannot be undone." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearEvidence, disabled: clearingEvidence, variant: "outline", children: clearingEvidence ? "Clearing…" : "Clear evidence" }) })
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export diagnostics" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Downloads a JSON file with local Guard evidence for debugging or support." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportDiagnostics, disabled: exporting, variant: "secondary", children: exporting ? "Exporting…" : "Export" }) })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Repair approval center" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Resets the approval center locator when the approval link returns an API error." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairApprovalCenter, disabled: repairing, variant: "secondary", children: repairing ? "Repairing…" : "Repair" }) })
                  ] })
                ] })
              ] }),
              actionMessage ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: actionMessage }) : null
            ] })
          }
        )
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sticky bottom-4 rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleSave, disabled: saving || saveSuccess, children: saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
          "Saved"
        ] }) : saving ? "Saving…" : "Save settings" }),
        hasUnsavedChanges(savedSettingsRef.current, draft) && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "ml-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-brand-attention" }),
          "Unsaved changes"
        ] })
      ] }),
      saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-emerald-600", children: "Settings saved" }) : saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-purple", children: saveError }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use this for local tuning. Team policy from Guard Cloud may still override some decisions." })
    ] }) }),
    pendingMode === "observe" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-5 w-5 text-brand-attention", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Switch to Observe mode?" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "In Observe mode, Guard records what your AI apps do but does not pause any actions. This reduces your protection. Only use this when debugging or in trusted environments." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: confirmModeChange, className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90", children: "Switch to Observe" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: cancelModeChange, className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50", children: "Keep current mode" })
      ] })
    ] }) })
  ] });
}
function AccordionSection(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 overflow-hidden", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        onClick: props.onToggle,
        className: "flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50/60",
        "aria-expanded": props.expanded,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: props.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: props.subtitle })
          ] }),
          props.expanded ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
        ]
      }
    ),
    props.expanded && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-4 py-4", children: props.children })
  ] });
}
function DiagnosticsPerfCard(props) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg bg-slate-50/80 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-brand-dark", children: "Runtime" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500", children: [
      threadCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        threadCount,
        " threads"
      ] }),
      daemonPort !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Port ",
        daemonPort
      ] }),
      startedAt !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Started ",
        new Date(startedAt).toLocaleTimeString()
      ] })
    ] })
  ] });
}
function SettingSelect(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        value: props.value,
        onChange: props.onChange,
        disabled: props.disabled,
        className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60",
        children: props.options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function SettingToggle(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 transition-colors hover:bg-slate-100/60", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "checkbox", checked: props.checked, onChange: props.onChange, className: "h-4 w-4 accent-brand-blue" })
  ] });
}
export {
  SettingsWorkspace,
  buildClearPolicyPayload,
  resolveSecurityLevelDescription
};
