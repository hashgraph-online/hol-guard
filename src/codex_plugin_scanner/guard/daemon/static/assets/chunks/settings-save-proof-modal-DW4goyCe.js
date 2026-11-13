import { bA as isGuardDemoMode, bn as isRecord, bm as fetchWithGuardAuth, r as reactExports, aZ as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, a_ as ApprovalProofModal, T as Tag, ae as useFocusTrap, cD as HiMiniKey, S as SectionLabel } from "../guard-dashboard.js";
const HOOK_REMOVAL_CONFIRMATION = "remove-guard-hooks";
class GuardRepairRequestError extends Error {
  status;
  code;
  constructor(status, code, message) {
    super(message);
    this.name = "GuardRepairRequestError";
    this.status = status;
    this.code = code;
  }
}
const STEP_STATUSES = /* @__PURE__ */ new Set(["ok", "changed", "planned", "skipped", "error"]);
function normalizeRepairReport(payload) {
  if (!isRecord(payload) || !Array.isArray(payload.steps) || typeof payload.status !== "string") {
    throw new GuardRepairRequestError(502, "invalid_response", "Guard returned an invalid repair result.");
  }
  const steps = [];
  for (const item of payload.steps) {
    if (!isRecord(item) || typeof item.step !== "string") continue;
    steps.push({
      step: item.step,
      title: typeof item.title === "string" ? item.title : item.step,
      status: STEP_STATUSES.has(String(item.status)) ? item.status : "error",
      summary: typeof item.summary === "string" ? item.summary : "",
      needs_attention: Array.isArray(item.needs_attention) ? item.needs_attention.filter((entry) => typeof entry === "string") : [],
      budget_exhausted: item.budget_exhausted === true
    });
  }
  return {
    dry_run: payload.dry_run === true,
    status: payload.status,
    summary: typeof payload.summary === "string" ? payload.summary : "",
    steps
  };
}
function normalizeHarnessRows(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!isRecord(item) || typeof item.harness !== "string") return [];
    return [
      {
        harness: item.harness,
        hook_count: typeof item.hook_count === "number" ? item.hook_count : void 0,
        files_with_hooks: Array.isArray(item.files_with_hooks) ? item.files_with_hooks.filter((entry) => typeof entry === "string") : void 0,
        adapter_uninstall: typeof item.adapter_uninstall === "string" ? item.adapter_uninstall : void 0,
        swept_hook_count: typeof item.swept_hook_count === "number" ? item.swept_hook_count : void 0
      }
    ];
  });
}
function normalizeHookRemovalReport(payload) {
  if (!isRecord(payload) || typeof payload.status !== "string") {
    throw new GuardRepairRequestError(502, "invalid_response", "Guard returned an invalid removal result.");
  }
  const postState = isRecord(payload.post_state) ? {
    clean: payload.post_state.clean === true,
    remaining_harnesses: normalizeHarnessRows(payload.post_state.remaining_harnesses)
  } : void 0;
  return {
    dry_run: payload.dry_run === true,
    status: payload.status,
    harnesses: normalizeHarnessRows(payload.harnesses),
    removed_hook_count: typeof payload.removed_hook_count === "number" ? payload.removed_hook_count : 0,
    backup_dir: typeof payload.backup_dir === "string" ? payload.backup_dir : null,
    reinstall_command: typeof payload.reinstall_command === "string" ? payload.reinstall_command : "hol-guard install --all",
    post_state: postState
  };
}
async function postJson(path, body) {
  const response = await fetchWithGuardAuth(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : null;
    const message = isRecord(payload) && typeof payload.message === "string" ? payload.message : `Guard request failed with ${response.status}.`;
    throw new GuardRepairRequestError(response.status, code, message);
  }
  return payload;
}
function credentialFields(credentials) {
  const fields = {};
  if (credentials?.approval_password !== void 0) fields.approval_password = credentials.approval_password;
  if (credentials?.approval_totp_code !== void 0) fields.approval_totp_code = credentials.approval_totp_code;
  return fields;
}
async function runGuardRepair(options = {}) {
  if (isGuardDemoMode()) {
    return {
      dry_run: options.dryRun === true,
      status: "healthy",
      summary: "Nothing needed repair.",
      steps: [
        {
          step: "hooks",
          title: "Harness hooks",
          status: "ok",
          summary: "All managed hooks verified.",
          needs_attention: [],
          budget_exhausted: false
        }
      ]
    };
  }
  return normalizeRepairReport(
    await postJson("/v1/repair", {
      dry_run: options.dryRun === true,
      ...credentialFields(options.credentials)
    })
  );
}
async function planGuardHookRemoval() {
  if (isGuardDemoMode()) {
    return {
      dry_run: true,
      status: "planned",
      harnesses: [{ harness: "codex", hook_count: 3 }],
      removed_hook_count: 0,
      reinstall_command: "hol-guard install --all"
    };
  }
  return normalizeHookRemovalReport(await postJson("/v1/protection/remove-hooks", { dry_run: true }));
}
async function removeAllGuardHooks(credentials) {
  if (isGuardDemoMode()) {
    return {
      dry_run: false,
      status: "removed",
      harnesses: [{ harness: "codex", hook_count: 3 }],
      removed_hook_count: 3,
      reinstall_command: "hol-guard install --all",
      post_state: { clean: true, remaining_harnesses: [] }
    };
  }
  return normalizeHookRemovalReport(
    await postJson("/v1/protection/remove-hooks", {
      confirm: HOOK_REMOVAL_CONFIRMATION,
      ...credentialFields(credentials)
    })
  );
}
function stepNeedsAttention(step) {
  return step.needs_attention.length > 0;
}
function repairAttentionTitles(steps) {
  return steps.filter(stepNeedsAttention).map((step) => step.title);
}
function repairStepTone(step) {
  if (step.status === "error" || stepNeedsAttention(step)) return "attention";
  if (step.status === "changed") return "green";
  if (step.status === "planned") return "blue";
  return "slate";
}
function repairStepLabel(step) {
  if (step.status === "error") return "Failed";
  if (stepNeedsAttention(step)) return "Needs you";
  if (step.status === "changed") return "Fixed";
  if (step.status === "planned") return "Needs repair";
  if (step.status === "skipped") return "Skipped";
  return "Healthy";
}
function repairHeadline(report) {
  if (report.status === "partial") {
    if (report.steps.some((step) => step.status === "error")) {
      return "Some repair steps failed. Run Repair Guard again, or run `hol-guard repair` in a terminal.";
    }
    const waiting = repairAttentionTitles(report.steps);
    const named = waiting.length > 0 ? ` Still waiting on you: ${waiting.join(", ")}.` : "";
    if (report.steps.some((step) => step.budget_exhausted)) {
      return `No repair step failed. Run Repair Guard again to continue the cleanup it could not finish.${named}`;
    }
    return `No repair step failed, and running repair again reaches the same answer.${named}`;
  }
  if (report.status === "repaired") return "Guard was repaired. Restart any coding-agent session that was blocked.";
  if (report.status === "needs_repair") return "Guard found problems to repair.";
  return "Nothing needed repair.";
}
function GuardRepairStepList({ steps }) {
  if (steps.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white", "aria-label": "Repair steps", children: steps.map((step) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-start justify-between gap-x-3 gap-y-1 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: step.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-words text-xs text-slate-500", children: step.summary })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: repairStepTone(step), children: repairStepLabel(step) })
  ] }, step.step)) });
}
function GuardRepairControl({
  description,
  buttonVariant = "secondary",
  onFinished
}) {
  const [phase, setPhase] = reactExports.useState({ kind: "idle" });
  const run = reactExports.useCallback(
    async (credentials, gate = null) => {
      setPhase({ kind: "working" });
      try {
        const report = await runGuardRepair({ credentials });
        setPhase({ kind: "done", report });
        onFinished?.(report);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Guard could not run repair.";
        if (error instanceof GuardRepairRequestError && gate?.enabled && error.status >= 400 && error.status < 500) {
          setPhase({ kind: "proof", gate, error: message });
          return;
        }
        setPhase({ kind: "error", message });
      }
    },
    [onFinished]
  );
  const handleStart = reactExports.useCallback(async () => {
    setPhase({ kind: "working" });
    let gate = null;
    try {
      gate = await fetchResolvedApprovalGate();
    } catch {
      setPhase({ kind: "error", message: "Guard could not check the approval gate. Try again." });
      return;
    }
    if (gate?.enabled) {
      setPhase({ kind: "proof", gate, error: null });
      return;
    }
    await run(void 0, gate);
  }, [run]);
  const handleConfirm = reactExports.useCallback(
    (credentials) => {
      if (phase.kind !== "proof") return;
      void run(credentials, phase.gate);
    },
    [phase, run]
  );
  const handleCancel = reactExports.useCallback(() => setPhase({ kind: "idle" }), []);
  const handleStartClick = reactExports.useCallback(() => {
    void handleStart();
  }, [handleStart]);
  const working = phase.kind === "working";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: description }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleStartClick, disabled: working, variant: buttonVariant, children: working ? "Repairing…" : "Repair Guard" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "aria-live": "polite", children: [
      phase.kind === "done" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: repairHeadline(phase.report) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(GuardRepairStepList, { steps: phase.report.steps })
      ] }) : null,
      phase.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-brand-attention", children: phase.message }) : null
    ] }),
    phase.kind === "proof" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: "Repair Guard",
        detail: "Enter local approval proof before Guard repairs its daemon, hooks, and stale local state.",
        confirmLabel: "Repair Guard",
        approvalGate: phase.gate,
        error: phase.error,
        onCancel: handleCancel,
        onConfirm: handleConfirm
      }
    ) : null
  ] });
}
function resolveSettingsSaveProofKind(input) {
  if (input.draftGateEnabled && !input.savedGateEnabled) {
    return "setup-gate";
  }
  if (input.savedGateEnabled) {
    return "verify-save";
  }
  return null;
}
function requiresSettingsSaveProof(kind) {
  return kind !== null;
}
function resolveSettingsSaveProofModalCopy(input) {
  if (input.mode === "setup-gate") {
    return {
      title: "Set your approval password",
      detail: "Choose a password Guard will ask for before allow or trust changes stick.",
      confirmLabel: "Save settings"
    };
  }
  if (input.mode === "change-password") {
    return {
      title: "Change approval password",
      detail: "Confirm your approval proof, then choose a new password.",
      confirmLabel: "Update password"
    };
  }
  if (input.mode === "maintenance") {
    if (input.maintenanceAction === "clear-approvals") {
      return {
        title: "Clear saved approvals",
        detail: "Guard needs fresh proof before it removes saved allow decisions.",
        confirmLabel: "Clear approvals"
      };
    }
    if (input.maintenanceAction === "clear-queue") {
      return {
        title: "Clear review queue",
        detail: "Guard needs fresh proof before it removes pending review items.",
        confirmLabel: "Clear queue"
      };
    }
    if (input.maintenanceAction === "revoke-cooldown") {
      return {
        title: "Revoke cooldown",
        detail: "Confirm your identity before Guard ends the active cooldown.",
        confirmLabel: "Revoke cooldown"
      };
    }
    if (input.maintenanceAction === "disable-totp") {
      return {
        title: "Disconnect authenticator",
        detail: "Confirm a current app code to remove this second factor.",
        confirmLabel: "Disconnect"
      };
    }
    if (input.maintenanceAction === "import-settings") {
      return {
        title: "Import settings",
        detail: "Guard needs fresh proof before it replaces your local settings from a file.",
        confirmLabel: "Import settings"
      };
    }
    if (input.maintenanceAction === "reset-settings") {
      return {
        title: "Reset settings",
        detail: "Guard needs fresh proof before it restores every local setting to defaults.",
        confirmLabel: "Reset settings"
      };
    }
    return {
      title: "Confirm your identity",
      detail: "Guard needs fresh proof before this cleanup can continue.",
      confirmLabel: "Continue"
    };
  }
  if (input.gateSettingsChanged) {
    return {
      title: "Confirm before saving gate changes",
      detail: "Enter your approval proof so Guard can apply the gate updates you chose.",
      confirmLabel: "Save settings"
    };
  }
  return {
    title: "Confirm before saving",
    detail: "Enter your approval proof so Guard can save these settings.",
    confirmLabel: "Save settings"
  };
}
function isSettingsSaveProofSubmitDisabled(mode, credentials, totpRequired) {
  const current = credentials.currentPassword?.trim() ?? "";
  const next = credentials.newPassword?.trim() ?? "";
  const confirm = credentials.confirmPassword?.trim() ?? "";
  const totp = credentials.totpCode?.trim() ?? "";
  if (mode === "setup-gate") {
    return next.length === 0 || confirm.length === 0 || next !== confirm;
  }
  if (mode === "change-password") {
    if (next.length === 0 || confirm.length === 0 || next !== confirm) {
      return true;
    }
    return totpRequired ? totp.length === 0 : current.length === 0;
  }
  if (totpRequired) {
    return totp.length === 0;
  }
  return current.length === 0;
}
function SettingsSaveProofModal(props) {
  const dialogRef = reactExports.useRef(null);
  const passwordRef = reactExports.useRef(null);
  const totpRef = reactExports.useRef(null);
  const [currentPassword, setCurrentPassword] = reactExports.useState("");
  const [newPassword, setNewPassword] = reactExports.useState("");
  const [confirmPassword, setConfirmPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  useFocusTrap(props.open, dialogRef);
  reactExports.useEffect(() => {
    if (!props.open) {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTotpCode("");
      return;
    }
    const timer = setTimeout(() => {
      if (props.gate?.totp_enabled === true && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance")) {
        totpRef.current?.focus();
      } else {
        passwordRef.current?.focus();
      }
    }, 50);
    return () => clearTimeout(timer);
  }, [props.gate?.totp_enabled, props.open, props.mode]);
  reactExports.useEffect(() => {
    if (props.open) {
      document.documentElement.dataset.guardModalOpen = String(
        Number(document.documentElement.dataset.guardModalOpen ?? 0) + 1
      );
      return () => {
        const count = Number(document.documentElement.dataset.guardModalOpen ?? 1) - 1;
        if (count <= 0) {
          delete document.documentElement.dataset.guardModalOpen;
        } else {
          document.documentElement.dataset.guardModalOpen = String(count);
        }
      };
    }
    return void 0;
  }, [props.open]);
  const totpRequired = props.gate?.totp_enabled === true && (props.mode === "verify-save" || props.mode === "change-password" || props.mode === "maintenance");
  const needsCurrentPassword = props.mode !== "setup-gate" && !totpRequired;
  const handleCurrentPasswordChange = reactExports.useCallback((event) => {
    setCurrentPassword(event.target.value);
  }, []);
  const handleNewPasswordChange = reactExports.useCallback((event) => {
    setNewPassword(event.target.value);
  }, []);
  const handleConfirmPasswordChange = reactExports.useCallback((event) => {
    setConfirmPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const handleBackdropClick = reactExports.useCallback(
    (event) => {
      if (event.target === event.currentTarget && !props.pending) {
        props.onCancel();
      }
    },
    [props.onCancel, props.pending]
  );
  const handleConfirm = reactExports.useCallback((event) => {
    event.preventDefault();
    if (props.pending || isSettingsSaveProofSubmitDisabled(
      props.mode,
      { currentPassword, newPassword, confirmPassword, totpCode },
      totpRequired
    )) {
      return;
    }
    props.onConfirm({
      ...currentPassword.trim().length > 0 ? { currentPassword } : {},
      ...newPassword.trim().length > 0 ? { newPassword } : {},
      ...confirmPassword.trim().length > 0 ? { confirmPassword } : {},
      ...totpCode.trim().length > 0 ? { totpCode } : {}
    });
  }, [confirmPassword, currentPassword, newPassword, props, totpCode, totpRequired]);
  const credentials = {
    currentPassword,
    newPassword,
    confirmPassword,
    totpCode
  };
  const confirmDisabled = isSettingsSaveProofSubmitDisabled(props.mode, credentials, totpRequired);
  if (!props.open) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm",
      onClick: handleBackdropClick,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "settings-save-proof-title",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "form",
        {
          ref: dialogRef,
          className: "w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl",
          onSubmit: handleConfirm,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 items-center justify-center rounded-full bg-brand-blue/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniKey, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "settings-save-proof-title", className: "text-lg font-semibold tracking-tight text-brand-dark", children: props.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: props.detail })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 space-y-3", children: [
              needsCurrentPassword ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Approval password" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    ref: passwordRef,
                    type: "password",
                    autoComplete: "current-password",
                    value: currentPassword,
                    onChange: handleCurrentPasswordChange,
                    className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  }
                )
              ] }) : null,
              props.mode === "setup-gate" || props.mode === "change-password" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: props.mode === "setup-gate" ? "Password" : "New password" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      ref: props.mode === "setup-gate" ? passwordRef : void 0,
                      type: "password",
                      autoComplete: "new-password",
                      value: newPassword,
                      onChange: handleNewPasswordChange,
                      className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Confirm password" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      type: "password",
                      autoComplete: "new-password",
                      value: confirmPassword,
                      onChange: handleConfirmPasswordChange,
                      className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] })
              ] }) : null,
              totpRequired ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Authenticator code" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    type: "text",
                    inputMode: "numeric",
                    pattern: "[0-9]*",
                    maxLength: 6,
                    ref: totpRef,
                    autoComplete: "one-time-code",
                    value: totpCode,
                    onChange: handleTotpChange,
                    placeholder: "123456",
                    className: "mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  }
                )
              ] }) : null
            ] }),
            props.error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: props.onCancel,
                  disabled: props.pending,
                  className: "rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50",
                  children: "Go back"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { type: "submit", disabled: props.pending || confirmDisabled, children: props.pending ? "Working…" : props.confirmLabel })
            ] })
          ]
        }
      )
    }
  );
}
export {
  GuardRepairControl as G,
  SettingsSaveProofModal as S,
  GuardRepairRequestError as a,
  resolveSettingsSaveProofKind as b,
  requiresSettingsSaveProof as c,
  resolveSettingsSaveProofModalCopy as d,
  planGuardHookRemoval as p,
  removeAllGuardHooks as r
};
