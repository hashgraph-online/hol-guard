import { bq as isGuardDemoMode, bd as isRecord, bc as fetchWithGuardAuth, r as reactExports, aM as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, aN as ApprovalProofModal, T as Tag } from "../guard-dashboard.js";
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
export {
  GuardRepairControl as G,
  GuardRepairRequestError as a,
  planGuardHookRemoval as p,
  removeAllGuardHooks as r
};
