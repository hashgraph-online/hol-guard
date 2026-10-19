import { bi as isGuardDemoMode, bj as isRecord, bk as fetchWithGuardAuth, r as reactExports, aF as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, aG as ApprovalProofModal, T as Tag, ar as harnessPostureRows, bl as overrideRows, au as harnessRowTone, bm as harnessPostureSummary, bn as joinNames, bo as sortHarnessRows, ay as PROTECTION_POSTURE_COPY, az as globalPosture, as as selectHarnessPosture, bp as restartHarnessWatch, p as HiMiniMagnifyingGlass, bq as harnessWatchPrompt, av as harnessPostureOptions, br as canRestartHarnessWatch, aw as HiMiniEye, R as HiMiniShieldCheck, ax as harnessRowStatus, a2 as useFocusTrap, bs as HiMiniKey, S as SectionLabel } from "../guard-dashboard.js";
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
      summary: typeof item.summary === "string" ? item.summary : ""
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
      steps: [{ step: "hooks", title: "Harness hooks", status: "ok", summary: "All managed hooks verified." }]
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
function repairStepTone(status) {
  if (status === "error") return "attention";
  if (status === "changed") return "green";
  if (status === "planned") return "blue";
  return "slate";
}
function repairStepLabel(status) {
  if (status === "error") return "Failed";
  if (status === "changed") return "Fixed";
  if (status === "planned") return "Needs repair";
  if (status === "skipped") return "Skipped";
  return "Healthy";
}
function repairHeadline(report) {
  if (report.status === "partial") return "Some repair steps failed. Run Repair Guard again, or run `hol-guard repair` in a terminal.";
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: repairStepTone(step.status), children: repairStepLabel(step.status) })
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
function HarnessPostureManager(props) {
  const { settings, onSettingsChange } = props;
  const [pendingWatch, setPendingWatch] = reactExports.useState(null);
  const [search, setSearch] = reactExports.useState("");
  const locked = settings.harness_postures_locked === true;
  const rows = reactExports.useMemo(() => harnessPostureRows(settings, props.capabilities), [settings, props.capabilities]);
  const sortedRows = reactExports.useMemo(() => sortHarnessRows(rows), [rows]);
  const query = search.trim().toLowerCase();
  const visibleRows = query.length === 0 ? sortedRows : sortedRows.filter(
    (row) => row.displayName.toLowerCase().includes(query) || row.harness.toLowerCase().includes(query)
  );
  const machineLabel = PROTECTION_POSTURE_COPY[globalPosture(settings)].label;
  const pendingRow = pendingWatch !== null ? visibleRows.find((row) => row.harness === pendingWatch) : void 0;
  const handleChoice = reactExports.useCallback((harness, choice) => {
    if (choice === "watch") {
      setPendingWatch(harness);
      return;
    }
    setPendingWatch(null);
    onSettingsChange(selectHarnessPosture(settings, harness, choice));
  }, [onSettingsChange, settings]);
  const handleConfirmWatch = reactExports.useCallback(() => {
    if (pendingWatch === null) return;
    onSettingsChange(selectHarnessPosture(settings, pendingWatch, "watch"));
    setPendingWatch(null);
  }, [onSettingsChange, pendingWatch, settings]);
  const handleCancelWatch = reactExports.useCallback(() => setPendingWatch(null), []);
  const handleRestartWatch = reactExports.useCallback((harness) => {
    onSettingsChange(restartHarnessWatch(settings, harness));
  }, [onSettingsChange, settings]);
  if (rows.length === 0) return null;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", "data-testid": props.testId ?? "harness-posture-section", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `rounded-xl border px-4 py-3 ${watchingCount > 0 ? "border-brand-attention/25 bg-brand-attention/[0.05]" : "border-brand-green/20 bg-brand-green/[0.05]"}`,
        "data-testid": "harness-posture-status",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-center gap-2 text-sm font-semibold text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusDot, { tone: watchingCount > 0 ? "watch" : "protected" }),
            harnessPostureSummary(rows)
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-slate-500", children: [
            "Apps start with the machine setting (",
            machineLabel,
            ") and only differ when you give one its own choice."
          ] }),
          props.onChangeTab ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => props.onChangeTab?.("protection"),
              className: "mt-2 min-h-11 text-sm font-semibold text-brand-blue underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue sm:min-h-0",
              children: "Change the machine setting"
            }
          ) : null
        ]
      }
    ),
    locked ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Your organization manages protection for each app, so these choices can't be changed here." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "search",
          value: search,
          onChange: (event) => setSearch(event.target.value),
          placeholder: "Find an app...",
          "aria-label": "Find an app",
          className: "w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white", children: visibleRows.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HarnessPostureRowCard,
        {
          row,
          settings,
          locked,
          capability: props.capabilities.find((item) => item.harness === row.harness) ?? null,
          onChoose: handleChoice,
          onRestartWatch: handleRestartWatch
        }
      ),
      pendingRow?.harness === row.harness ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "li",
        {
          className: "bg-brand-attention/[0.06]",
          role: "alertdialog",
          "aria-label": `Switch ${pendingRow.displayName} to Watch`,
          children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: harnessWatchPrompt(rows, pendingRow.harness) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: handleConfirmWatch,
                  className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white",
                  children: "Switch to Watch"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: handleCancelWatch,
                  className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark",
                  children: "Keep protection on"
                }
              )
            ] })
          ] })
        }
      ) : null
    ] }, row.harness)) }),
    visibleRows.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "No apps match your search." }) : null
  ] });
}
function HarnessPostureRowCard(props) {
  const { row } = props;
  const tone = harnessRowTone(row);
  const options = harnessPostureOptions(props.settings, row.harness);
  const restartPending = props.settings.harness_watch_restart?.includes(row.harness) === true;
  const canRestart = !props.locked && canRestartHarnessWatch(props.settings, row.harness);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: tone === "watch" ? "bg-brand-attention/[0.04]" : void 0, "data-harness": row.harness, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-center gap-2 text-sm font-semibold text-brand-dark", children: [
        tone === "watch" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
        row.displayName
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: harnessRowStatus(row) }),
      props.capability?.limited ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-slate-400", title: props.capability.honesty_sentence, children: [
        "Limited: ",
        props.capability.honesty_sentence
      ] }) : null,
      canRestart && restartPending ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Watch timer restarts when you save." }) : null,
      canRestart && !restartPending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => props.onRestartWatch(row.harness),
          className: "mt-1 min-h-11 text-xs font-semibold text-brand-blue underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue sm:min-h-0",
          children: "Restart Watch timer"
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "border-0 p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: `Protection for ${row.displayName}` }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "inline-flex gap-1 rounded-xl bg-slate-100 p-1", children: options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        HarnessPostureChoiceLabel,
        {
          groupName: `harness-posture-${row.harness}`,
          choice: option.choice,
          label: option.label,
          selected: row.selected === option.choice,
          disabled: props.locked,
          harness: row.harness,
          onChoose: props.onChoose
        },
        option.choice
      )) })
    ] })
  ] }) });
}
function HarnessPostureChoiceLabel(props) {
  const handleChange = reactExports.useCallback(() => {
    if (props.disabled) return;
    props.onChoose(props.harness, props.choice);
  }, [props.choice, props.disabled, props.harness, props.onChoose]);
  const isWatch = props.choice === "watch";
  let choiceClass = "cursor-pointer text-slate-600 hover:text-brand-dark";
  if (props.disabled && props.selected) choiceClass = "cursor-not-allowed text-slate-500";
  else if (props.disabled) choiceClass = "cursor-not-allowed text-slate-400";
  else if (props.selected) {
    choiceClass = isWatch ? "cursor-pointer bg-brand-attention text-white shadow-sm" : "cursor-pointer bg-brand-blue text-white shadow-sm";
  }
  let icon = null;
  if (!props.compact) {
    icon = isWatch ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4 shrink-0", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4 shrink-0", "aria-hidden": "true" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "label",
    {
      className: `flex min-h-11 items-center justify-center rounded-lg py-2 text-sm font-semibold transition-colors focus-within:ring-2 focus-within:ring-brand-blue ${props.compact ? "min-w-20 px-2.5" : "min-w-24 gap-1.5 px-3"} ${choiceClass}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "radio",
            name: props.groupName,
            value: props.choice,
            checked: props.selected,
            disabled: props.disabled,
            onChange: handleChange,
            className: "sr-only"
          }
        ),
        icon,
        props.label
      ]
    }
  );
}
function StatusDot(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      "aria-hidden": "true",
      className: `h-2 w-2 shrink-0 rounded-full ${props.tone === "watch" ? "bg-brand-attention" : "bg-brand-green"}`
    }
  );
}
function HarnessPostureSummaryCard(props) {
  const rows = harnessPostureRows(props.settings, props.capabilities);
  if (rows.length === 0) return null;
  const overrides = overrideRows(rows);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "flex flex-col gap-3 py-3 sm:flex-row sm:items-center sm:justify-between",
      "data-testid": "harness-posture-summary-card",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-center gap-2 text-sm font-medium text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusDot, { tone: rows.some((row) => harnessRowTone(row) === "watch") ? "watch" : "protected" }),
            harnessPostureSummary(rows)
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: overrides.length > 0 ? `Your choices: ${joinNames(overrides.map((row) => row.displayName))}.` : "Apps follow the machine setting unless you choose Watch for one of them." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onOpenApps, children: "Choose per app" }) })
      ]
    }
  );
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
  HarnessPostureChoiceLabel as H,
  SettingsSaveProofModal as S,
  GuardRepairRequestError as a,
  resolveSettingsSaveProofKind as b,
  requiresSettingsSaveProof as c,
  HarnessPostureSummaryCard as d,
  HarnessPostureManager as e,
  resolveSettingsSaveProofModalCopy as f,
  planGuardHookRemoval as p,
  removeAllGuardHooks as r
};
