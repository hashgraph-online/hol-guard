import { aV as isGuardDemoMode, aW as fetchWithGuardAuth, r as reactExports, ag as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, ah as ApprovalProofModal, ai as Tag } from "../guard-dashboard.js";
const SUPPORTED_APP_SLUGS = [
  "codex",
  "claude-code",
  "opencode",
  "copilot",
  "cursor",
  "cline",
  "gemini",
  "hermes",
  "openclaw",
  "kimi",
  "grok",
  "devin"
];
const SUPPORTED_APPS_BRIEF = "Guard works with Codex, Claude Code, OpenCode, Copilot, Cursor, Cline, Gemini, Hermes, OpenClaw, Kimi, Grok, and Devin.";
function defaultConnectHarness(repairHarness, visibleHarnesses = []) {
  return repairHarness ?? visibleHarnesses[0] ?? SUPPORTED_APP_SLUGS[0];
}
const APP_STATUS_LABELS = {
  active: "Active",
  partial: "Partial setup",
  observed: "Observed",
  not_installed: "Not installed"
};
const RISK_CONTROL_CONSEQUENCES = {
  local_secret_read: {
    key: "local_secret_read",
    example: "Reading .env, .npmrc, SSH keys, or cloud credential files",
    impact: "Guard asks before any AI tool opens files that look like credential stores on this machine"
  },
  credential_exfiltration: {
    key: "credential_exfiltration",
    example: "A command that sends API keys or tokens to a remote host",
    impact: "Guard stops credential data from leaving your machine without your review"
  },
  data_flow_exfiltration: {
    key: "data_flow_exfiltration",
    example: "Reading .env then piping the value to curl or a network call in the same session",
    impact: "Guard stops the full secret-to-network route, even when it spans multiple steps"
  },
  destructive_shell: {
    key: "destructive_shell",
    example: "rm -rf, git clean -fdx, or commands that rewrite core config files",
    impact: "Guard pauses irreversible file deletions and overwrites so you can review first"
  },
  encoded_execution: {
    key: "encoded_execution",
    example: "eval(atob(...)) or base64-decoded shell payloads that hide their content",
    impact: "Guard stops scripts that encode their intent so you cannot tell what they do without decoding"
  },
  network_egress: {
    key: "network_egress",
    example: "A request to a host Guard has not seen in this project before",
    impact: "Guard asks before any new external network destination is contacted"
  },
  prompt_injection: {
    key: "prompt_injection",
    example: "A pasted instruction that tells the AI app to ignore Guard or expose secrets",
    impact: "Guard pauses prompt patterns that try to override safety rules"
  },
  mcp_dangerous_tool: {
    key: "mcp_dangerous_tool",
    example: "An MCP server requests a file delete, shell execution, or broad filesystem tool",
    impact: "Guard lets you choose which MCP tools can run without review"
  },
  malicious_skill: {
    key: "malicious_skill",
    example: "A skill from an untrusted source asks to install hooks or run hidden commands",
    impact: "Guard asks before skills can make persistent or privileged changes"
  },
  package_script: {
    key: "package_script",
    example: "npm postinstall, pnpm prepare, or a package lifecycle script runs code",
    impact: "Guard checks supply-chain scripts before they execute locally"
  },
  persistence: {
    key: "persistence",
    example: "A command writes launch agents, shell startup files, or recurring tasks",
    impact: "Guard stops AI apps from adding background persistence without review"
  },
  guard_bypass: {
    key: "guard_bypass",
    example: "A command disables hooks, edits Guard policy, or routes around approvals",
    impact: "Guard blocks attempts to weaken or bypass local protection"
  },
  cloud_advisory: {
    key: "cloud_advisory",
    example: "A team or Cloud advisory marks an action pattern as risky",
    impact: "Guard can apply trusted team guidance when Cloud sync is enabled"
  },
  encoded_exfiltration: {
    key: "encoded_exfiltration",
    example: "A base64 payload decodes a secret and sends it over the network",
    impact: "Guard connects hidden execution and exfiltration into one reviewable risk"
  }
};
const SETTINGS_SEARCH_INDEX = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, SSH keys, and cloud credentials.", section: "risk" },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away.", section: "risk" },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret reaches a network or external sink.", section: "risk" },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files.", section: "risk" },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads.", section: "risk" },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context.", section: "risk" },
  { key: "prompt_injection", label: "Prompt injection", description: "Instructions that try to override Guard or leak private data.", section: "risk" },
  { key: "mcp_dangerous_tool", label: "Connected tools", description: "Tool calls that can read files, run commands, or reach the network.", section: "risk" },
  { key: "malicious_skill", label: "Skills", description: "Agent skills from unknown or risky sources.", section: "risk" },
  { key: "package_script", label: "Package scripts", description: "Lifecycle scripts such as postinstall, prepare, and prepublish.", section: "risk" },
  { key: "persistence", label: "Persistence", description: "Startup files, launch agents, scheduled jobs, and recurring hooks.", section: "risk" },
  { key: "guard_bypass", label: "Guard bypass", description: "Attempts to disable Guard hooks, policies, or approval flow.", section: "risk" },
  { key: "cloud_advisory", label: "Cloud advisories", description: "Team and Cloud guidance for known risky patterns.", section: "risk" },
  { key: "encoded_exfiltration", label: "Encoded exfiltration", description: "Encoded payloads that hide secret extraction and network transfer.", section: "risk" },
  { key: "default_action", label: "First-time action", description: "What Guard does the first time it sees a new action.", section: "defaults" },
  { key: "unknown_publisher_action", label: "Unknown source", description: "What Guard does when it cannot verify who published a tool or command.", section: "defaults" },
  { key: "changed_hash_action", label: "Changed command", description: "What Guard does when an approved command changes.", section: "defaults" },
  { key: "new_network_domain_action", label: "New website or host", description: "What Guard does when an app contacts a host it has not seen before.", section: "defaults" },
  { key: "subprocess_action", label: "Nested commands", description: "What Guard does when a command starts another command.", section: "defaults" },
  { key: "approval_surface_policy", label: "Where to ask", description: "Where Guard shows approval prompts.", section: "defaults" },
  { key: "protection_posture", label: "Protection", description: "Protected, Extra careful, or Watch.", section: "protection" },
  { key: "security_level", label: "Advanced rules", description: "Custom per-risk rules on top of the selected protection posture.", section: "protection" },
  { key: "mode", label: "Legacy protection mode", description: "Compatibility alias for observe, prompt, and enforce.", section: "protection" },
  { key: "approval_wait_timeout", label: "Approval wait timeout", description: "How long Guard waits for you to respond before resuming.", section: "protection" },
  { key: "telemetry", label: "Telemetry", description: "Send anonymized usage data to improve Guard.", section: "protection" },
  { key: "sync", label: "Cloud sync", description: "Sync decisions and rules with Guard Cloud.", section: "protection" },
  { key: "redaction", label: "Cloud receipt privacy", description: "Choose how much command detail Guard sends to Guard Cloud.", section: "protection" },
  { key: "billing", label: "Billing features", description: "Enable billing and subscription features.", section: "protection" },
  { key: "clear_approvals", label: "Clear saved approvals", description: "Remove all stored allow or block decisions. Guard will ask again.", section: "maintenance" },
  { key: "clear_evidence", label: "Clear evidence log", description: "Permanently remove all recorded evidence. Cannot be undone.", section: "maintenance" },
  { key: "export_diagnostics", label: "Export diagnostics", description: "Download a JSON file with local Guard evidence for debugging.", section: "maintenance" },
  { key: "repair_approval_center", label: "Repair approval center", description: "Reset the approval center locator when the link returns an error.", section: "maintenance" }
];
function filterSettingsBySearch(query) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return SETTINGS_SEARCH_INDEX.filter(
    (item) => item.label.toLowerCase().includes(q) || item.description.toLowerCase().includes(q) || item.key.toLowerCase().includes(q)
  );
}
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
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
export {
  APP_STATUS_LABELS as A,
  GuardRepairControl as G,
  RISK_CONTROL_CONSEQUENCES as R,
  SUPPORTED_APPS_BRIEF as S,
  GuardRepairRequestError as a,
  defaultConnectHarness as d,
  filterSettingsBySearch as f,
  planGuardHookRemoval as p,
  removeAllGuardHooks as r
};
